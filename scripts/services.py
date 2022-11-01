from this import d
from brownie import credentialRegistry, accounts, VoteRegistry
import uuid
import requests
import json
import rsa
from cryptography.fernet import Fernet

contractDeployAccount = accounts[0]
hospital = accounts[1]
doctor = accounts[2]
patient = accounts[3]
verifier = accounts[4]
relative = accounts[5]
voter = accounts[6]

cred_contract = credentialRegistry.deploy({'from': contractDeployAccount})
vote_contract = VoteRegistry.deploy({'from': contractDeployAccount})
mapch_server = "127.0.0.1:5000"
head = {"Content-Type": "application/json"}

def issueCredential(issuing_account, issuer, holder, credential_hash, r, e, n1):
    id = str(uuid.uuid1())
    cred_contract.issueCredential(id, issuer, holder, credential_hash, r, e, n1, {'from': issuing_account})
    
    return id

def getCredential(id, acc):

    _, _, _, cred_hash, cred_r, cred_e, cred_n1 = cred_contract.getCredential(id, {'from': acc})
    
    return {
        "h" : cred_hash,
        "r" : cred_r,
        "N1" : cred_n1,
        "e" : cred_e
    }

def createABEAuthority(authority_name):
    body = { "authority_name" : authority_name }
    x = requests.post(f"http://{mapch_server}/create_abe_authority", headers=head, json=body)
    maab_master_pk_sk = json.loads(x.text)
    
    return maab_master_pk_sk

def createCHKeys():
    x = requests.get(f"http://{mapch_server}/create_ch_keys", headers=head)
    cham_hash_pk_sk = json.loads(x.text)
    
    return cham_hash_pk_sk

def createABESecretKey(abe_master_sk, gid, user_attribute):
    body = {
        "sk" : abe_master_sk,
        "gid" : gid,
        "user_attribute" : [user_attribute]
    }

    x = requests.post(f"http://{mapch_server}/create_abe_attribute_secret_key", headers=head, json=body)
    abe_secret_key = json.loads(x.text)

    return abe_secret_key

def generateSupportingCredential(credential, access_policy, ch_pk, ch_sk, authority_abe_pk, issuing_account, official_issuer, holder):
    body = {
        "cham_pk" : ch_pk, 
        "cham_sk" : ch_sk,
        "message" : credential,
        "authority_abe_pk" : authority_abe_pk,
        "access_policy" : access_policy
    }

    x = requests.post(f"http://{mapch_server}/hash", headers=head, json=body)
    hash = json.loads(x.text)

    cred_id = issueCredential(issuing_account, official_issuer, holder, hash["h"], hash["r"], hash["e"], hash["N1"])

    return {
        "credential_hash" : hash,
        "credential_id" : cred_id
    }

def verifySupportingCredential(credential_message, credential_id, ch_pk, verifier):

    reconstructed_hash = getCredential(credential_id, verifier)
    
    body = {
        "message" : credential_message,
        "cham_pk" : ch_pk,
        "hash" : reconstructed_hash
    }
    
    x = requests.post(f"http://{mapch_server}/hash_verify", headers=head, json=body)
    hash_res = json.loads(x.text)
    
    return hash_res["is_hash_valid"] == "True"

def adaptSupportingCredential(credential_hash, original_msg, new_msg, cham_pk, gid, abe_secret_key, issuing_account, issuer, holder, voting_required, num_votes_required):
    
    # modify credential
    body = {
        "hash" : credential_hash,
        "original_message" : original_msg,
        "new_message" : new_msg,
        "cham_pk" : cham_pk,
        "gid" : gid,
        "abe_secret_key" : abe_secret_key
    }

    x = requests.post(f"http://{mapch_server}/adapt", headers=head, json=body)
    hash_modified = json.loads(x.text)
    
    # add it to credential registry
    cred_id = issueCredential(issuing_account, issuer, holder, hash_modified["h"], hash_modified["r"], hash_modified["e"], hash_modified["N1"])

    # add it to vote registry
    vote_contract.addCredential(cred_id, voting_required, num_votes_required, {'from': issuing_account})

    return {
        "credential_hash" : hash_modified,
        "credential_id" : cred_id
    }

def loadCredential(file):
    with open(file, "r") as f:
        return json.load(f)

## voting

def tryShareModifiedCredential(credential_id, issuer_account):
    return vote_contract.isVotingCompleted(credential_id, {'from': issuer_account})

def addVote(cred_id, cred_message, cham_pk, role_credential_pack, role_credential_pk, voter):
    if (verifySupportingCredential(cred_message, cred_id, cham_pk, voter)):
        
        decryped_sym_key = rsa.decrypt(role_credential_pack["encryped_key"], role_credential_pk)
        fernet = Fernet(decryped_sym_key)    

        decryped_rc = fernet.decrypt(role_credential_pack["role_credential"]).decode()
        json_rc = json.loads(decryped_rc)
        cred_message_json = json.loads(cred_message)

        print(json_rc["credentialSubject"]["role"])
        print(cred_message_json)

        if (json_rc["credentialSubject"]["role"] in cred_message_json[0]["approvalPolicty"]):
            vote_contract.vote(cred_id, {'from': voter})
        else:
            print("COULD NOT VOTE BECAUSE VOTER DOES NOT HAVE THE RIGHT ROLE")
    else:
        print("COULD NOT VOTE BECAUSE MESSAGE IS NOT CORRECT")

def issueRoleCredential(rc_rsakey, rc_symkey):
    rc_json = loadCredential("scripts/role_credential_example.json")
    rc_msg = json.dumps(rc_json)

    fernet = Fernet(rc_symkey)
    enc_rc = fernet.encrypt(rc_msg.encode())
    enc_key = rsa.encrypt(rc_symkey, rc_rsakey)

    return {
        "encryped_key" : enc_key,
        "role_credential" : enc_rc
    }

def main():

    ##### SCENARIO 1
    
    # == hospital ==
    print("CREATING ABE AUTHORITY ===\n")
    maab_master_pk_sk = createABEAuthority("DOCTORA")
    print("CREATING CH KEYS ===\n")
    cham_hash_pk_sk = createCHKeys()

    print("CREATING REGULAR ROLE CREDENTIAL KEYS ===\n")
    rc_pk, rc_sk = rsa.newkeys(512)
    rc_symkey = Fernet.generate_key()
    
    print("CREATING HASH ===\n")
    print("LOADING HASH MESSAGE===\n")
    credential_msg_json = loadCredential("scripts/supporting_credential_example.json")
    credential_msg = json.dumps(credential_msg_json)
    original_msg = json.dumps(credential_msg_json)

    print("CREATING ACTUAL HASH===\n")
    credential_pack = generateSupportingCredential(credential_msg, "(DOCTOR@DOCTORA or PATIENT@DOCTORA)", cham_hash_pk_sk["pk"], cham_hash_pk_sk["sk"], maab_master_pk_sk["pk"], hospital, "did:" + str(hospital.address), "did:" + str(doctor.address))
    # action: share credential pack, cham_hash_pk and maab_master_pk_sk with DOCTORA

    ## == doctor ==
    print("VERIFYING HASH ===\n")
    res1 = verifySupportingCredential(credential_msg, credential_pack["credential_id"], cham_hash_pk_sk["pk"], doctor)
    print(res1)

    print("CREATING ABE SECRET KEY FOR DOCTOR===\n")
    doctor_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Doctor", "DOCTOR@DOCTORA") 
    
    print("ADAPTING HASH (Doctor) ===\n")
    credential_msg_json[1]["credentialSubject"]["permissions"] = ["some permissions"]
    doctor_modified_message = json.dumps(credential_msg_json)
    doctor_modified_credential_pack = adaptSupportingCredential(credential_pack["credential_hash"], original_msg, doctor_modified_message, cham_hash_pk_sk["pk"], "Doctor", doctor_abe_secret_key, doctor, "did:" + str(doctor.address), "did:" + str(patient.address), True, 1)
    
    print("VERIFYING HASH (Doctor) ===\n")
    res2 = verifySupportingCredential(doctor_modified_message, doctor_modified_credential_pack["credential_id"], cham_hash_pk_sk["pk"], verifier)
    print(res2) 

    print("CREATING ABE SECRET KEY FOR PATIENT 1===\n")
    patient1_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Patient1", "PATIENT@DOCTORA")

    # action flow: share key and credential with patient

    print("TRY SHARE MODIFIED CREDENTIAL WITHOUT VOTING ===\n")
    vote_res1 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    print(vote_res1)

    print("BEGIN VOTING PROCESS===\n")
    
    print("ISSING ROLE CREDENTIAL===\n")
    role_credential_pack = issueRoleCredential(rc_pk, rc_symkey)

    print("ADDING VOTE===\n")
    addVote(doctor_modified_credential_pack["credential_id"], doctor_modified_message, cham_hash_pk_sk["pk"], role_credential_pack, rc_sk, voter)
    
    print("TRY SHARE MODIFIED CREDENTIAL WITH VOTING ===\n")
    vote_res2 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    print(vote_res2)

    ## == relative ==
    print("ADAPTING HASH (Patient 1) ===\n")
    credential_msg_json[2]["credentialSubject"]["permissions"] = ["some relative permissions"]
    patient_modified_message = json.dumps(credential_msg_json)
    patient_modified_credential_pack = adaptSupportingCredential(doctor_modified_credential_pack["credential_hash"], doctor_modified_message, patient_modified_message, cham_hash_pk_sk["pk"], "Patient1", patient1_abe_secret_key, patient, "did:" + str(patient.address), "did:" + str(relative.address), False, 0)

    print("VERIFYING HASH (Relative/Verifier) ===\n")
    res3 = verifySupportingCredential(patient_modified_message, patient_modified_credential_pack["credential_id"], cham_hash_pk_sk["pk"], verifier)
    print(res3) 
    