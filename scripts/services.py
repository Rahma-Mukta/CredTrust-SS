from this import d
from brownie import revocationRegistry, DIDRegistry, IssuerRegistry, VoteRegistry, credentialRegistry, accounts
import uuid
import requests
import json
import hashlib
import rsa
from cryptography.fernet import Fernet

contractDeployAccount = accounts[0]
hospital = accounts[1]
doctor = accounts[2]
patient = accounts[3]
verifier = accounts[4]
relative = accounts[5]
voter = accounts[6]

DID_contract = DIDRegistry.deploy({'from': contractDeployAccount})
issuer_contract = IssuerRegistry.deploy({'from':contractDeployAccount})
revocation_contract = revocationRegistry.deploy({'from':contractDeployAccount})

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

def createABEAuthority(authority_name, issuer):
    body = { "authority_name" : authority_name }
    x = requests.post(f"http://{mapch_server}/create_abe_authority", headers=head, json=body)
    maab_master_pk_sk = json.loads(x.text)
    print(maab_master_pk_sk["pk"])
    addMasterKey(maab_master_pk_sk["pk"], issuer)
    return maab_master_pk_sk

def createCHKeys(issuer):
    x = requests.get(f"http://{mapch_server}/create_ch_keys", headers=head)
    cham_hash_pk_sk = json.loads(x.text)
    addHashKey(cham_hash_pk_sk["pk"], issuer)

    return cham_hash_pk_sk

def createABESecretKey(abe_master_key, gid, user_attribute, issuer):
    # if master key is invalid , return None
    if not checkMasterKey(abe_master_key["pk"], issuer):
        return None
    body = {
        "sk" : abe_master_key["sk"],
        "gid" : gid,
        "user_attribute" : [user_attribute]
    }

    x = requests.post(f"http://{mapch_server}/create_abe_attribute_secret_key", headers=head, json=body)
    abe_secret_key = json.loads(x.text)

    addSecretKey(abe_master_key["pk"], abe_secret_key, issuer)
    return abe_secret_key

def generateSupportingCredential(credential, access_policy, ch_pk, ch_sk, authority_abe_pk, issuing_account, official_issuer, holder):
    # if master key is invalid, return none
    if not checkMasterKey(authority_abe_pk, issuing_account) or not checkHashKey(ch_pk, issuing_account):
        return None
    # access policy
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
    addCredential(hash, issuing_account)

    return {
        "credential_hash" : hash,
        "credential_id" : cred_id
    }

def verifySupportingCredential(credential_message, credential, ch_pk, verifier):

    if not checkCredential(credential["credential_hash"], verifier) or not checkHashKey(ch_pk, verifier):
        return False
   
    reconstructed_hash = getCredential(credential["credential_id"], verifier)
    
    body = {
        "message" : credential_message,
        "cham_pk" : ch_pk,
        "hash" : reconstructed_hash
    }
    
    x = requests.post(f"http://{mapch_server}/hash_verify", headers=head, json=body)
    hash_res = json.loads(x.text)
    
    return hash_res["is_hash_valid"] == "True"

def adaptSupportingCredential(credential_hash, original_msg, new_msg, cham_pk, gid, abe_secret_key, issuing_account, issuer, holder, voting_required, num_votes_required):
    # if secret key is not valid, return None

    if not checkSecretKey(abe_secret_key, issuing_account) or not checkHashKey(cham_pk, issuing_account):
        return None
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

def addVote(credential, cred_message, cham_pk, role_credential_pack, role_credential_pk, voter):
    if not checkHashKey(cham_pk, voter):
        print("THE CH HASH KEY IS INVALID")
        return

    if (verifySupportingCredential(cred_message, credential, cham_pk, voter)):
        
        decryped_sym_key = rsa.decrypt(role_credential_pack["encryped_key"], role_credential_pk)
        fernet = Fernet(decryped_sym_key)    

        decryped_rc = fernet.decrypt(role_credential_pack["role_credential"]).decode()
        json_rc = json.loads(decryped_rc)
        cred_message_json = json.loads(cred_message)

        if (json_rc["credentialSubject"]["role"] in cred_message_json[0]["approvalPolicty"]):
            vote_contract.vote(credential["credential_id"], {'from': voter})
        else:
            print("COULD NOT VOTE BECAUSE VOTER DOES NOT HAVE THE RIGHT ROLE")
    else:
        print("COULD NOT VOTE BECAUSE MESSAGE IS NOT CORRECT")

def issueRoleCredential(rc_rsakey, rc_pk, rc_symkey, issuer):
    rc_json = loadCredential("scripts/role_credential_example.json")
    rc_msg = json.dumps(rc_json)

    fernet = Fernet(rc_symkey)
    enc_rc = fernet.encrypt(rc_msg.encode())
    enc_key = rsa.encrypt(rc_symkey, rc_rsakey)
    # Add rc_pk to IssuerRegistry
    registerIssuer(issuer, issuer, rc_pk)
    # TODO: Add smart contract code for revocation
    #[rc_pk, encrypted(rc_symkey)]

    # rc_symkey enc json
    # rsa_sk  enc rc_sy
    return {
        "encryped_key" : enc_key,
        "role_credential" : enc_rc
    }

## Revocation

def registerDID(issuer):
    DID_contract.register(issuer, str("did"+ issuer.address), {"from":  issuer})
    print(DID_contract.getDID(issuer))

def addPubKey(issuer, holder, ch_pk):
    DID_contract.addPublicKey(issuer, holder, str(ch_pk), {"from": issuer})

def registerIssuer(holder, issuer, ch_pk):
    issuer_contract.addIssuer(str(ch_pk), holder, {"from": issuer})

def addMasterKey(abe_master_key, issuer):
    revocation_contract.addMasterKey(str(abe_master_key["egga"]) + str(abe_master_key["gy"]), {"from": issuer})

def addSecretKey(abe_master_key, abe_secret_key, issuer):
    revocation_contract.addSecretKey(str(abe_master_key["egga"]) + str(abe_master_key["gy"]), hashlib.sha256(str(abe_secret_key).encode()).hexdigest(), {"from": issuer})

def revokeMasterKey(abe_master_key, aggressive, issuer):
    return revocation_contract.revokeMasterKey(str(abe_master_key["egga"]) + str(abe_master_key["gy"]), aggressive, {"from": issuer})

def revokeSecretKey(abe_secret_key, issuer):
    return revocation_contract.revokeSecretKey(hashlib.sha256(str(abe_secret_key).encode()).hexdigest(), {"from": issuer})

def checkMasterKey(abe_master_key, issuer):
    return revocation_contract.checkMasterKey(str(abe_master_key["egga"]) + str(abe_master_key["gy"]), {"from": issuer})

def checkSecretKey(abe_secret_key, issuer):
    return revocation_contract.checkSecretKey(hashlib.sha256(str(abe_secret_key).encode()).hexdigest(), {"from": issuer})

def addCredential(credential_id, issuer):
    revocation_contract.addCredential(str(credential_id["h"] + credential_id["r"]), {"from": issuer})

def addDependentCredential(top_credential_id, bottom_credential_id, issuer):
    revocation_contract.addCredential(str(top_credential_id["h"] + top_credential_id["r"]), str(bottom_credential_id["h"] + bottom_credential_id["r"]), {"from": issuer})

def revokeCredential(credential_id, aggressive, issuer):
    revocation_contract.revokeDependentCredential(str(credential_id["h"] + credential_id["r"]), aggressive, {"from": issuer})

def checkCredential(credential_id, issuer):
    return revocation_contract.checkCredential(str(credential_id["h"] + credential_id["r"]), {"from": issuer})

def addHashKey(ch_hash_pk, issuer):
    revocation_contract.addHashKey(str(ch_hash_pk["N"]), {"from": issuer}) 

def revokeHashKey(ch_hash_pk, issuer):
    revocation_contract.revokeHashKey(str(ch_hash_pk["N"]), {"from": issuer}) 

def checkHashKey(ch_hash_pk, issuer):
    return revocation_contract.checkHashKey(str(ch_hash_pk["N"]), {"from": issuer})


def main():

    ##### SCENARIO 1
    
    # == hospital ==
    print("REGISTER DID ===\n")
    registerDID(hospital)

    print("CREATING ABE AUTHORITY ===\n")
    maab_master_pk_sk = createABEAuthority("DOCTORA", hospital)

    print("CHECK FOR MASTER KEY VALIDITY ===\n")
    print(checkMasterKey(maab_master_pk_sk["pk"], hospital))

    print("CREATING CH KEYS ===\n")
    cham_hash_pk_sk = createCHKeys(hospital)

    print("CHECKING CH KEYS VALIDITY ===\n")
    print(checkHashKey(cham_hash_pk_sk["pk"], hospital))

    print("CREATING REGULAR ROLE CREDENTIAL KEYS ===\n")
    rc_sk, rc_pk = rsa.newkeys(512) # Add to Issuer Registry 
    rc_symkey = Fernet.generate_key() # encrypted symkey bc, credential based,[rc_pk, encrypted(rc_symkey)]

    print(rc_sk)
    print("CREATING HASH ===\n")
    print("LOADING HASH MESSAGE===\n")
    credential_msg_json = loadCredential("scripts/supporting_credential_example.json")
    credential_msg = json.dumps(credential_msg_json)
    original_msg = json.dumps(credential_msg_json)

    print("ADDING OWNER TO THE BLOCKCHAIN===\n")
    print(cham_hash_pk_sk["pk"])
    addPubKey(hospital, hospital, cham_hash_pk_sk["pk"]["N"])
    registerIssuer(hospital, hospital, cham_hash_pk_sk["pk"]["N"])
    # TODO: fix access policy, should be both patient and doctor
    print("CREATING ACTUAL HASH===\n")
    credential_pack = generateSupportingCredential(credential_msg, "(DOCTOR@DOCTORA or PATIENT@DOCTORA)", cham_hash_pk_sk["pk"], cham_hash_pk_sk["sk"], maab_master_pk_sk["pk"], hospital, "did:" + str(hospital.address), "did:" + str(doctor.address))
    print(credential_pack)
    # action: share credential pack, cham_hash_pk and maab_master_pk_sk with DOCTORA

    ## == doctor ==
    print("REGISTER DID ===\n")
    registerDID(doctor)

    print("VERIFYING HASH ===\n")
    res1 = verifySupportingCredential(credential_msg, credential_pack, cham_hash_pk_sk["pk"], doctor)
    print(res1)

    print("CREATING ABE SECRET KEY FOR DOCTOR===\n")
    doctor_abe_secret_key = createABESecretKey(maab_master_pk_sk, "Doctor", "DOCTOR@DOCTORA", hospital) 
    print(doctor_abe_secret_key)

    print("ADDING OWNER TO THE BLOCKCHAIN===\n")
    addPubKey(hospital, doctor, cham_hash_pk_sk["pk"]["N"])
    registerIssuer(doctor, hospital, cham_hash_pk_sk["pk"]["N"])

    print("ADAPTING HASH (Doctor) ===\n")
    credential_msg_json[1]["credentialSubject"]["permissions"] = ["some permissions"]
    doctor_modified_message = json.dumps(credential_msg_json)
    doctor_modified_credential_pack = adaptSupportingCredential(credential_pack["credential_hash"], original_msg, doctor_modified_message, cham_hash_pk_sk["pk"], "Doctor", doctor_abe_secret_key, doctor, "did:" + str(doctor.address), "did:" + str(patient.address), True, 1)

    print("VERIFYING HASH (Doctor) ===\n")
    res2 = verifySupportingCredential(doctor_modified_message, doctor_modified_credential_pack, cham_hash_pk_sk["pk"], verifier)
    print(res2)

    print("CREATING ABE SECRET KEY FOR PATIENT 1===\n")
    patient1_abe_secret_key = createABESecretKey(maab_master_pk_sk, "Patient1", "PATIENT@DOCTORA", doctor)

    # action flow: share key and credential with patient

    print("TRY SHARE MODIFIED CREDENTIAL WITHOUT VOTING ===\n")
    vote_res1 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    print(vote_res1)

    print("BEGIN VOTING PROCESS===\n")
    
    print("ISSING ROLE CREDENTIAL===\n")
    role_credential_pack = issueRoleCredential(rc_sk, rc_pk, rc_symkey, hospital)

    print("ADDING VOTE===\n")
    addVote(doctor_modified_credential_pack, doctor_modified_message, cham_hash_pk_sk["pk"], role_credential_pack, rc_pk, voter)
    
    print("TRY SHARE MODIFIED CREDENTIAL WITH VOTING ===\n")
    vote_res2 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    print(vote_res2)

    ## == relative ==
    print("ADAPTING HASH (Patient 1) ===\n")
    credential_msg_json[2]["credentialSubject"]["permissions"] = ["some relative permissions"]
    patient_modified_message = json.dumps(credential_msg_json)
    patient_modified_credential_pack = adaptSupportingCredential(doctor_modified_credential_pack["credential_hash"], doctor_modified_message, patient_modified_message, cham_hash_pk_sk["pk"], "Patient1", patient1_abe_secret_key, patient, "did:" + str(patient.address), "did:" + str(relative.address), False, 0)

    print("VERIFYING HASH (Relative/Verifier) ===\n")
    res3 = verifySupportingCredential(patient_modified_message, patient_modified_credential_pack, cham_hash_pk_sk["pk"], verifier)
    print(res3) 

    print("REVOKE MASTER KEY ===\n")
    revokeMasterKey(maab_master_pk_sk["pk"], False, hospital)

    print("CHECK FOR MASTER KEY VALIDITY ===\n")
    print(checkMasterKey(maab_master_pk_sk["pk"], hospital))

    print("CHECK FOR ABE SECRET KEY VALIDITY ===\n")
    print(checkSecretKey(doctor_abe_secret_key, hospital))

    print("REVOKE MASTER KEY AGGRESSIVE ===\n")
    revokeMasterKey(maab_master_pk_sk["pk"], True, hospital)

    print("CHECK FOR ABE SECRET KEY VALIDITY ===\n")
    print(checkSecretKey(doctor_abe_secret_key, hospital))

    print("REVOKE Credential Hash ===\n")
    revokeCredential(doctor_modified_credential_pack["credential_hash"], True, hospital)

    print("VERIFYING HASH (Doctor) after revocation ===\n")
    res4 = verifySupportingCredential("stuff", doctor_modified_credential_pack, cham_hash_pk_sk["pk"], verifier)
    print(res4)

    print("REVOKE CH KEYS  ===\n")
    print(revokeHashKey(cham_hash_pk_sk["pk"], hospital))

    print("CHECKING CH KEYS VALIDITY ===\n")
    print(checkHashKey(cham_hash_pk_sk["pk"], hospital))
   



    