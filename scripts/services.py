from this import d
from brownie import credentialRegistry, accounts, VoteRegistry
import uuid
import requests
import json
import rsa
from cryptography.fernet import Fernet

from scripts.MAPCH import chamwithemp
from scripts.MAPCH import MAABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from json import dumps, loads
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction,SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.integergroup import integer
import re

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

groupObj = PairingGroup('SS512')
maabe = MAABE.MaabeRW15(groupObj)
public_parameters = maabe.setup()

# helpers

def cut_text(text,lenth): 
    textArr = re.findall('.{'+str(lenth)+'}', text) 
    textArr.append(text[(len(textArr)*lenth):]) 
    return textArr

def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

# credential

def issueCredential(issuing_account, issuer, holder, credential_hash, r, e, n1):
    id = str(uuid.uuid1())
    cred_contract.issueCredential(id, issuer, holder, credential_hash, r, e, n1, {'from': issuing_account})
    
    return id

def getCredential(id, acc, hash):

    _, _, _, cred_hash, cred_r, cred_e, cred_n1 = cred_contract.getCredential(id, {'from': acc})
    
    return {
        "h" : cred_hash,
        "r" : cred_r,
        "N1" : cred_n1,
        "e" : cred_e
    }

def createABEAuthority(authority_name):
    (pk, sk) = maabe.authsetup(public_parameters, authority_name)
    return {"pk" : pk, "sk" : sk}

def createCHKeys(hash_func):
    (pk, sk) = hash_func.keygen(1024)
    return {"pk" : pk, "sk" : sk}

def createABESecretKey(abe_master_sk, gid, user_attribute):
    return maabe.multiple_attributes_keygen(public_parameters, abe_master_sk, gid, user_attribute)

def createHash(cham_pk, cham_sk, msg, hash_func, abe_master_pk, access_policy):
    xi = hash_func.hash(cham_pk, cham_sk, msg)
    etd = [xi['p1'],xi['q1']]
    
    maabepk = { abe_master_pk["name"] : abe_master_pk }

    # encrypt
    rand_key = groupObj.random(GT)
    #if debug: print("msg =>", rand_key)
    #encrypt rand_key
    maabect = maabe.encrypt(public_parameters, maabepk, rand_key, access_policy)
    #rand_key->symkey AE  
    symcrypt = AuthenticatedCryptoAbstraction(extractor(rand_key))
    #symcrypt msg(etd=(p1,q1))
    etdtostr = [str(i) for i in etd]
    etdsumstr = etdtostr[0]+etdtostr[1]
    symct = symcrypt.encrypt(etdsumstr)

    ct = {'rkc':maabect,'ec':symct}

    #if debug: print("\n\nCiphertext...\n")
    #groupObj.debug(ct)
    #print("ciphertext:=>", ct)
    h = {'h': xi['h'], 'r': xi['r'], 'cipher':ct, 'N1': xi['N1'], 'e': xi['e']}
    return h

def generateAndIssueSupportingCredential(supporting_credential_msg, hash_funcs, access_policy, ch_pk, ch_sk, authority_abe_pk, issuing_account, official_issuer, holder):

    block1_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[0]), hash_funcs[0], authority_abe_pk, access_policy)
    block2_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[1]), hash_funcs[1], authority_abe_pk, access_policy)
    block3_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[2]), hash_funcs[2], authority_abe_pk, access_policy)
    
    block1_cred_id = issueCredential(issuing_account, official_issuer, holder, block1_original_hash["h"], block1_original_hash["r"], block1_original_hash["e"], block1_original_hash["N1"])
    block2_cred_id = issueCredential(issuing_account, official_issuer, holder, block2_original_hash["h"], block2_original_hash["r"], block2_original_hash["e"], block2_original_hash["N1"])
    block3_cred_id = issueCredential(issuing_account, official_issuer, holder, block3_original_hash["h"], block3_original_hash["r"], block3_original_hash["e"], block3_original_hash["N1"])    
    
    supporting_credential = {
        "block1" : {
            "msg" : json.dumps(supporting_credential_msg[0]),
            "hash" : block1_original_hash,
            "id" : block1_cred_id
        },
        "block2" : {
            "msg" : json.dumps(supporting_credential_msg[1]),
            "hash" : block2_original_hash,
            "id" : block2_cred_id
        },
        "block3" : {
            "msg" : json.dumps(supporting_credential_msg[2]),
            "hash" : block3_original_hash,
            "id" : block3_cred_id
        }
    }

    return supporting_credential

def verifySupportingCredential(supporting_credential, ch_pk, hash_funcs):
    
    chamHash1 = hash_funcs[0]
    chamHash2 = hash_funcs[1]
    chamHash3 = hash_funcs[2]

    block1_verify_res = chamHash1.hashcheck(ch_pk, supporting_credential["block1"]["msg"], supporting_credential["block1"]["hash"])
    block2_verify_res = chamHash2.hashcheck(ch_pk, supporting_credential["block2"]["msg"], supporting_credential["block2"]["hash"])
    block3_verify_res = chamHash3.hashcheck(ch_pk, supporting_credential["block3"]["msg"], supporting_credential["block3"]["hash"])
    
    return (block1_verify_res and block2_verify_res and block3_verify_res)

def collision(original_msg, new_msg, h, hash_func, ch_pk, abe_secret_key, gid):
    
    user_sk = {'GID': gid, 'keys': merge_dicts(abe_secret_key)}
    
    #decrypt rand_key
    rec_key = maabe.decrypt(public_parameters, user_sk, h['cipher']['rkc'])
    #rec_key->symkey AE
    rec_symcrypt = AuthenticatedCryptoAbstraction(extractor(rec_key))
    #symdecrypt rec_etdsumstr
    rec_etdsumbytes = rec_symcrypt.decrypt(h['cipher']['ec'])
    rec_etdsumstr = str(rec_etdsumbytes, encoding="utf8")
    #print("etdsumstr type=>",type(rec_etdsumstr))
    #sumstr->etd str list
    rec_etdtolist = cut_text(rec_etdsumstr, 309)
   # print("rec_etdtolist=>",rec_etdtolist)
    #etd str list->etd integer list
    rec_etdint = {'p1': integer(int(rec_etdtolist[0])),'q1':integer(int(rec_etdtolist[1]))}
    #print("rec_etdint=>",rec_etdint)
    r1 = hash_func.collision(original_msg, new_msg, h, rec_etdint, ch_pk)
    #if debug: print("new randomness =>", r1)
    new_h = {'h': h['h'], 'r': r1, 'cipher': h['cipher'], 'N1': h['N1'], 'e': h['e']}
    return new_h

def adaptSupportingCredential(credential_hash, original_msg, new_msg, cham_pk, hash_func, abe_secret_key, issuing_account, issuer, holder, voting_required, num_votes_required, gid):
    
    hash_modified = collision(original_msg, new_msg, credential_hash, hash_func, cham_pk, abe_secret_key, gid)

    # add it to credential registry
    cred_id = issueCredential(issuing_account, issuer, holder, hash_modified["h"], hash_modified["r"], hash_modified["e"], hash_modified["N1"])

    # add it to vote registry
    vote_contract.addCredential(cred_id, voting_required, num_votes_required, {'from': issuing_account})

    return {
        "credential_hash" : hash_modified,
        "credential_id" : cred_id
    }

def adaptSupportingCredentialBlock(supporting_credential, block, hash_func, ch_pk, abe_secret_key, gid):

    block_original = supporting_credential[block]["msg"]
    block_modified = block_original
    block_modified = json.loads(block_modified)
    block_modified["credentialSubject"]["permissions"] = ["some permissions 2"]
    block_modified = json.dumps(block_modified)

    hash_modified = collision(block_original, block_modified, supporting_credential[block]["hash"], hash_func, ch_pk, abe_secret_key, gid)
    
    modified_supporting_credential = supporting_credential

    modified_supporting_credential[block]["hash"] = hash_modified
    modified_supporting_credential[block]["id"] = "N/A"
    modified_supporting_credential[block]["msg"] = block_modified

    return modified_supporting_credential

def loadCredential(file):
    with open(file, "r") as f:
        return json.load(f)

## voting

def tryShareModifiedCredential(credential_id, issuer_account):
    return vote_contract.isVotingCompleted(credential_id, {'from': issuer_account})

def addVote(hash, cred_id, cred_message, cham_pk, role_credential_pack, role_credential_pk, voter, hash_func):
    # TODO: fix
    if (verifySupportingCredential(cred_message, hash, cham_pk, voter, hash_func)):
        
        decryped_sym_key = rsa.decrypt(role_credential_pack["encryped_key"], role_credential_pk)
        fernet = Fernet(decryped_sym_key)    

        decryped_rc = fernet.decrypt(role_credential_pack["role_credential"]).decode()
        json_rc = json.loads(decryped_rc)
        cred_message_json = json.loads(cred_message)

        if (json_rc["credentialSubject"]["role"] in cred_message_json[0]["approvalPolicty"]):
            vote_contract.vote(cred_id, {'from': voter})
        else:
            print("COULD NOT VOTE BECAUSE VOTER DOES NOT HAVE THE RIGHT ROLE")
    else:
        print("COULD NOT VOTE BECAUSE MESSAGE IS NOT CORRECT")

def issueRoleCredential(rc_rsakey, rc_symkey):
    rc_json = loadCredential("role_credential_example.json")
    rc_msg = json.dumps(rc_json)

    fernet = Fernet(rc_symkey)
    enc_rc = fernet.encrypt(rc_msg.encode())
    enc_key = rsa.encrypt(rc_symkey, rc_rsakey)

    return {
        "encryped_key" : enc_key,
        "role_credential" : enc_rc
    }

def main():

    # == hospital ==
    print("CREATING ABE AUTHORITY ===\n")
    maab_master_pk_sk = createABEAuthority("DOCTORA")

    print("CREATING CH KEYS ===\n")
    chamHash1 = chamwithemp.Chamwithemp()
    cham_hash_pk_sk = createCHKeys(chamHash1)

    chamHash2 = chamwithemp.Chamwithemp()
    _ = createCHKeys(chamHash2)

    chamHash3 = chamwithemp.Chamwithemp()
    _ = createCHKeys(chamHash3)
    
    # TODO: role credential

    print("CREATING AND ISSUING SUPPORTING CREDENTIAL ===\n")
    credential_msg_json = loadCredential("supporting_credential_example.json")
    supporting_credential = generateAndIssueSupportingCredential(credential_msg_json, [chamHash1, chamHash2 , chamHash3], "(DOCTOR@DOCTORA or PATIENT@DOCTORA)",
                                                                 cham_hash_pk_sk["pk"], cham_hash_pk_sk["sk"], maab_master_pk_sk["pk"], 
                                                                 hospital, "did:" + str(hospital.address), "did:" + str(doctor.address))

    # action: share credential pack, cham_hash_pk and maab_master_pk_sk with DOCTORA

    # == doctor ==
    print("VERIFYING SUPPORTING CREDENTIAL ===\n")
    print(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3]))

    print("CREATING ABE SECRET KEY FOR DOCTOR===\n")
    doctor_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Doctor", ["DOCTOR@DOCTORA"]) 

    print("ADAPTING BLOCK 2 HASH (Doctor) ===\n")
    supporting_credential = adaptSupportingCredentialBlock(supporting_credential, "block2", chamHash2, cham_hash_pk_sk["pk"], doctor_abe_secret_key, "Doctor")

    # TODO: add modified credential to credential registry, voting registry

    print("VERIFYING DOCTOR MODIFIED SUPPORTING CREDENTIAL (Doctor) ===\n")
    print(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3]))

    print("CREATING ABE SECRET KEY FOR PATIENT 1===\n")
    patient1_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Patient1", ["PATIENT@DOCTORA"])

    # action flow: share key and credential with patient

    # TODO: voting

    # == Patient ==
    print("ADAPTING BLOCK 3 (Patient 1) ===\n")
    supporting_credential = adaptSupportingCredentialBlock(supporting_credential, "block3", chamHash3, cham_hash_pk_sk["pk"], patient1_abe_secret_key, "Patient1")

    # TODO: add modified credential to credential registry, voting registry

    # == Relative ==

    print("VERIFYING HASH (Relative/Verifier) ===\n")
    print(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3]))

    ######################

    # # == hospital ==
    # print("CREATING ABE AUTHORITY ===\n")
    # maab_master_pk_sk = createABEAuthority("DOCTORA")
    # print("CREATING CH KEYS ===\n")
    # chamHash1 = chamwithemp.Chamwithemp()
    # cham_hash_pk_sk = createCHKeys(chamHash1)

    # print("CREATING REGULAR ROLE CREDENTIAL KEYS ===\n")
    # rc_sk, rc_pk = rsa.newkeys(512)
    # rc_symkey = Fernet.generate_key()
    
    # print("CREATING HASH ===\n")
    # print("LOADING HASH MESSAGE===\n")
    # credential_msg_json = loadCredential("supporting_credential_example.json")
    # credential_msg = json.dumps(credential_msg_json)
    # original_msg = json.dumps(credential_msg_json)

    # print("CREATING ACTUAL HASH===\n")
    # credential_pack = generateSupportingCredential(credential_msg, chamHash1, "(DOCTOR@DOCTORA or PATIENT@DOCTORA)", cham_hash_pk_sk["pk"], cham_hash_pk_sk["sk"], maab_master_pk_sk["pk"], hospital, "did:" + str(hospital.address), "did:" + str(doctor.address))
    # # action: share credential pack, cham_hash_pk and maab_master_pk_sk with DOCTORA

    # ## == doctor ==
    # print("VERIFYING HASH ===\n")
    # res1 = verifySupportingCredential(credential_msg, credential_pack["credential_hash"], cham_hash_pk_sk["pk"], doctor, chamHash1)
    # print(res1)

    # print("CREATING ABE SECRET KEY FOR DOCTOR===\n")
    # doctor_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Doctor", ["DOCTOR@DOCTORA"]) 
    
    # print("ADAPTING HASH (Doctor) ===\n")
    # credential_msg_json[1]["credentialSubject"]["permissions"] = ["some permissions"]
    # doctor_modified_message = json.dumps(credential_msg_json)
    # doctor_modified_credential_pack = adaptSupportingCredential(credential_pack["credential_hash"], original_msg, doctor_modified_message, cham_hash_pk_sk["pk"], chamHash1, doctor_abe_secret_key, doctor, "did:" + str(doctor.address), "did:" + str(patient.address), True, 1, "Doctor")
    
    # print("VERIFYING HASH (Doctor) ===\n")
    # res2 = verifySupportingCredential(doctor_modified_message, doctor_modified_credential_pack["credential_hash"], cham_hash_pk_sk["pk"], verifier, chamHash1)
    # print(res2)

    # print("CREATING ABE SECRET KEY FOR PATIENT 1===\n")
    # patient1_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Patient1", ["PATIENT@DOCTORA"])

    # # action flow: share key and credential with patient

    # print("TRY SHARE MODIFIED CREDENTIAL WITHOUT VOTING ===\n")
    # vote_res1 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    # print(vote_res1)

    # print("BEGIN VOTING PROCESS===\n")
    
    # print("ISSING ROLE CREDENTIAL===\n")
    # role_credential_pack = issueRoleCredential(rc_sk, rc_symkey)

    # print("ADDING VOTE===\n")
    # addVote(doctor_modified_credential_pack["credential_hash"], doctor_modified_credential_pack["credential_id"], doctor_modified_message, cham_hash_pk_sk["pk"], role_credential_pack, rc_pk, voter, chamHash1)
    
    # print("TRY SHARE MODIFIED CREDENTIAL WITH VOTING ===\n")
    # vote_res2 = tryShareModifiedCredential(doctor_modified_credential_pack["credential_id"], doctor)
    # print(vote_res2)

    # ## == Patient ==
    # print("ADAPTING HASH (Patient 1) ===\n")
    # credential_msg_json[2]["credentialSubject"]["permissions"] = ["some relative permissions"]
    # patient_modified_message = json.dumps(credential_msg_json)
    # patient_modified_credential_pack = adaptSupportingCredential(doctor_modified_credential_pack["credential_hash"], doctor_modified_message, patient_modified_message, cham_hash_pk_sk["pk"], chamHash1, patient1_abe_secret_key, patient, "did:" + str(patient.address), "did:" + str(relative.address), False, 0, "Patient1")

    # ## == Relative ==

    # print("VERIFYING HASH (Relative/Verifier) ===\n")
    # res3 = verifySupportingCredential(patient_modified_message, patient_modified_credential_pack["credential_hash"], cham_hash_pk_sk["pk"], verifier, chamHash1)
    # print(res3)