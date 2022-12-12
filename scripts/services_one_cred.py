from this import d
from brownie import credentialRegistry, accounts, VoteRegistry, IssuerRegistry
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
import sys

contractDeployAccount = accounts[0]
hospital = accounts[1]
doctor = accounts[2]
patient = accounts[3]
verifier = accounts[4]
relative = accounts[5]
voter = accounts[6]
hospital_rc = accounts[7]

cred_contract = credentialRegistry.deploy({'from': contractDeployAccount})
vote_contract = VoteRegistry.deploy({'from': contractDeployAccount})
issuer_contract = IssuerRegistry.deploy({'from': contractDeployAccount})

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

def issueCredential(issuing_account, issuer, holder, credential_hash):
    id = str(uuid.uuid1())
    cred_contract.issueCredential(id, issuer, holder, credential_hash, {'from': issuing_account})

    return id

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

def createHashWithUUID(cham_pk, cham_sk, msg, hash_func, abe_master_pk, access_policy):
  id = str(uuid.uuid1())
  res = createHash(cham_pk, cham_sk, msg, hash_func, abe_master_pk, access_policy)
  return { "id" : id, "hash" : res }

def generateAndIssueSupportingCredential(supporting_credential, hash_funcs, access_policy, ch_pk, ch_sk, authority_abe_pk, issuing_account, official_issuer, holder):

    supporting_credential_msg = supporting_credential
    supporting_credential_msg[0]["Officialissuer"] = official_issuer

    print("\t - create chameleon hash for block 1, block 2 and block 3")
    block1_original_hash = createHashWithUUID(ch_pk, ch_sk, json.dumps(supporting_credential_msg[0]), hash_funcs[0], authority_abe_pk, access_policy)
    block2_original_hash = createHashWithUUID(ch_pk, ch_sk, json.dumps(supporting_credential_msg[1]), hash_funcs[1], authority_abe_pk, access_policy)
    block3_original_hash = createHashWithUUID(ch_pk, ch_sk, json.dumps(supporting_credential_msg[2]), hash_funcs[2], authority_abe_pk, access_policy)

    credential_uuid_list = block1_original_hash["id"] + "_" + block2_original_hash["id"] + "_" + block3_original_hash["id"]
    
    print("\t - add supporting credential to credential registry")
    metadata_id = issueCredential(issuing_account, official_issuer, holder, credential_uuid_list)

    if (supporting_credential_msg[0]["scenario"] in ["InPatient"]):
      vote_contract.addCredential(metadata_id, True, supporting_credential_msg[0]["numVotesRequired"], {'from': issuing_account})

    print("\t - add Hospital to issuer registry")
    # adding to issuer registry
    issuer_contract.addIssuer(official_issuer, "PCH", str(ch_pk["N"]), {'from': issuing_account})

    # collate supporting credential

    supporting_credential = {
        "metadata": {
            "msg" : credential_uuid_list,
            "hash" : credential_uuid_list,
            "id" : metadata_id
        },
        "block1" : {
            "msg" : json.dumps(supporting_credential_msg[0]),
            "hash" : block1_original_hash["hash"],
            "id" : block1_original_hash["id"]
        },
        "block2" : {
            "msg" : json.dumps(supporting_credential_msg[1]),
            "hash" : block2_original_hash["hash"],
            "id" : block2_original_hash["id"]
        },
        "block3" : {
            "msg" : json.dumps(supporting_credential_msg[2]),
            "hash" : block3_original_hash["hash"],
            "id" : block3_original_hash["id"]
        }
    }

    return supporting_credential

def verifySupportingCredential(supporting_credential, ch_pk, hash_funcs):

    msg = supporting_credential["block1"]["msg"]
    official_issuer = (json.loads(msg))["Officialissuer"]

    print("\t - check issuer is in issuer registry")

    check_public_key = issuer_contract.checkIssuer(official_issuer, "PCH", str(ch_pk["N"]), {'from': accounts[0]})

    chamHash1 = hash_funcs[0]
    chamHash2 = hash_funcs[1]
    chamHash3 = hash_funcs[2]

    print("\t - check credential is valid in credential registry")

    cred_registry_check = cred_contract.checkCredential(supporting_credential["metadata"]["id"], supporting_credential["metadata"]["hash"], {'from': accounts[0]})

    print("\t - check credential signature")

    if (check_public_key and cred_registry_check):
        block1_verify_res = chamHash1.hashcheck(ch_pk, supporting_credential["block1"]["msg"], supporting_credential["block1"]["hash"])
        block2_verify_res = chamHash2.hashcheck(ch_pk, supporting_credential["block2"]["msg"], supporting_credential["block2"]["hash"])
        block3_verify_res = chamHash3.hashcheck(ch_pk, supporting_credential["block3"]["msg"], supporting_credential["block3"]["hash"])

        return (block1_verify_res and block2_verify_res and block3_verify_res)

    else:
        return False

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

def adaptSupportingCredentialBlock(supporting_credential, block, hash_func, ch_pk, abe_secret_key, gid):

    block_original = supporting_credential[block]["msg"]
    block_modified = block_original
    block_modified = json.loads(block_modified)
    block_modified["credentialSubject"]["permissions"] = ["some permissions 2"]
    block_modified = json.dumps(block_modified)

    print("\t - computing collision")
    hash_modified = collision(block_original, block_modified, supporting_credential[block]["hash"], hash_func, ch_pk, abe_secret_key, gid)
    
    modified_supporting_credential = supporting_credential

    modified_supporting_credential[block]["hash"] = hash_modified
    modified_supporting_credential[block]["msg"] = block_modified

    return modified_supporting_credential

def loadCredential(file):
    with open(file, "r") as f:
        return json.load(f)

def issueAdaptedSupportingCredential(supporting_credential, block, issuer_account, issuer, holder, ch_pk):
    
    print("\t - check voting results")
    if (checkVoting(supporting_credential["metadata"]["id"], issuer_account)):

        # print("\t - issue modified credential")
        # cred_contract.issueCredential(supporting_credential[block]["id"], issuer, holder, supporting_credential[block]["hash"]["h"], supporting_credential[block]["hash"]["r"], supporting_credential[block]["hash"]["e"], supporting_credential[block]["hash"]["N1"], {'from': issuer_account})
        
        print("\t - adding issuer to registry")
        issuer_contract.addIssuer(issuer, "PCH", str(ch_pk["N"]), {'from': issuer_account})

        return True
    else:
        return False

## voting

def checkVoting(credential_id, issuer_account):
    return vote_contract.isVotingCompleted(credential_id, {'from': issuer_account})

def addVoteAndTryUpdateCredential(supporting_credential, role_credential_pack, role_credential_pk, block, voting_account, issuer_account, issuer, holder, ch_pk, rc_issuer):
    
    # role credential
    concat_rc_keys = str(role_credential_pk) + "_" + str(role_credential_pack["encryped_key"])

    print("\t - check issuer is in issuer registry")
    if (issuer_contract.checkIssuer(rc_issuer, "RSA_FERMAT", concat_rc_keys, {'from': accounts[0]}) == False):
        print("ROLE CREDENTIAL KEYS ARE NOT VALID")
        return False
    
    print("\t - decrypt credential, check voter is eligible for voting")
    decryped_sym_key = rsa.decrypt(role_credential_pack["encryped_key"], role_credential_pk)
    fernet = Fernet(decryped_sym_key)    

    decryped_rc = fernet.decrypt(role_credential_pack["role_credential"]).decode()
    json_rc = json.loads(decryped_rc)

    block1 = json.loads(supporting_credential["block1"]["msg"])
    voter_did = json_rc["credentialSubject"]["id"]

    if (json_rc["credentialSubject"]["role"] in block1["approvalPolicty"]):

        print("\t - add vote to voting registry")
        vote_contract.vote(supporting_credential["metadata"]["id"], voter_did, {'from': voting_account})

        print("\t - try to issue modified credential")
        return issueAdaptedSupportingCredential(supporting_credential, block, issuer_account, issuer, holder, ch_pk)

    else:
        print("COULD NOT VOTE BECAUSE VOTER DOES NOT HAVE THE RIGHT ROLE")
        return False

def issueRoleCredential(rc_rsapkey, rc_rsaskey, rc_symkey, issuer, holder_did):
    
    print("\t - sign role credential")
    
    rc_json = loadCredential("role_credential_example.json")
    rc_json["credentialSubject"]["id"] = holder_did
    rc_msg = json.dumps(rc_json)

    fernet = Fernet(rc_symkey)
    enc_rc = fernet.encrypt(rc_msg.encode())
    enc_key = rsa.encrypt(rc_symkey, rc_rsaskey)


    print("\t - issue role credential")
    cred_id = issueCredential(issuer, "did:" + str(issuer.address), holder_did, enc_rc)

    concat_key = str(rc_rsapkey) + "_" + str(enc_key)

    print("\t - add issuer to issuer registry")
    issuer_contract.addIssuer("did:" + str(issuer.address), "RSA_FERMAT", concat_key, {'from': issuer})

    return {
        "id" : cred_id, 
        "encryped_key" : enc_key,
        "role_credential" : enc_rc
    }

def main():

    # == hospital ==

    print("=== HOSPITAL ===")

    print("CREATING ABE AUTHORITY ===")
    maab_master_pk_sk = createABEAuthority("DOCTORA")

    print("CREATING CH KEYS ===")
    chamHash1 = chamwithemp.Chamwithemp()
    cham_hash_pk_sk = createCHKeys(chamHash1)

    chamHash2 = chamwithemp.Chamwithemp()
    _ = createCHKeys(chamHash2)

    chamHash3 = chamwithemp.Chamwithemp()
    _ = createCHKeys(chamHash3)

    chamHash4 = chamwithemp.Chamwithemp()
    _ = createCHKeys(chamHash4)

    print("CREATING REGULAR ROLE CREDENTIAL KEYS ===")
    print("\t - create RSA public private key pair")
    rc_sk, rc_pk = rsa.newkeys(512)
    print("\t - create symmetric encryption (fernet) key")
    rc_symkey = Fernet.generate_key()

    print("CREATING AND ISSUING SUPPORTING CREDENTIAL ===")
    credential_msg_json = loadCredential("supporting_credential_example.json")
    supporting_credential = generateAndIssueSupportingCredential(credential_msg_json, [chamHash1, chamHash2 , chamHash3, chamHash4], "(DOCTOR@DOCTORA or PATIENT@DOCTORA)",
                                                                 cham_hash_pk_sk["pk"], cham_hash_pk_sk["sk"], maab_master_pk_sk["pk"], 
                                                                 hospital, "did:" + str(hospital.address), "did:" + str(doctor.address))

    print("ACTION: SHARE CREDENTIAL & KEYS WITH DOCTOR(S)")
    # action: share credential pack, cham_hash_pk and maab_master_pk_sk with DOCTORA

    print("=== DOCTOR ===")

    # == doctor ==
    print("VERIFYING SUPPORTING CREDENTIAL ===")
    print("\t - attempt result: " + str(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3])))

    print("CREATING ABE SECRET KEY FOR DOCTOR ===")
    doctor_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Doctor", ["DOCTOR@DOCTORA"]) 

    print("ADAPTING SUPPORTING CREDENTIAL (BLOCK 2 HASH) ===")
    supporting_credential = adaptSupportingCredentialBlock(supporting_credential, "block2", chamHash2, cham_hash_pk_sk["pk"], doctor_abe_secret_key, "Doctor")

    print("TRY TO SHARE MODIFIED CREDENTIAL WITHOUT VOTES ===")
    try_issue_doctor_modified_sc = issueAdaptedSupportingCredential(supporting_credential, "block2", doctor , "did:" + str(doctor.address), "did:" + str(patient.address), cham_hash_pk_sk["pk"])
    print("\t - attempt result: " + str(try_issue_doctor_modified_sc))

    print("BEGIN VOTING PROCESS ===")
    
    print("ISSUING ROLE CREDENTIAL ===")
    role_credential_pack = issueRoleCredential(rc_pk, rc_sk, rc_symkey, hospital_rc, "did" + str(voter.address))

    print("ADDING VOTE ===")
    addVoteAndTryUpdateCredential(supporting_credential, role_credential_pack, rc_pk, "block2", voter, doctor, "did:" + str(doctor.address), "did:" + str(patient.address), cham_hash_pk_sk["pk"], "did:" + str(hospital_rc.address))

    print("VERIFYING DOCTOR MODIFIED SUPPORTING CREDENTIAL (Doctor) ===")
    print("\t - attempt result: " + str(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3])))

    print("CREATING ABE SECRET KEY FOR PATIENT 1 ===\n")
    patient1_abe_secret_key = createABESecretKey(maab_master_pk_sk["sk"], "Patient1", ["PATIENT@DOCTORA"])

    # action flow: share key and credential with patient
    print("ACTION: SHARE CREDENTIAL & KEYS WITH PATIENT")

    # == Patient ==
    print("=== PATIENT ===")

    print("ADAPTING SUPPORTING CREDENTIAL (BLOCK 3 HASH) ===")
    supporting_credential = adaptSupportingCredentialBlock(supporting_credential, "block3", chamHash3, cham_hash_pk_sk["pk"], patient1_abe_secret_key, "Patient1")

    try_issue_patient_modified_sc = issueAdaptedSupportingCredential(supporting_credential, "block3", patient , "did:" + str(patient.address), "did:" + str(relative.address), cham_hash_pk_sk["pk"])
    print("\t - attempt result: " + str(try_issue_patient_modified_sc))

    # == Relative ==
    print("=== RELATIVE/VERIFIER ===")
    print("VERIFYING HASH (Relative/Verifier) ===\n")
    print("\t - attempt result: " + str(verifySupportingCredential(supporting_credential, cham_hash_pk_sk["pk"], [chamHash1, chamHash2 , chamHash3])))