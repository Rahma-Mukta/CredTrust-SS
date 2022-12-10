from flask import Flask, request
from brownie import credentialRegistry, accounts, VoteRegistry, IssuerRegistry, web3
import uuid
import json

from scripts.MAPCH import chamwithemp
from scripts.MAPCH import MAABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from json import dumps, loads
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction,SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.integergroup import integer
import re
# contractDeployAccount = accounts[0]
# hospital = accounts[1]
# doctor = accounts[2]
# patient = accounts[3]
# verifier = accounts[4]
# relative = accounts[5]
# voter = accounts[6]
# hospital_rc = accounts[7]

# cred_contract = credentialRegistry.deploy({'from': contractDeployAccount})
# vote_contract = VoteRegistry.deploy({'from': contractDeployAccount})
# issuer_contract = IssuerRegistry.deploy({'from': contractDeployAccount})
contractDeployAccount = accounts.load('deployment_account')
cred_contract = credentialRegistry.at('0x6983BB28834A39eAC034593bC7Df015cF23FC822')
vote_contract = VoteRegistry.at('0x36259565436E1D273def8089800C8B0902BD83a8')
issuer_contract = IssuerRegistry.at('0x73AC097d1601e5183783367dcA032e443F037f2d')
# network.gas_limit("auto")

groupObj = PairingGroup('SS512')
maabe = MAABE.MaabeRW15(groupObj)
public_parameters = maabe.setup()

app = Flask("__main__")

cur_index = 0
all_hash_funcs = {}

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

def convert_pairing_to_hex(obj_group, obj_to_convert):
    seralized_obj = obj_group.serialize(obj_to_convert)
    hexed_obj = seralized_obj.hex()
    return hexed_obj

def convert_hex_to_pairing(obj_group, hexed_obj):
    byte_obj1 = bytes.fromhex(hexed_obj)
    pairing_obj = obj_group.deserialize(byte_obj1)
    return pairing_obj

def convert_abe_master_sk_from_json(sk_json):
    return {"name" : sk_json["name"], "alpha" : convert_hex_to_pairing(groupObj, sk_json["alpha"]), "y" : convert_hex_to_pairing(groupObj, sk_json["y"])}

def convert_abe_master_pk_from_json(pk_json):
    return {"name" : pk_json["name"], "egga" : convert_hex_to_pairing(groupObj, pk_json["egga"]), "gy" : convert_hex_to_pairing(groupObj, pk_json["gy"]) }

def convert_cham_pk(hash_func, pk_json):
    return {
        'secparam': int(pk_json["secparam"]), 
        'N': convert_hex_to_pairing(hash_func.group, pk_json["N"]), 
        'phi_N': convert_hex_to_pairing(hash_func.group, pk_json["phi_N"])
    }

def convert_cham_sk(hash_func, sk_json):
    return {
        'p': convert_hex_to_pairing(hash_func.group, sk_json["p"]), 
        'q': convert_hex_to_pairing(hash_func.group, sk_json["q"])
    }

def convert_maabect_to_json(maabect):

    def convert_C(c_key):
        json_c = {}
        for c_policy, c_val in maabect[c_key].items():
            json_c[c_policy] = convert_pairing_to_hex(groupObj, c_val)
        return json_c

    return {
        "policy" : maabect["policy"],
        "C0" : convert_pairing_to_hex(groupObj, maabect["C0"]),
        "C1" : convert_C("C1"),
        "C2" : convert_C("C2"),
        "C3" : convert_C("C3"),
        "C4" : convert_C("C4")
    }

def convert_json_maabect_to_pairing(maabect_json):
    def convert_C(c_key):
        pairing_c = {}
        for c_policy, c_val in maabect_json[c_key].items():
            pairing_c[c_policy] = convert_hex_to_pairing(groupObj, c_val)
        return pairing_c

    return {
        "policy" : maabect_json["policy"],
        "C0" : convert_hex_to_pairing(groupObj, maabect_json["C0"]),
        "C1" : convert_C("C1"),
        "C2" : convert_C("C2"),
        "C3" : convert_C("C3"),
        "C4" : convert_C("C4")
    }

# credential
def issueCredential(issuing_account, issuer, holder, credential_hash, r, e, n1):
  id = str(uuid.uuid1())
  tx = cred_contract.issueCredential(id, issuer, holder, credential_hash, r, e, n1, {'from': issuing_account, 'gas': 7_500_000})
  print(dir(tx))
  web3.eth.wait_for_transaction_receipt(tx.hash)  
  return id

@app.route("/create_abe_authority", methods=['POST'])
def createABEAuthority():
    request_data = request.json
    authority_name = request_data["authority_name"]
    (pk, sk) = maabe.authsetup(public_parameters, authority_name)
    return dumps({
        "pk" : {"name" : authority_name, "egga" : convert_pairing_to_hex(groupObj, pk["egga"]), "gy" : convert_pairing_to_hex(groupObj, pk["gy"]) },
        "sk" : {"name" : authority_name, "alpha" : convert_pairing_to_hex(groupObj, sk["alpha"]), "y" : convert_pairing_to_hex(groupObj, sk["y"]) }
    })

@app.route("/create_ch_keys", methods=['GET'])
def createCHKeys():
    request_data = request.json
    hash_func_id = request_data["hash_func_id"]
    hash_func = all_hash_funcs[hash_func_id]
    (pk, sk) = hash_func.keygen(1024)

    return dumps({
        "pk" : {
            'secparam': pk["secparam"], 
            'N': convert_pairing_to_hex(hash_func.group, pk["N"]), 
            'phi_N': convert_pairing_to_hex(hash_func.group, pk["phi_N"])
            },
        "sk" : {
            'p': convert_pairing_to_hex(hash_func.group, sk["p"]), 
            'q': convert_pairing_to_hex(hash_func.group, sk["q"])
        }
    })

@app.route("/init_hash_fns", methods=['GET'])
def initHashFuncs():
  global cur_index
  id_list = []
  
  id1 = str(uuid.uuid1())
  id2 = str(uuid.uuid1())
  id3 = str(uuid.uuid1())

  chamHash1 = chamwithemp.Chamwithemp()
  chamHash2 = chamwithemp.Chamwithemp()
  chamHash3 = chamwithemp.Chamwithemp()

  id_list.append(id1)
  all_hash_funcs[id1] = chamHash1

  id_list.append(id2)
  all_hash_funcs[id2] = chamHash2

  id_list.append(id3)
  all_hash_funcs[id3] = chamHash3
  return dumps(id_list)

@app.route("/create_abe_attribute_secret_key", methods=['POST'])
def createABESecretKey():
  request_data = request.json 
  json_sk = request_data["sk"]
  sk = convert_abe_master_sk_from_json(json_sk)

  gid = request_data["gid"] # e.g PATIENTA

  user_attribute = list(request_data["user_attribute"]) # e.g ['PATIENT@DOCTORA']
  user_sk_dict = maabe.multiple_attributes_keygen(public_parameters, sk, gid, user_attribute)

  json_user_sk = {}

  for attr, attr_key in user_sk_dict.items():
      json_user_sk[attr] = {"K": convert_pairing_to_hex(groupObj, attr_key["K"]), "KP": convert_pairing_to_hex(groupObj, attr_key["KP"])}

  return dumps(json_user_sk)

def createHash(cham_pk, cham_sk, msg, hash_func, maabepk, access_policy):
    xi = hash_func.hash(cham_pk, cham_sk, msg)
    etd = [xi['p1'],xi['q1']]

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

    #if debug: print("\n\nCiphertext...\n")
    #groupObj.debug(ct)
    #print("ciphertext:=>", ct)
    h = {
        "h" : convert_pairing_to_hex(hash_func.group, xi['h']),
        "r" : convert_pairing_to_hex(hash_func.group, xi['r']),
        "N1" : convert_pairing_to_hex(hash_func.group, xi['N1']),
        "e" : convert_pairing_to_hex(hash_func.group, xi['e']),
        "cipher" : {'rkc': convert_maabect_to_json(maabect),'ec':symct }
    }
    return h

@app.route("/hash", methods=['POST'])
def generateAndIssueSupportingCredential():

  request_data = request.json
  
  supporting_credential_msg = request_data["supporting_credential_contents"]

  hash_id_list = request_data["hash_func_id_list"]

  key_hash_func = all_hash_funcs[hash_id_list[0]]

  json_cham_pk = request_data["cham_pk"]
  json_cham_sk = request_data["cham_sk"]
  ch_pk = convert_cham_pk(key_hash_func, json_cham_pk)
  ch_sk = convert_cham_sk(key_hash_func, json_cham_sk)

  access_policy = request_data["access_policy"]

  authority_abe_pk = { request_data["authority_abe_pk"]["name"] : convert_abe_master_pk_from_json(request_data["authority_abe_pk"]) }

  block1_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[0]), all_hash_funcs[hash_id_list[0]], authority_abe_pk, access_policy)
  block2_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[1]), all_hash_funcs[hash_id_list[1]], authority_abe_pk, access_policy)
  block3_original_hash = createHash(ch_pk, ch_sk, json.dumps(supporting_credential_msg[2]), all_hash_funcs[hash_id_list[2]], authority_abe_pk, access_policy)

  block1_cred_id = issueCredential(contractDeployAccount, "Hospital Issuer", "Doctor Issuer", block1_original_hash["h"], block1_original_hash["r"], block1_original_hash["e"], block1_original_hash["N1"])
  block2_cred_id = issueCredential(contractDeployAccount, "Hospital Issuer", "Doctor Issuer", block2_original_hash["h"], block2_original_hash["r"], block2_original_hash["e"], block2_original_hash["N1"])
  block3_cred_id = issueCredential(contractDeployAccount, "Hospital Issuer", "Doctor Issuer", block3_original_hash["h"], block3_original_hash["r"], block3_original_hash["e"], block3_original_hash["N1"])    

  credential_uuid_list = block1_cred_id + "_" + block2_cred_id + "_" + block3_cred_id

  # metadata_hash = createHash(ch_pk, ch_sk, credential_uuid_list, all_hash_funcs[hash_id_list[3]], authority_abe_pk, access_policy)
  
  metadata_id = issueCredential(contractDeployAccount, "Hospital Issuer", "Doctor Issuer", credential_uuid_list, "r", "e", "N1")

  # TODO: voting 
  # voting_required = False

  # if (supporting_credential_msg[0]["scenario"] in ["InPatient"]):
  #     voting_required = True

  # vote_contract.addCredential(metadata_id, voting_required, supporting_credential_msg[0]["numVotesRequired"], {'from': issuing_account})

  # print("\t - add Hospital to issuer registry")
  # adding to issuer registry
  tx = issuer_contract.addIssuer("Hospital Issuer", "PCH", str(ch_pk["N"]), {'from': contractDeployAccount})
  print(dir(tx))
  web3.eth.wait_for_transaction_receipt(tx)
  # collate supporting credential

  supporting_credential = {
      "metadata": {
          "msg" : credential_uuid_list,
          "hash" : credential_uuid_list,
          "id" : metadata_id
      },
      "block1" : {
          "msg" : json.dumps(supporting_credential_msg[0]),
          "hash" : block1_original_hash,
          "id" : block1_cred_id,
          "hash_func_id" : hash_id_list[0]
      },
      "block2" : {
          "msg" : json.dumps(supporting_credential_msg[1]),
          "hash" : block2_original_hash,
          "id" : block2_cred_id,
          "hash_func_id" : hash_id_list[1]
      },
      "block3" : {
          "msg" : json.dumps(supporting_credential_msg[2]),
          "hash" : block3_original_hash,
          "id" : block3_cred_id,
          "hash_func_id" : hash_id_list[2]
      }
  }

  return dumps(supporting_credential)

@app.route("/hash_verify", methods=['POST'])
def verifySupportingCredential():

  request_data = request.json

  supporting_credential = request_data["supporting_credential"]

  hash_id_list = request_data["hash_func_id_list"]

  key_hash_func = all_hash_funcs[hash_id_list[0]]

  json_cham_pk = request_data["cham_pk"]
  ch_pk = convert_cham_pk(key_hash_func, json_cham_pk)

  check_public_key = issuer_contract.checkIssuer("Hospital Issuer", "PCH", str(ch_pk["N"]), {'from': contractDeployAccount})
  print(dir(check_public_key))
  web3.eth.wait_for_transaction_receipt(check_public_key)

  chamHash1 = all_hash_funcs[hash_id_list[0]]
  chamHash2 = all_hash_funcs[hash_id_list[1]]
  chamHash3 = all_hash_funcs[hash_id_list[2]]

  cred_registry_check1 = cred_contract.checkCredential(supporting_credential["metadata"]["id"], supporting_credential["metadata"]["hash"], "r", "e", "N1", {'from': contractDeployAccount})
  print(dir(cred_registry_check1))
  web3.eth.wait_for_transaction_receipt(cred_registry_check1.hash)
  
  
  print("cred registry check 1 is : ", cred_registry_check1)
  cred_registry_check2 = cred_contract.checkCredential(supporting_credential["block1"]["id"], supporting_credential["block1"]["hash"]["h"], supporting_credential["block1"]["hash"]["r"], supporting_credential["block1"]["hash"]["e"], supporting_credential["block1"]["hash"]["N1"],{'from': contractDeployAccount})
  print(dir(cred_registry_check2))
  web3.eth.wait_for_transaction_receipt(cred_registry_check2.hash)
  cred_registry_check3 = cred_contract.checkCredential(supporting_credential["block2"]["id"], supporting_credential["block2"]["hash"]["h"], supporting_credential["block2"]["hash"]["r"], supporting_credential["block2"]["hash"]["e"], supporting_credential["block2"]["hash"]["N1"],{'from': contractDeployAccount})
  print(dir(cred_registry_check3))
  web3.eth.wait_for_transaction_receipt(cred_registry_check3.hash)
  cred_registry_check4 = cred_contract.checkCredential(supporting_credential["block3"]["id"], supporting_credential["block3"]["hash"]["h"], supporting_credential["block3"]["hash"]["r"], supporting_credential["block3"]["hash"]["e"], supporting_credential["block3"]["hash"]["N1"],{'from': contractDeployAccount})
  print(dir(cred_registry_check4))
  web3.eth.wait_for_transaction_receipt(cred_registry_check4.hash)

  if (check_public_key and cred_registry_check1 and cred_registry_check2 and cred_registry_check3 and cred_registry_check4):
      
      original_b1_hash = {
        "h" : convert_hex_to_pairing(chamHash1.group, supporting_credential["block1"]["hash"]["h"]),
        "r" : convert_hex_to_pairing(chamHash1.group, supporting_credential["block1"]["hash"]["r"]),
        "N1" : convert_hex_to_pairing(chamHash1.group, supporting_credential["block1"]["hash"]["N1"]),
        "e" : convert_hex_to_pairing(chamHash1.group, supporting_credential["block1"]["hash"]["e"])
      }

      original_b2_hash = {
        "h" : convert_hex_to_pairing(chamHash2.group, supporting_credential["block2"]["hash"]["h"]),
        "r" : convert_hex_to_pairing(chamHash2.group, supporting_credential["block2"]["hash"]["r"]),
        "N1" : convert_hex_to_pairing(chamHash2.group, supporting_credential["block2"]["hash"]["N1"]),
        "e" : convert_hex_to_pairing(chamHash2.group, supporting_credential["block2"]["hash"]["e"])
      }

      original_b3_hash = {
        "h" : convert_hex_to_pairing(chamHash3.group, supporting_credential["block3"]["hash"]["h"]),
        "r" : convert_hex_to_pairing(chamHash3.group, supporting_credential["block3"]["hash"]["r"]),
        "N1" : convert_hex_to_pairing(chamHash3.group, supporting_credential["block3"]["hash"]["N1"]),
        "e" : convert_hex_to_pairing(chamHash3.group, supporting_credential["block3"]["hash"]["e"])
      }
      
      block1_verify_res = chamHash1.hashcheck(ch_pk, supporting_credential["block1"]["msg"], original_b1_hash)
      block2_verify_res = chamHash2.hashcheck(ch_pk, supporting_credential["block2"]["msg"], original_b2_hash)
      block3_verify_res = chamHash3.hashcheck(ch_pk, supporting_credential["block3"]["msg"], original_b3_hash)

      return dumps({ "is_hash_valid" : str(block1_verify_res and block2_verify_res and block3_verify_res) })

  else:
      return dumps({ "is_hash_valid" : str(False) })

def collision(original_msg, new_msg, json_hash, hash_func, ch_pk, user_sk):
  
  h = {
        "h" : convert_hex_to_pairing(hash_func.group, json_hash["h"]),
        "r" : convert_hex_to_pairing(hash_func.group, json_hash["r"]),
        "N1" : convert_hex_to_pairing(hash_func.group, json_hash["N1"]),
        "e" : convert_hex_to_pairing(hash_func.group, json_hash["e"]),
        "cipher" : {"rkc" : convert_json_maabect_to_pairing(json_hash["cipher"]["rkc"]), "ec" : json_hash["cipher"]["ec"]}
    }
  
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
  new_h = {
        "h" : convert_pairing_to_hex(hash_func.group, h['h']),
        "r" : convert_pairing_to_hex(hash_func.group, r1),
        "N1" : convert_pairing_to_hex(hash_func.group, h['N1']),
        "e" : convert_pairing_to_hex(hash_func.group, h['e']),
        "cipher" : {'rkc': convert_maabect_to_json(h['cipher']['rkc']),'ec': h['cipher']['ec'] }
  }
  return new_h

@app.route("/adapt", methods=['POST'])
def adaptSupportingCredentialBlock():

  request_data = request.json
  supporting_credential = request_data["supporting_credential"]

  hash_id_list = request_data["hash_func_id_list"]
  key_hash_func = all_hash_funcs[hash_id_list[0]]
  # hardcode for api testing
  block_hash_func = all_hash_funcs[hash_id_list[1]]

  json_cham_pk = request_data["cham_pk"]
  ch_pk = convert_cham_pk(key_hash_func, json_cham_pk)

  gid = request_data["gid"]

  json_abe_secret_key = request_data["abe_secret_key"]
  original_abe_sk_dict = {}

  for attr, attr_key in json_abe_secret_key.items():
      original_abe_sk_dict[attr] = {"K": convert_hex_to_pairing(groupObj, attr_key["K"]), "KP": convert_hex_to_pairing(groupObj, attr_key["KP"])}

  abe_secret_key = {'GID': gid, 'keys': original_abe_sk_dict}

  block_original = supporting_credential["block2"]["msg"]
  block_modified = block_original
  block_modified = json.loads(block_modified)
  block_modified["credentialSubject"]["permissions"] = ["some permissions 2"]
  block_modified = json.dumps(block_modified)

  hash_modified = collision(block_original, block_modified, supporting_credential["block2"]["hash"], block_hash_func, ch_pk, abe_secret_key)
  
  modified_supporting_credential = supporting_credential

  modified_supporting_credential["block2"]["hash"] = hash_modified
  modified_supporting_credential["block2"]["msg"] = block_modified

  # TODO: add voting
  tx = cred_contract.issueCredential(supporting_credential["block2"]["id"], "Doctor Issuer", "Patient Issuer", supporting_credential["block2"]["hash"]["h"], supporting_credential["block2"]["hash"]["r"], supporting_credential["block2"]["hash"]["e"], supporting_credential["block2"]["hash"]["N1"], {'from': contractDeployAccount, 'max_fee' : '0.20 gwei'})
  print(dir(tx))
  web3.eth.wait_for_transaction_receipt(tx)
  tx = issuer_contract.addIssuer("Doctor Issuer", "PCH", str(ch_pk["N"]), {'from': contractDeployAccount})
  print(dir(tx))
  web3.eth.wait_for_transaction_receipt(tx)

  return dumps(modified_supporting_credential)

@app.route('/')
def hello():
    return 'Hello, World!'

app.run(threaded=False)