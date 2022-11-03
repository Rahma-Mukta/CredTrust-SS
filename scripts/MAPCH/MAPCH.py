from flask import Flask, request
import chamwithemp
import MAABE
from charm.toolbox.pairinggroup import PairingGroup, GT
from json import dumps, loads
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction,SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from charm.toolbox.integergroup import integer
import re

app = Flask(__name__)

groupObj = PairingGroup('SS512')

maabe = MAABE.MaabeRW15(groupObj)
chamHash = chamwithemp.Chamwithemp()

public_parameters = maabe.setup()
print(public_parameters)

#################################

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

def convert_cham_pk(pk_json):
    return {
        'secparam': int(pk_json["secparam"]), 
        'N': convert_hex_to_pairing(chamwithemp.group, pk_json["N"]), 
        'phi_N': convert_hex_to_pairing(chamwithemp.group, pk_json["phi_N"])
    }

def convert_cham_sk(sk_json):
    return {
        'p': convert_hex_to_pairing(chamwithemp.group, sk_json["p"]), 
        'q': convert_hex_to_pairing(chamwithemp.group, sk_json["q"])
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

def cut_text(text,lenth): 
    textArr = re.findall('.{'+str(lenth)+'}', text) 
    textArr.append(text[(len(textArr)*lenth):]) 
    return textArr


#################################

def maabe_auth_setup(authority_name):
    (pk, sk) = maabe.authsetup(public_parameters, authority_name)
    return (pk, sk)

# @app.route("/create_ch_keys", methods=['GET'])
# def create_chamhash_keys():
    
#     (pk, sk) = chamHash.keygen(1024)
    
#     return dumps({
#         "pk" : {
#             'secparam': pk["secparam"], 
#             'N': convert_pairing_to_hex(chamwithemp.group, pk["N"]), 
#             'phi_N': convert_pairing_to_hex(chamwithemp.group, pk["phi_N"])
#             },
#         "sk" : {
#             'p': convert_pairing_to_hex(chamwithemp.group, sk["p"]), 
#             'q': convert_pairing_to_hex(chamwithemp.group, sk["q"])
#         }
#     })

def create_multiple_attributes_key(abe_master_sk, gid, user_attribute):
    user_sk_dict = maabe.multiple_attributes_keygen(public_parameters, abe_master_sk, gid, user_attribute)
    return user_sk_dict

@app.route("/hash", methods=['POST'])
def hash():
    request_data = request.json 
    
    ## cham hash ##
    json_cham_pk = request_data["cham_pk"]
    json_cham_sk = request_data["cham_sk"]
    msg = request_data["message"]

    pk = convert_cham_pk(json_cham_pk)
    sk = convert_cham_sk(json_cham_sk)

    xi = chamHash.hash(pk, sk, msg)
    etd = [xi['p1'],xi['q1']]
    #if debug: print("Hash...")
    #if debug: print("hash result =>", xi)
 
    ## abe encypt ##
    maabepk = { request_data["authority_abe_pk"]["name"] : convert_abe_master_pk_from_json(request_data["authority_abe_pk"]) }
    access_policy = request_data["access_policy"]

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
        "h" : convert_pairing_to_hex(chamwithemp.group, xi['h']),
        "r" : convert_pairing_to_hex(chamwithemp.group, xi['r']),
        "N1" : convert_pairing_to_hex(chamwithemp.group, xi['N1']),
        "e" : convert_pairing_to_hex(chamwithemp.group, xi['e']),
        "cipher" : {'rkc': convert_maabect_to_json(maabect),'ec':symct }
    }

    return dumps(h)

# NOTE: test
@app.route("/hash_verify", methods=['POST'])
def verify():
    request_data = request.json 
    msg = request_data["message"]
    json_cham_pk = request_data["cham_pk"]
    json_hash = request_data["hash"]

    pk = convert_cham_pk(json_cham_pk)
    original_hash = {
        "h" : convert_hex_to_pairing(chamwithemp.group, json_hash["h"]),
        "r" : convert_hex_to_pairing(chamwithemp.group, json_hash["r"]),
        "N1" : convert_hex_to_pairing(chamwithemp.group, json_hash["N1"]),
        "e" : convert_hex_to_pairing(chamwithemp.group, json_hash["e"])
    }
    # original_hash = {
    #     "h" : convert_hex_to_pairing(chamwithemp.group, json_hash["h"]),
    #     "r" : convert_hex_to_pairing(chamwithemp.group, json_hash["r"]),
    #     "N1" : convert_hex_to_pairing(chamwithemp.group, json_hash["N1"]),
    #     "e" : convert_hex_to_pairing(chamwithemp.group, json_hash["e"]),
    #     "cipher" : {"rkc" : convert_json_maabect_to_pairing(json_hash["cipher"]["rkc"]), "ec" : json_hash["cipher"]["ec"]}
    # }

    checkresult = chamHash.hashcheck(pk, msg, original_hash)
    return dumps({ "is_hash_valid" : str(checkresult) })

# NOTE: test
@app.route("/adapt", methods=['POST'])
def collision():

    request_data = request.json
    json_hash = request_data["hash"]
    msg1 = request_data["original_message"]
    msg2 = request_data["new_message"]
    json_cham_pk = request_data["cham_pk"]
    gid = request_data["gid"]
    
    json_abe_secret_key = request_data["abe_secret_key"]
    pk = convert_cham_pk(json_cham_pk)
    h = {
        "h" : convert_hex_to_pairing(chamwithemp.group, json_hash["h"]),
        "r" : convert_hex_to_pairing(chamwithemp.group, json_hash["r"]),
        "N1" : convert_hex_to_pairing(chamwithemp.group, json_hash["N1"]),
        "e" : convert_hex_to_pairing(chamwithemp.group, json_hash["e"]),
        "cipher" : {"rkc" : convert_json_maabect_to_pairing(json_hash["cipher"]["rkc"]), "ec" : json_hash["cipher"]["ec"]}
    }

    original_abe_sk_dict = {}
    for attr, attr_key in json_abe_secret_key.items():
        original_abe_sk_dict[attr] = {"K": convert_hex_to_pairing(groupObj, attr_key["K"]), "KP": convert_hex_to_pairing(groupObj, attr_key["KP"])}

    user_sk = {'GID': gid, 'keys': original_abe_sk_dict}

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
    r1 = chamHash.collision(msg1, msg2, h, rec_etdint, pk)
    #if debug: print("new randomness =>", r1)
    #new_h = {'h': h['h'], 'r': r1, 'cipher': h['cipher'], 'N1': h['N1'], 'e': h['e']}
    
    new_json_h = {
        "h" : convert_pairing_to_hex(chamwithemp.group, h['h']),
        "r" : convert_pairing_to_hex(chamwithemp.group, r1),
        "N1" : convert_pairing_to_hex(chamwithemp.group, h['N1']),
        "e" : convert_pairing_to_hex(chamwithemp.group, h['e']),
        "cipher" : {'rkc': convert_maabect_to_json(h['cipher']['rkc']),'ec': h['cipher']['ec'] }
    }
    
    return dumps(new_json_h)

# @app.route('/post_json', methods=['POST'])
# def process_json():
#     json = request.json
#     return json

# access_policy = '(PATIENT@DOCTORA)'
# user_sk = {'GID': gid, 'keys': MAPCH.merge_dicts(user_sk1)}

#################################

app.run()