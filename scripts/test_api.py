import requests
import json

head = {"Content-Type": "application/json"}
body = {}

### create abe authority
print("CREATING ABE AUTHORITY ===\n")
body = { "authority_name" : "DOCTORA" }
x = requests.post("http://127.0.0.1:5000/create_abe_authority", headers=head, json=body)
maab_master_pk_sk = json.loads(x.text)

### init hash funcs
print("CREATING HASH FUNCTIONS ===\n")
x = requests.get("http://127.0.0.1:5000/init_hash_fns", headers=head)
hash_func_ids_list = json.loads(x.text)

### create ch keys
print("CREATING CH KEYS FOR 1 ===\n")
body = { "hash_func_id" : hash_func_ids_list[0] }
x = requests.get("http://127.0.0.1:5000/create_ch_keys", headers=head, json=body)
cham_hash_pk_sk1 = json.loads(x.text)

# print("CREATING CH KEYS FOR 2 ===\n")
# body = { "hash_func_id" : hash_func_ids_list[1] }
# x = requests.get("http://127.0.0.1:5000/create_ch_keys", headers=head, json=body)
# cham_hash_pk_sk2 = json.loads(x.text)

# print("CREATING CH KEYS FOR 3 ===\n")
# body = { "hash_func_id" : hash_func_ids_list[2] }
# x = requests.get("http://127.0.0.1:5000/create_ch_keys", headers=head, json=body)
# cham_hash_pk_sk3 = json.loads(x.text)

### create abe attribute secret key
print("CREATING ABE SECRET KEY ===\n")
body = {
    "sk" : maab_master_pk_sk["sk"],
    "gid" : "Patient",
    "user_attribute" : ["PATIENT@DOCTORA"]
}

x = requests.post("http://127.0.0.1:5000/create_abe_attribute_secret_key", headers=head, json=body)
abe_secret_key = json.loads(x.text)
# print(abe_secret_key)

cred = [{
    "@context" : ["https://www.w3.org/2018/credentials/v1"],
    "id": "http://example.edu/credentials/1872",
    "type": [" VerifiableCredential ", "DelegationCredential"],
    "Officialissuer" : "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "issuanceDate": "2021-07-10T04:20:00Z", 
    "expirationDate": "2021-07-17T04:20:00Z",
    "scenario": "InPatient",
    "approvalPolicty": ["Doctor", "Nurse"],
    "numVotesRequired": 5,
    "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "permissions": ["some permission"]
    }
},
{
    "ProxyIssuer" : "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "credentialSubject": {
        "id": "did:example_patient:fcgfc2g823fcdd387f23fd32",
        "permissions": ["some permission"]
    }
},
{
    "PersonalIssuer" : "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "permissions": ["some permission"]
    }
}]

### hash
print("CREATING SUPPORTING CREDENTIAL ===\n")
body = {
  "supporting_credential_contents" : cred,
  "cham_pk" : cham_hash_pk_sk1["pk"],
  "cham_sk" : cham_hash_pk_sk1["sk"],
  "hash_func_id_list" : hash_func_ids_list,
  "access_policy" : "(PATIENT@DOCTORA)",
  "authority_abe_pk" : maab_master_pk_sk["pk"]
}
x = requests.post("http://127.0.0.1:5000/hash", headers=head, json=body)
supporting_credential = json.loads(x.text)

### verify
print("VERIFYING SUPPORTING CREDENTIAL ===\n")
body = {
    "supporting_credential" : supporting_credential,
    "cham_pk" : cham_hash_pk_sk1["pk"],
    "hash_func_id_list" : hash_func_ids_list
}
x = requests.post("http://127.0.0.1:5000/hash_verify", headers=head, json=body)
hash_res = json.loads(x.text)
print(hash_res)
assert hash_res["is_hash_valid"] == "True"

### collision
print("ADAPTING HASH ===\n")
body = {
    "supporting_credential" : supporting_credential,
    "hash_func_id_list" : hash_func_ids_list,
    "cham_pk" : cham_hash_pk_sk1["pk"],
    "gid" : "Patient",
    "abe_secret_key" : abe_secret_key
}

x = requests.post("http://127.0.0.1:5000/adapt", headers=head, json=body)
supporting_credential_modified = json.loads(x.text)

### verify
print("VERIFYING HASH 2 ===\n")
body = {
    "supporting_credential" :  supporting_credential_modified,
    "cham_pk" : cham_hash_pk_sk1["pk"],
    "hash_func_id_list" : hash_func_ids_list
}
x = requests.post("http://127.0.0.1:5000/hash_verify", headers=head, json=body)
hash_res = json.loads(x.text)
assert hash_res["is_hash_valid"] == "True"
print(hash_res)
