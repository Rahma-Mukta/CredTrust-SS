pragma solidity >=0.4.20;

contract revocationRegistry {

    mapping(string => string[]) keys_map;
    mapping(string => bool) AbeMasterKey_exist;
    mapping(string => bool) AbeSecretKey_exist;
    mapping(string => string[]) credential_map;
    mapping(string => bool) credential_exist;
    mapping(string => bool) ch_hash_exist;

    function addMasterKey(string memory key) public {
        AbeMasterKey_exist[key] = true;
    }

    function addSecretKey(string memory master_key, string memory secret_key) public {
        require (AbeMasterKey_exist[master_key] == true, "the Master key does not exists");
        AbeSecretKey_exist[secret_key] = true;
        keys_map[master_key].push(secret_key);
    }

    function addCredential(string memory redential_hash) public returns(bool) {
        credential_exist[redential_hash] = true;
    }

    function addDependentCredential(string memory top_credential_hash, string memory bottom_credential_hash) public returns(bool) {
        require (credential_exist[top_credential_hash] == true, "top_credential_hash does not exists");
        require (credential_exist[bottom_credential_hash] == true, "bottom_credential_hash does not exists");
        credential_map[top_credential_hash].push(bottom_credential_hash);
    }

    function addHashKey(string memory key) public {
        ch_hash_exist[key] = true;
    }

    function revokeMasterKey(string memory key, bool aggressive) public returns(bool) {
        AbeMasterKey_exist[key] = false;
        if (!aggressive) return true;

        for (uint i = 0; i < keys_map[key].length; i++) {
            revokeSecretKey(keys_map[key][i]);
        }
        delete keys_map[key];
        return true;
    }

    function revokeSecretKey(string memory key) public returns(bool){
        if (AbeSecretKey_exist[key] == false) return false;
        AbeSecretKey_exist[key] = false;
        return true;
    }

    function revokeDependentCredential(string memory credential_hash, bool aggressive) public returns(bool) {
        if (credential_exist[credential_hash] == false) return false;
        for (uint i = 0; i < credential_map[credential_hash].length; i++) {
            revokeDependentCredential(credential_map[credential_hash][i], aggressive);
            revokeCredential(credential_map[credential_hash][i]);
        }
        delete credential_map[credential_hash];
        revokeCredential(credential_hash);
        return true;
    }

    function revokeCredential(string memory credential_hash) public returns(bool) {
        if (credential_exist[credential_hash] == false) return false;
        credential_exist[credential_hash] = false;
        return true;
    }

    function revokeHashKey(string memory key) public {
        ch_hash_exist[key] = false;
    }

    function checkMasterKey(string memory key) public view returns(bool) {
        return (AbeMasterKey_exist[key] == true);
    }

    function checkSecretKey(string memory key) public view returns(bool) {
        return (AbeSecretKey_exist[key] == true);
    }     

    function checkCredential(string memory key) public view returns(bool) {
        return (credential_exist[key] == true);
    }

    function checkHashKey(string memory key) public view returns(bool) {
        return (ch_hash_exist[key] == true);
    }

}