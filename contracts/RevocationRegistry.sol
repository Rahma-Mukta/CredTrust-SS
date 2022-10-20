pragma solidity >=0.4.20;

contract revocationRegistry {

    mapping(string => string[]) keys_map;
    mapping(string => bool) AbeMasterKey_exist;
    mapping(string => bool) AbeSecretKey_exist;

    function addMasterKey(string memory key) public {
        AbeMasterKey_exist[key] = true;
    }

    function addSecretKey(string memory master_key, string memory secret_key) public {
        require (AbeMasterKey_exist[master_key] == true, "the Master key does not exists");
        AbeSecretKey_exist[secret_key] = true;
        keys_map[master_key].push(secret_key);
    }

    function revokeMasterKey(string memory key) public {
        AbeMasterKey_exist[key] = false;
        for (uint i = 0; i < keys_map[key].length; i++) {
            revokeSecretKey(keys_map[key][i]);
        }
        delete keys_map[key];
    }

    function revokeSecretKey(string memory key) public {
        AbeSecretKey_exist[key] = false;
    }

    function checkMasterKey(string memory key) public view returns(bool) {
        return (AbeMasterKey_exist[key] == true);
    }

    function checkSecretKey(string memory key) public view returns(bool) {
        return (AbeSecretKey_exist[key] == true);
    }     

}