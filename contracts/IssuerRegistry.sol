pragma solidity ^0.4.20;

contract IssuerRegistry {

    struct DDO
    {
        string did;
        string publicKeyType;
        string publicKey;
    }

    string[] issuers;
    mapping (string => DDO) issuers_ddo;
    
    function addIssuer(string _did, string  _keyType, string _publicKey) public {
        issuers_ddo[_did].did = _did; 
        issuers_ddo[_did].publicKeyType = _keyType;
        issuers_ddo[_did].publicKey = _publicKey;

        issuers.push(_did);
    }

    function checkIssuer(string _did, string  _keyType, string _publicKey) public view returns (bool exists) {

        bool encountered = false;
        
        for (uint256 i = 0; i < issuers.length; ++i) { 
            if (keccak256(abi.encodePacked(issuers[i])) == keccak256(abi.encodePacked(_did)))
            {
                if ( 
                    (keccak256(abi.encodePacked(issuers_ddo[_did].publicKeyType)) == keccak256(abi.encodePacked(_keyType))) && 
                    (keccak256(abi.encodePacked(issuers_ddo[_did].publicKey)) == keccak256(abi.encodePacked(_publicKey)))
                ) 
                {
                    encountered = true;
                }

            }
        }

        return encountered;
    }
}