pragma solidity ^0.4.20;

contract credentialRegistry {

    struct Credential
    {
        string id;
        string issuer;
        string holder;
        string credentialHash;
    }

    mapping(string => Credential) private credential;

    function issueCredential(
        string _id,
        string _issuer,
        string _holder,
        string _credentialHash
    ) public {
        credential[_id].id = _id;
        credential[_id].issuer = _issuer;
        credential[_id].holder = _holder;
        credential[_id].credentialHash = _credentialHash;
    }

    // use string for credential hash value is for scalability, and also to avoid an error that "cannot return string, string, string, bytes32, string ...".
    function getCredential(string _id)
        public
        view
        returns (
            string __id,
            string __issuer,
            string __holder,
            string __credentialHash
        )
    {
        return (
            credential[_id].id,
            credential[_id].issuer,
            credential[_id].holder,
            credential[_id].credentialHash
        );
    }

    function checkCredential(
        string _id,
        string _credentialHash
    ) public view returns (bool isSame)
    {
        return (
            (keccak256(abi.encodePacked(credential[_id].credentialHash)) == keccak256(abi.encodePacked(_credentialHash)))
        );
    }
}