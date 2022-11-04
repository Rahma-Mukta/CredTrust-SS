pragma solidity ^0.4.20;

contract credentialRegistry {

    struct Credential
    {
        string id;
        string issuer;
        string holder;
        string credentialHash;
        string r;
        string e;
        string n1;
    }

    mapping(string => Credential) private credential;

    function issueCredential(
        string _id,
        string _issuer,
        string _holder,
        string _credentialHash,
        string _r,
        string _e,
        string _N1
    ) public {
        credential[_id].id = _id;
        credential[_id].issuer = _issuer;
        credential[_id].holder = _holder;
        credential[_id].credentialHash = _credentialHash;
        credential[_id].r = _r;
        credential[_id].e = _e;
        credential[_id].n1 = _N1;
    }

    // use string for credential hash value is for scalability, and also to avoid an error that "cannot return string, string, string, bytes32, string ...".
    function getCredential(string _id)
        public
        view
        returns (
            string __id,
            string __issuer,
            string __holder,
            string __credentialHash,
            string __r,
            string __e,
            string __n1
        )
    {
        return (
            credential[_id].id,
            credential[_id].issuer,
            credential[_id].holder,
            credential[_id].credentialHash,
            credential[_id].r,
            credential[_id].e,
            credential[_id].n1
        );
    }

    function checkCredential(
        string _id,
        string _credentialHash,
        string _r,
        string _e,
        string _n1
    ) public view returns (bool isSame)
    {
        return (
            (keccak256(abi.encodePacked(credential[_id].credentialHash)) == keccak256(abi.encodePacked(_credentialHash))) &&
            (keccak256(abi.encodePacked(credential[_id].r)) == keccak256(abi.encodePacked(_r))) &&
            (keccak256(abi.encodePacked(credential[_id].e)) == keccak256(abi.encodePacked(_e))) &&
            (keccak256(abi.encodePacked(credential[_id].n1)) == keccak256(abi.encodePacked(_n1)))
        );
    }
}