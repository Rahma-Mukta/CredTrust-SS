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

    // function issueSupportingCredential(
    //     string _id1,
    //     string _issuer1,
    //     string _holder1,
    //     string _credentialHash1,
    //     string _r1,
    //     string _e1,
    //     string _N11,
    //     string _id2,
    //     string _issuer2,
    //     string _holder2,
    //     string _credentialHash2,
    //     string _r2,
    //     string _e2,
    //     string _N12,
    //     string _id3,
    //     string _issuer3,
    //     string _holder3,
    //     string _credentialHash3,
    //     string _r3,
    //     string _e3,
    //     string _N13,
    //     string _id4,
    //     string _issuer4,
    //     string _holder4,
    //     string _credentialHash4,
    //     string _r4,
    //     string _e4,
    //     string _N14
    // ) public {
    //     credential[_id1].id = _id1;
    //     credential[_id1].issuer = _issuer1;
    //     credential[_id1].holder = _holder1;
    //     credential[_id1].credentialHash = _credentialHash1;
    //     credential[_id1].r = _r1;
    //     credential[_id1].e = _e1;
    //     credential[_id1].n1 = _N11;

    //     credential[_id2].id = _id2;
    //     credential[_id2].issuer = _issuer2;
    //     credential[_id2].holder = _holder2;
    //     credential[_id2].credentialHash = _credentialHash2;
    //     credential[_id2].r = _r2;
    //     credential[_id2].e = _e2;
    //     credential[_id2].n1 = _N12;

    //     credential[_id3].id = _id3;
    //     credential[_id3].issuer = _issuer3;
    //     credential[_id3].holder = _holder3;
    //     credential[_id3].credentialHash = _credentialHash3;
    //     credential[_id3].r = _r3;
    //     credential[_id3].e = _e3;
    //     credential[_id3].n1 = _N13;

    //     credential[_id4].id = _id4;
    //     credential[_id4].issuer = _issuer4;
    //     credential[_id4].holder = _holder4;
    //     credential[_id4].credentialHash = _credentialHash4;
    //     credential[_id4].r = _r4;
    //     credential[_id4].e = _e4;
    //     credential[_id4].n1 = _N14;
    // }

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