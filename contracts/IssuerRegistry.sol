pragma solidity >=0.4.20;


//before deploy this contract, you need to import the code of admin account registry.
import "./AdminAccountRegistry.sol";

contract IssuerRegistry {

    mapping (string => address[]) issuer_map; // describes the interaction infromation to other DIDs
    mapping (string => bool) issuer_exist;
    address adminReristryAddr;
    
    function issuerPermission(address _adminReristryAddr) public{
        adminReristryAddr = _adminReristryAddr;
    }

    modifier onlyAdmin(){
        require(AdminAccountRegistry(adminReristryAddr).isAdmin(msg.sender));
        _;
    }
    
    function addIssuer(string memory newIssuer, address _newIssuer) public {
        issuer_map[newIssuer].push(_newIssuer);
        issuer_exist[newIssuer] = true;
    }
    
    function deleteIssuer(string memory _issuer) public onlyAdmin(){
        delete issuer_map[_issuer];
        issuer_exist[_issuer] = false;
    }

    function getPublicKey(string memory _issuer) public view returns (address) {
        // TODO: Not sure why James code is returning the first pub_key
        return issuer_map[_issuer][0];
    }

    function checkIssuer(string memory _issuer) external view returns(bool) {
        return (issuer_exist[_issuer] == true);
    }
}
