pragma solidity >=0.4.20;


//currently there is only one admin by default, you can modify the code to achieve multiple admins.
//the update functionalities are not included in this contract for now, please refer to multiple authority smart contract for them.

contract AdminAccountRegistry{
    
    address admin;
    address _temAdmin;
    
    bool delegated;
    uint total;
    address[] delegates;
    
    //to judge if there is already a request, prevent double (or multi-) requesting
    bool agreeing;
    
    uint agreeThreshold;
    mapping(address => bool) agreeState;  
     
    uint updateThreshold;
    
    function adminAccountRegistry() public{
        admin = msg.sender;
    }

    modifier onlyAdmin(){
        require(msg.sender == admin);
        _;
    }
    
    function changeAdmin(address _admin) public onlyAdmin(){
        admin = _admin;
    }
    
    function isAdmin(address _admin) public view returns(bool){
        if (admin == _admin)
            return true;
        else
            return false;
    }
    
    function delegateSetup(uint aThreshold, uint uThreshold, address[] memory _delegates) public{
        if(delegated) 
            return; 
        total = _delegates.length; 
        agreeThreshold = aThreshold; 
        updateThreshold = uThreshold; 
        delegates = _delegates; 
        agreeing = false; 
         
        for(uint i = 0; i < total; i++){ 
            agreeState[delegates[i]] = false;
        } 
        
        delegated = true;
    }
    
    function recoverAdminRequest() public{
        require(agreeing == false);
        _temAdmin = msg.sender;
        agreeing = true;
    }
    
    function vote() public{
        agreeState[msg.sender] = true;
    }
    
    function agreeResult() internal view returns (bool signatureResult){
    //to check the number of valid authorisation
        uint k = 0; 
        for(uint i = 0; i < total; i++){ 
            if(agreeState[delegates[i]] == true) 
               k++; 
        } 
        if(k >= agreeThreshold){
            return true;
        }
        else 
            return false; 
    }
    
    function recoverAdmin() public{
        if(agreeResult()){ 
            admin = _temAdmin;
            delete _temAdmin;
            agreeing = false;
            for(uint i = 0; i < total; i++)
                agreeState[delegates[i]] = false;
        }
    }
}
