pragma solidity ^0.4.20;

contract VoteRegistry {

    struct CredentialVoteInfo
    {
        string id;
        bool votingRequired;
        int numRequiredVotes;
        int currentVotesReceived;
        string[] voters;
    }

    mapping(string => CredentialVoteInfo) private credentialVotes;

    function addCredential(
        string _id,
        bool _votingRequired,
        int _numRequiredVotes
    ) public {
        credentialVotes[_id].id = _id;
        credentialVotes[_id].votingRequired = _votingRequired;
        credentialVotes[_id].numRequiredVotes = _numRequiredVotes;
        credentialVotes[_id].currentVotesReceived = 0;
    }

    function vote(
        string _id,
        string _voter
    ) public {

        bool encountered = false;

        for (uint256 i = 0; i < credentialVotes[_id].voters.length; ++i) { 
            if (keccak256(abi.encodePacked(credentialVotes[_id].voters[i])) == keccak256(abi.encodePacked(_voter)))
            {
                encountered = true;
            }
        }

        if (encountered == false)
        {
            credentialVotes[_id].currentVotesReceived++;
            credentialVotes[_id].voters.push(_voter);
        }
    }

    function isVotingCompleted(string _id) public view returns (bool hasCompleted)
    {
        if (credentialVotes[_id].votingRequired == false)
        {
            return true;
        }

        if (credentialVotes[_id].numRequiredVotes == credentialVotes[_id].currentVotesReceived)
        {
            return true;
        }

        return false;
    }

    function getVotingInfo(string _id) public view 
    returns (
        string __id,
        bool __votingRequired,
        int __numRequiredVotes,
        int __currentVotesReceived
    )
    {
        return (
            credentialVotes[_id].id,
            credentialVotes[_id].votingRequired,
            credentialVotes[_id].numRequiredVotes,
            credentialVotes[_id].currentVotesReceived
        );
    }
}