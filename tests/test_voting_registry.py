from brownie import accounts, VoteRegistry

def test_add_get_credential_vote():
    vote_contract = VoteRegistry.deploy({'from': accounts[0]})
    vote_contract.addCredential("id", False, 0, {'from': accounts[0]})

    vote_id, vote_required, num_votes, cur_votes = vote_contract.getVotingInfo("id")

    assert(vote_id == "id")
    assert(vote_required == False)
    assert(num_votes == 0)
    assert(cur_votes == 0)

def test_vote():
    vote_contract = VoteRegistry.deploy({'from': accounts[0]})
    vote_contract.addCredential("id", True, 2, {'from': accounts[0]})
    vote_contract.vote("id", {'from': accounts[0]})
    
    vote_id, vote_required, num_votes, cur_votes = vote_contract.getVotingInfo("id", {'from': accounts[0]})
    assert(vote_id == "id")
    assert(vote_required)
    assert(num_votes == 2)
    assert(cur_votes == 1)

def test_is_voting_complete():
    vote_contract = VoteRegistry.deploy({'from': accounts[0]})
    vote_contract.addCredential("id", True, 2, {'from': accounts[0]})
    vote_contract.vote("id", {'from': accounts[0]})
    vote_contract.vote("id", {'from': accounts[0]})
    
    vote_id, vote_required, num_votes, cur_votes = vote_contract.getVotingInfo("id", {'from': accounts[0]})
    assert(vote_id == "id")
    assert(vote_required)
    assert(num_votes == 2)
    assert(cur_votes == 2)
    assert(vote_contract.isVotingCompleted("id", {'from': accounts[0]}))
