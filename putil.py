"""Utility functions for processors"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from merkle import MerkleTree
from block import GenesisBlock

class YouAreBad(Exception):
    """Exception to throw when you are bad"""

def check_hash(hash, blockchain):
        #pre 0
        if len(blockchain) == 0:
            return False # ?
        num_zeros = int(blockchain[0].block.num_zeros)
        if hash[-num_zeros:] == '0'*num_zeros:
            return True
        return False

def valid_transaction(transaction, blockchain, coins_from_issuer, block_transactions):
    """
    Checks if a new transaction is valid given the metadata,
    prior transactions in the block, and the blockchain
    """
    # Should we check if the blockchain is valid first?
    # get source and destination of transaction
    (block_id, transaction_id) = transaction.src_transact_id
    if block_id == 0:
        if len(blockchain) == 0:
            # invalid blockchain
            return False
        src_str = blockchain[0].block.issr_pub_key
    else:
        try:
            src_str = blockchain[block_id].get_transaction(transaction_id).dst_pub_key
        except:
            # Some error gettting the transaction either wrong block_id or wrong transaction_id
            return False
    try:
        src_key = load_pem_public_key(bytes.fromhex(src_str), backend=default_backend())
    except:
        # Some error making the key
        return False
    dst_str = transaction.dst_pub_key

    # check if transaction signature is valid
    if not transaction.verify(src_key):
        return False

    # check if transaction is a registration from the issuer or a vote
    if src_str == blockchain[0].block.issr_pub_key:
        # issuer issuing new vote
        if dst_str in coins_from_issuer:
            # can never double register
            # TODO maybe allow? depends on election type
            return False

        # make sure no double register within same block
        for transaction_bc in block_transactions:
            # TODO shouldn't just check dest, need to also check if source
            # is issuer, otherwise prevents A registering and B voting for A
            # in the same block
            if transaction_bc.dst_pub_key == dst_str:
                return False
        return True

    # voter sending vote to candidate
    if src_str not in coins_from_issuer:
        # never got any coins, so cannot vote
        return False
    if coins_from_issuer[src_str] == 0:
        # already spent coin, so cannot vote
        return False

    # make sure no double spend within one block
    for transaction_bc in block_transactions:
        if transaction_bc.src_transact_id == (block_id, transaction_id):
            return False

    return True

def valid_block(newblock, blockchain, coins_from_issuer):
    """Checks if a new block is valid given the previous blocks and transaction metadata"""
    
    if blockchain is None:
        return False

    if len(blockchain) == 0:
        if isinstance(newblock.block, GenesisBlock): # ?
            print("The first block of an empty blockchain is a GenesisBlock")
            return True
        print("The first block is not a genesis block", type(newblock), type(newblock.block))
        return False

    # check if hash matches previous block
    if newblock.prev_block_hash != blockchain[-1].block.to_hash():
        return False

    # check number of transactions
    if len(newblock.tree) != blockchain[0].block.block_size:
        return False

    # check each transaction, except the mining transaction
    block_transactions = newblock.tree[0:1]
    for transaction in newblock.tree[1:]:
        if not valid_transaction(transaction, blockchain, coins_from_issuer, block_transactions):
            return False
        block_transactions.append(transaction)

    # check if transaction merkle tree root hash matches
    if MerkleTree(newblock.tree).get_hash() != newblock.block.root_hash:
        return False

    # Check if number of zeros in the block.tohash is the right amount
    if not check_hash(newblock.block.to_hash(), blockchain):
        return False

    return True

def valid_blockchain(blockchain):
    """
    Returns (None, None) if invalid, otherwise returns metadata tuple
    (coins_from_issuer, coins_from_voter)
    """

    # initialize metadata
    coins_from_issuer = {}
    coins_from_voter = {}
    if len(blockchain) == 0:
        return None, None
    if not isinstance(blockchain[0].block, GenesisBlock):
        return None, None
    new_blockchain = [blockchain[0]]
    # check blockchain block by block
    for logic_block in blockchain[1:]:
        # check if each block is valid for appending, given the metadata
        if valid_block(logic_block, new_blockchain, coins_from_issuer):
            # add block and update metadata
            new_blockchain.append(logic_block)
            update_metadata(logic_block, new_blockchain, coins_from_issuer, coins_from_voter)
        else:
            return None, None

    return coins_from_issuer, coins_from_voter

def update_metadata(new_block, blockchain, coins_from_issuer, coins_from_voter):
    """
    In-place updates the metadata dictionaries of coins_from_issuer and coins_from_voter
    based on a new block. This function does no real checking itself, as such checking
    should be done beforehand, but raises errors if something bad happens.
    """

    # update over each transaction in the block except the first mining transaction
    for transaction in new_block.tree[1:]:
        # get source and destination of transaction
        (block_id, transaction_id) = transaction.src_transact_id
        if block_id == 0:
            # if source block is 0, should be issuer issuing new vote
            src_str = blockchain[0].block.issr_pub_key
        else:
            # otherwise, must be a vote
            src_str = blockchain[block_id].get_transaction(transaction_id).dst_pub_key
        dst_str = transaction.dst_pub_key

        # update metadata for source and destination
        if src_str == blockchain[0].block.issr_pub_key:
            # issuer issuing a new vote
            coins_from_issuer[dst_str] = 1
        else:
            # voter sending vote to candidate
            if src_str not in coins_from_issuer:
                raise YouAreBad("The coin source is not in metadata. Did you validate the transaction?")
            if coins_from_issuer[src_str] == 0:
                raise YouAreBad("The coin source has no coins. Did you validate the transaction?")
            if dst_str not in coins_from_voter:
                coins_from_voter[dst_str] = 0
            coins_from_issuer[src_str] -= 1
            coins_from_voter[dst_str] += 1
