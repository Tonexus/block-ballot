from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

import merkle

class Block:
    """data corresponding to a single block"""
    def __init__(self, prev_hash, nonce, root_hash):
        # hash of previous block
        self.prev_hash = prev_hash
        # nonce to do proof of work
        self.nonce = nonce
        # root hash of merkle tree
        self.root_hash = root_hash

    def to_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.prev_hash))
        digest.update(bytes.fromhex(self.nonce))
        digest.update(bytes.fromhex(self.root_hash))
        return digest.finalize().hex()

class GenesisBlock:
    pass

class LogicalBlock:
    """block data and metadata for processor node"""
    def __init__(self, prev_block_hash, block_id, transactions):
        # hash of previous block
        self.prev_block_hash = prev_block_hash
        # position in block chain
        self.block_id = block_id
        # merkle tree of transactions attached to block
        self.tree = merkle.MerkleTree(transactions) # todo implement this

    def build_block_data(self, nonce):
        return Block(self.prev_block_hash, nonce, self.tree.get_root_hash())

    def get_transaction(self, i):
        # look through merkle tree for transaction
        return self.tree.get(i)
