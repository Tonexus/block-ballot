import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class Block:
    def __init__(self, prev_hash, nonce, root_hash):
        # hash of previous block
        self.prev_hash = prev_hash
        # nonce to do proof of work
        self.nonce = nonce
        # root hash of merkle tree
        self.root_hash = root_hash

    def to_digest(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.prev_hash))
        digest.update(bytes.fromhex(self.nonce))
        digest.update(bytes.fromhex(self.root_hash))
        return digest.finalize().hex()

class GenesisBlock:
    pass

class LogicalBlock:
    def __init__(self, block, tree=None):
        # actual block
        self.block = block
        # merkle tree of transactions attached to block
        self.tree = tree

    def get_transaction(self, i):
        # look through merkle tree for transaction
        pass
