import json

class Block:
    def __init__(self, prev_hash, nonce, root_hash):
        # hash of previous block
        self.prev_hash = prev_hash
        # nonce to do proof of work
        self.nonce = nonce
        # root hash of merkle tree
        self.root_hash = root_hash
    
    def to_string(self):
        self_dict = {
            "prev_hash": self.prev_hash,
            "nonce": self.nonce,
            "root_hash": self.root_hash
        }
        return json.dumps(self_dict)

class GenesisBlock:
    pass

class LogicalBlock:
    def __init__(self, block, tree=None)
        # actual block
        self.block = block
        # merkle tree of transactions attached to block
        self.tree = tree
    
    def get_transaction(self, i):
        # look through merkle tree for transaction
        pass