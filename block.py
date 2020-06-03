from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

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
        print("Inside to_hash", self.prev_hash, self.nonce, self.root_hash)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.prev_hash))
        digest.update(bytes.fromhex(self.nonce))
        digest.update(bytes.fromhex(self.root_hash))
        print("About to return")
        return digest.finalize().hex()

class GenesisBlock:
    def __init__(self, issr_pub_key, metadata):
        self.issr_pub_key = issr_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        # metadata as ascii string
        self.metadata = metadata
        self.prev_hash = ""
        self.nonce = ""
        self.root_hash = ""


    def to_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.issr_pub_key))
        digest.update(self.metadata.encode("ascii"))
        return digest.finalize().hex()

class LogicalBlock:
    """holds block data and metadata for processor node"""
    def __init__(self, prev_block_hash, block_id, transactions, nonce):
        # hash of previous block
        self.prev_block_hash = prev_block_hash
        # position in block chain
        self.block_id = block_id
        # merkle tree of transactions attached to block
        if block_id == 0:
            self.tree = None
            self.block = None
            self.transactions = None
            return

        self.tree = merkle.MerkleTree(transactions)

        self.block = self.build_block_data(nonce)
        self.transactions = transactions

    def build_block_data(self, nonce):
        """builds a block from the previously stored data and input nonce (in hex)"""
        return Block(self.prev_block_hash, nonce, self.tree.get_hash())

    def get_transaction(self, i):
        """find the transaction in the merkle tree with index i"""
        return self.tree.get_transaction(i)
