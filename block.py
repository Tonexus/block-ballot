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
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.prev_hash))
        digest.update(bytes.fromhex(self.nonce))
        digest.update(bytes.fromhex(self.root_hash))
        return digest.finalize().hex()

    def to_string(self):
        return self.__dict__

class GenesisBlock:
    def __init__(self, issr_pub_key, metadata, num_zeros, block_size):
        self.issr_pub_key = issr_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        # metadata as ascii string
        self.metadata = metadata
        self.prev_hash = ""
        self.nonce = ""
        self.root_hash = ""
        self.num_zeros = num_zeros
        self.block_size = block_size

    def to_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.issr_pub_key))
        digest.update(self.metadata.encode("ascii"))
        digest.update(str(self.num_zeros).encode("ascii"))
        digest.update(str(self.block_size).encode("ascii"))
        return digest.finalize().hex()

    def to_string(self):
        return self.__dict__

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
        print(type(transactions))
        self.tree = merkle.MerkleTree(transactions)
        self.block = self.build_block_data(nonce)
        # self.transactions = transactions

    def build_block_data(self, nonce):
        """builds a block from the previously stored data and input nonce (in hex)"""
        return Block(self.prev_block_hash, nonce, self.tree.get_hash())

    def get_transaction(self, i):
        """find the transaction in the merkle tree with index i"""
        return self.tree.get_transaction(i)

    def to_string(self):
        ret = self.__dict__
        ret['block_hash'] = self.block.to_hash()
        ret['block'] = self.block.to_string()
        if self.tree is not None:
            ret['tree'] = self.tree.to_string()
        if self.transactions is not None:
            transaction_str = []
            for transaction in self.transactions:
                transaction_str.append(transaction.to_string())
            ret['transactions'] = transaction_str
        return ret
