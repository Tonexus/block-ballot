"""class definition for each block's merkle tree of transactions"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from collections import Sequence

class MerkleTreeIterator:

    def __init__(self, tree):
        self._tree = tree
        self._index = 0

    def __iter__(self):
        return self

    def __next__(self):
        print('next is called')
        self._index += 1
        try:
            return self._tree.get_transaction(self._index - 1)
        except IndexError:
            self._index = 0
            raise StopIteration

class MerkleTree(Sequence):
    """Merkle tree of transactions"""
    def __init__(self, transacts):
        """Initialize from list of transactions"""
        self.idx = 0
        self.size = len(transacts)
        if self.size == 0:
            raise ValueError("No empty tree")
        if self.size == 1:
            # if size == 1, is a leaf node, so just hash the transaction
            self.transact_data = transacts[0]
            self.left = None
            self.right = None
            self.digest = self.transact_data.to_hash()
        else:
            # otherwise, split transactions in half and form subtrees
            # hash is combined from left and right
            self.transact_data = None
            self.left = MerkleTree(transacts[:self.size//2])
            self.right = MerkleTree(transacts[self.size//2:])
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(bytes.fromhex(self.left.digest))
            digest.update(bytes.fromhex(self.right.digest))
            self.digest = digest.finalize().hex()

    # def __iter__(self):
    #     return MerkleTreeIterator(self)

    def __getitem__(self, index):
        return self.get_transaction(index)

    def __len__(self):
        return self.size

    def to_string(self):
        ret = self.__dict__
        if self.left is not None:
            ret['left'] = self.left.to_string()
        if self.right is not None:
            ret['right'] = self.right.to_string()
        if self.transact_data is not None:
            ret['transact_data'] = self.transact_data.to_string()
        return ret

    def get_hash(self):
        """get the hash at the current level"""
        return self.digest

    def get_transaction(self, i):
        """get a transaction base don its index in the original ist of transactions"""
        if i < 0 or i >= self.size:
            raise IndexError("Not in range of values")
        if self.size == 1:
            return self.transact_data
        if i < self.size // 2:
            return self.left.get_transaction(i)
        return self.right.get_transaction(i - self.size // 2)

    def get_hash_path(self, i):
        ans = []
        if i < 0 or i >= self.size:
            return ans
        if(self.size == 1):
            return ans
        if (i < self.size // 2):
            ans = self.left.get_hash_path(i)
            ans.append(self.right.digest)
        else:
            ans = self.right.get_hash_path(i - self.size // 2)
            ans.append(self.left.digest)

        return ans    
