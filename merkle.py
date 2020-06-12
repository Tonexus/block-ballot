"""class definition for each block's merkle tree of transactions"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

class MerkleTree:
    """Merkle tree of transactions"""
    def __init__(self, transacts):
        """Initialize from list of transactions"""
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
            #print("SS ",digest)
            digest.update(bytes.fromhex(self.left.digest))
            digest.update(bytes.fromhex(self.right.digest))
            self.digest = digest.finalize().hex()

        #print("MKT  :  ",self.size," : ", self.digest)

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
            #ans.append(self.digest)
            return ans
        if (i < self.size // 2):
            ans = self.left.get_hash_path(i)
            ans.append([0,self.right.digest])
        else:
            ans = self.right.get_hash_path(i - self.size // 2)
            ans.append([1,self.left.digest])

        return ans    
