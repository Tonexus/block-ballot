import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class Transaction:
    def __init__(self, dst_addr, src_transact_data, prv_key):
        self.dst_addr = dst_addr
        # calculate digest
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.dst_addr))
        digest.update(bytes.fromhex(src_transact_data.dst_addr))
        digest.update(bytes.fromhex(src_transact_data.digest))
        digest.update(bytes.fromhex(src_transact_data.signature))
        self.digest = digest.finalize().hex()
        # sign digest
        self.signature = prv_key.sign(
            bytes.fromhex(self.digest),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()

class LogicalTransaction:
    def __init__(self, dst_addr, src_transact, prv_key):
        self.dst_addr = dst_addr
        # id of source block of transaction
        self.src_transact = src_transact
        self.transact_data = Transaction(self.dst_addr, src_transact.transact_data, prv_key)
