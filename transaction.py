from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class Transaction:
    """data corresponding to a single transaction"""
    def __init__(self, dst_pub_key, src_transact_data, src_prv_key):
        # stored as ASCII PEM data in bytes
        self.dst_pub_key = dst_pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        # calculate digest (named so because hash is python keyword)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.dst_pub_key))
        if src_transact_data is not None:
            digest.update(bytes.fromhex(src_transact_data.to_hash()))
        self.digest = digest.finalize().hex()
        # sign digest
        self.signature = src_prv_key.sign(
            bytes.fromhex(self.digest),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        ).hex()

    def to_hash(self):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(self.dst_pub_key))
        digest.update(bytes.fromhex(self.digest))
        digest.update(bytes.fromhex(self.signature))
        return digest.finalize().hex()

    def verify(self, src_pub_key):
        """verifies that the signature matches the transaction, returns true if valid"""
        try:
            src_pub_key.verify(
                bytes.fromhex(self.signature),
                bytes.fromhex(self.digest),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class LogicalTransaction:
    """transaction data and metadata to pass to processor node via RPC"""
    def __init__(self, src_transact_id, dst_pub_key, src_transact_data, src_prv_key):
        # tuple of source block id and transaction id within the block
        self.src_transact_id = src_transact_id
        self.transact_data = Transaction(dst_pub_key, src_transact_data, src_prv_key)

    def verify(self, src_pub_key):
        """verifies that the signature matches the transaction, returns true if valid"""
        return self.transact_data.verify(src_pub_key)
