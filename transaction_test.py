"""tests for transactions"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import transaction

def test_verify():
    """verifies the contents of the transactions"""
    prv_key_1 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    prv_key_2 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    prv_key_3 = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # transaction 1 send from key 1 to key 2, no prior transaction
    tx_1 = transaction.Transaction(prv_key_2.public_key(), None, prv_key_1)
    # verify key 1 signature
    assert tx_1.verify(prv_key_1.public_key())
    # verify that not key 2 signature
    assert not tx_1.verify(prv_key_2.public_key())
    # transaction 1 send from key 2 to key 3, referencing first transaction
    tx_2 = transaction.Transaction(prv_key_3.public_key(), tx_1, prv_key_2)
    # verify key 2 signature
    assert tx_2.verify(prv_key_2.public_key())
    # verify that not key 3 signature
    assert not tx_2.verify(prv_key_3.public_key())
