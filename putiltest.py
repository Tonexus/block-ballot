import unittest
import putil
from ballot import Issuer
from process import ProcessNode
from transaction import Transaction
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class TestPutilValidTransactions(unittest.TestCase):

    def setUp(self):
        config = {}
        config['node_addresses'] = []
        config['num_zeros'] = 2
        config['transactions_per_block'] = 2
        self.issuer = Issuer(config)
        self.processor = ProcessNode([], [], 0, '', {}, {'issuer_address': 'localhost:123'})
        self.processor.set_genesis(self.issuer.public_hex, self.issuer.num_zeros, self.issuer.transactions_per_block);
        self.private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
        self.public = self.private.public_key()
        self.public_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()

# def valid_transaction(transaction, blockchain, coins_from_issuer, block_transactions):

    def test_registration_valid_empty_blockchain(self):
        transaction = Transaction((0,0), self.public, None, self.issuer.private)
        self.assertTrue(putil.valid_transaction(transaction, self.processor.blockchain, {}, []))

    def test_registration_self_signed_empty_blockchain(self):
        transaction = Transaction((0,0), self.public, None, self.private)
        self.assertFalse(putil.valid_transaction(transaction, self.processor.blockchain, {}, []))

    def test_registration_other_signed_empty_blockchain(self):
        new_private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
        transaction = Transaction((0,0), self.public, None, new_private)
        self.assertFalse(putil.valid_transaction(transaction, self.processor.blockchain, {}, []))


    def test_registrationtwice_valid_empty_blockchain(self):
        transaction0 = Transaction((0,0), self.public, None, self.issuer.private)
        self.assertTrue(putil.valid_transaction(transaction0, self.processor.blockchain, {}, []))
        transaction1 = Transaction((0,0), self.public, None, self.private)
        self.assertFalse(putil.valid_transaction(transaction1, self.processor.blockchain, {}, [transaction0]))

    # def test_isupper(self):
    #     self.assertTrue('FOO'.isupper())
    #     self.assertFalse('Foo'.isupper())

    # def test_split(self):
    #     s = 'hello world'
    #     self.assertEqual(s.split(), ['hello', 'world'])
    #     # check that s.split fails when the separator is not a string
    #     with self.assertRaises(TypeError):
    #         s.split(2)

if __name__ == '__main__':
    unittest.main()