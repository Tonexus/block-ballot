import xmlrpc.client
from ballot import Ballot

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

config = {}
config['issuer_address'] = 'http://localhost:12345/ISSUER'
# config['node_addresses'] = ["http://localhost:30001/PROCESSOR", "http://localhost:30002/PROCESSOR", "http://localhost:30003/PROCESSOR"]
config['node_addresses'] = ["http://localhost:30001/PROCESSOR"]


i = xmlrpc.client.ServerProxy(config['issuer_address'])

print(i.start_election())

b = Ballot(config)
# print(b.public.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).hex())
print(b.register())
print(b.register())
b1 = Ballot(config)
print(b1.register())


ballots = []
for i in range(10):
	ballots.append(Ballot(config))
	print("Registering ballot: ", ballots[i].register())

