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


issuer = xmlrpc.client.ServerProxy(config['issuer_address'])

print(issuer.start_election())


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
for i in range(3):
	ballots.append(Ballot(config))
	print("Registering ballot: ", ballots[i].register())

print("About to vote for someone")
print("Vote is: ", ballots[0].vote(ballots[1].public))
print("Retry the vote is: ", ballots[0].vote(ballots[1].public))
print("---------- About to check balance -----------")
print("My Balance is: ", ballots[0].tally())
print("My Balance is: ", ballots[1].tally())
print("My Balance is: ", ballots[2].tally())
# print("Winner results: ", issuer.get_winner())
balances = issuer.get_winner()
for pub_key in balances:
	print(pub_key[50:60], ' --- balance is --- ', balances[pub_key]['balance'])
