import xmlrpc.client
import pickle

from ballot import Ballot

import putil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

config = {}
config['issuer_address'] = 'http://localhost:12345/ISSUER'
config['node_addresses'] = ["http://localhost:30001/PROCESSOR", "http://localhost:30002/PROCESSOR", "http://localhost:30003/PROCESSOR"]


issuer = xmlrpc.client.ServerProxy(config['issuer_address'], allow_none=True)
processor = xmlrpc.client.ServerProxy(config['node_addresses'][0], allow_none=True)
processor2 = xmlrpc.client.ServerProxy("http://localhost:30002/PROCESSOR", allow_none=True)


def print_processor_wallets(issuer, ballots):
	balances = issuer.get_winner()
	print('Balances of voters')
	for ballot in ballots:
		print('--- Voter balance is --- ', balances[ballot.public_hex]['balance'])
		balances[ballot.public_hex] = None
	print('Balances of processors and Issuer')
	for pk in balances:
		if balances[pk] is not None:
			print('--- Issuer/Processor balance is --- ', balances[pk]['balance'])

try:
	print(issuer.start_election())
except:
	print('The Issuer is not up')
	exit()
ballots = []
for i in range(12):
	ballots.append(Ballot(config))
	print("Registering ballot: ", ballots[i].register())

print("---------- About to check balance -----------")
for i in range(12):
	print('My balance is: ', ballots[i].tally())

for node_address in config['node_addresses']:
	issuer.set_nodes(pickle.dumps([node_address]))
	try:
		print_processor_wallets(issuer, ballots)
	except:
		print('Probably a key error')
issuer.set_nodes(pickle.dumps(config['node_addresses']))

print("About to vote for someone")
print("0 Votes for 2: ", ballots[0].vote(ballots[2].public))
print("1 Votes for 2: ", ballots[1].vote(ballots[2].public))
print("0 Votes for 2 again: ", ballots[0].vote(ballots[2].public))
print("3 Votes for 2: ", ballots[3].vote(ballots[2].public))
print("4 Votes for 7: ", ballots[4].vote(ballots[7].public))
print("5 Votes for 7: ", ballots[5].vote(ballots[7].public))
print("6 Votes for 0: ", ballots[6].vote(ballots[0].public))

print(len(ballots[0].get_blockchain()))

for node_address in config['node_addresses']:
	issuer.set_nodes(pickle.dumps([node_address]))
	try:
		print_processor_wallets(issuer, ballots)
	except:
		print('Probably a key error')
issuer.set_nodes(pickle.dumps(config['node_addresses']))