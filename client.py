import xmlrpc.client
import pickle

from ballot import Ballot

import putil
import random

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
NUM_VOTERS = issuer.get_transactions_per_block()*5
try:
	print('Starting the election by sending the issuers public key:', issuer.start_election())
except:
	print('The Issuer is not up')
	exit()
print('The number of transactions per block is ', issuer.get_transactions_per_block(), '. Thus transactions will be verified after every ', issuer.get_transactions_per_block(), ' transsactions are posted.')
print('First we register ', str(NUM_VOTERS), ' Voters where each registration is a separate transaction.')
ballots = []
for i in range(NUM_VOTERS):
	ballots.append(Ballot(config))
	print("Registering ballot: ", ballots[i].register())
print("Now for each registered ballot we check the wallet balance to verify that they are actually registered. Each should be 1.")
for i in range(NUM_VOTERS):
	print('Voter', str(i),' balance is: ', ballots[i].tally())
# for node_address in config['node_addresses']:
# 	issuer.set_nodes(pickle.dumps([node_address]))
# 	try:
# 		print_processor_wallets(issuer, ballots)
# 	except:
# 		print('Probably a key error')
# 	break
# issuer.set_nodes(pickle.dumps(config['node_addresses']))

print("About to vote for user 0 or 1 at random for all voters")
for i in range(NUM_VOTERS):
	voter = i
	candidate = random.choice(range(0, 2))
	print(str(i), ' votes for ', str(candidate), ':', ballots[voter].vote(ballots[candidate].public))
# print("0 Votes for 2: ", ballots[0].vote(ballots[2].public))
# print("1 Votes for 2: ", ballots[1].vote(ballots[2].public))
# for i in range(4):
# 	ballots.append(Ballot(config))
# 	print("Registering ballot: ", ballots[-1].register())
# print("0 Votes for 2 again: ", ballots[0].vote(ballots[2].public))
# print("3 Votes for 2: ", ballots[3].vote(ballots[2].public))
# print("4 Votes for 7: ", ballots[4].vote(ballots[7].public))
# print("5 Votes for 7: ", ballots[5].vote(ballots[7].public))
# print("6 Votes for 0: ", ballots[6].vote(ballots[0].public))

# for i in range(20):
# 	ballots.append(Ballot(config))
# 	print("Registering ballot: ", ballots[-1].register())

for node_address in config['node_addresses']:
	issuer.set_nodes(pickle.dumps([node_address]))
	try:
		print_processor_wallets(issuer, ballots)
	except:
		print('Probably a key error')
	break
print('Note the balances all total up to zero as any negative balance by the issuer was either a registration or the reward coins.')
issuer.set_nodes(pickle.dumps(config['node_addresses']))
# print("-------------------  DONE ------------------")
# print("-------------------  DONE ------------------")
# print("-------------------  DONE ------------------")
# print("-------------------  DONE ------------------")
# print("-------------------  DONE ------------------")





# for block in ballots[0].get_blockchain()[1:]:
# 	print('------ begin block-------')
# 	print('------- end block -------')
# 	print(len(block.tree))
# 	for transaction in block.tree:
# 		print(transaction.to_string())
print('Writing to blockchain.json: Note there may exist a file already so append a line with "-----" before this blockchain')
with open('blockchain.json', 'a') as file:
	file.write('\n-------\n')
	chain = list(map(lambda x : x.to_string(), ballots[0].get_blockchain()))
	for block in chain:
		file.write(str(block))







