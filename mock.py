import xmlrpc.client
import pickle
import threading
from ballot import Ballot

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

NUM_VOTERS = 10
config = {}
config['issuer_address'] = 'http://localhost:12345/ISSUER'
# config['node_addresses'] = ["http://localhost:30001/PROCESSOR", "http://localhost:30002/PROCESSOR", "http://localhost:30003/PROCESSOR"]
config['node_addresses'] = ["http://localhost:30001/PROCESSOR"]


issuer = xmlrpc.client.ServerProxy(config['issuer_address'])
processor = xmlrpc.client.ServerProxy(config['node_addresses'][0])

print('Election has started: ', issuer.start_election())

Ralph = Ballot(config)
David = Ballot(config)
Billy = Ballot(config)
print('David registering to Vote: ', David.register())
print('Ralph registering to Vote: ', Ralph.register())
voters = []
voter_threads = []
# multi threaded registration
for i in range(NUM_VOTERS):
	voters.append(Ballot(config))
	voter_threads.append(threading.Thread(target=voters[i].register, args=()))
	voter_threads[i].start()

# wait for all the voting to be done
for i in range(NUM_VOTERS):
	voter_threads[i].join()
num_not_registered = 0
for i in range(NUM_VOTERS):
	if str(voters[i].tally()) != '1':
		num_not_registered += 1
		print('%s has not fully registered' % i)
print('%s users of %s not registered' % (num_not_registered, NUM_VOTERS))





print(issuer.start_election())


b = Ballot(config)
# print(b.public.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ).hex())
print(b.register())
# print(b.register())
b1 = Ballot(config)
print(b1.register())
# bc = processor.get_blockchain()
# bc = pickle.loads(bc.data)
# print(len(bc[1].transactions))

ballots = []
for i in range(4):
	ballots.append(Ballot(config))
	print("Registering ballot: ", ballots[i].register())
print("---------- About to check balance -----------")
print("My Balance is: ", b.tally())
print("My Balance is: ", b1.tally())
print("My Balance is: ", ballots[0].tally())
print("My Balance is: ", ballots[1].tally())
print("My Balance is: ", ballots[2].tally())
print("My Balance is: ", ballots[3].tally())
# print("The blockchain is valid?: ", b.get_blockchain())

print("About to vote for someone")
print("Vote is: ", ballots[0].vote(ballots[2].public))
print("Vote is: ", ballots[1].vote(ballots[2].public))
print("Vote is: ", ballots[0].vote(ballots[2].public))
print("Vote is: ", ballots[3].vote(ballots[2].public))
print("Vote is: ", b.vote(ballots[2].public))
# print("Vote is: ", ballots[0].vote(ballots[3].public))
# print("Retry the vote is: ", ballots[2].vote(ballots[1].public))

# print("Winner results: ", issuer.get_winner())
balances = issuer.get_winner()
for pub_key in balances:
	print(pub_key[50:60], ' --- balance is --- ', balances[pub_key]['balance'])


print("SPV: ", ballots[3].SPV())
print("!!:", ballots[3].get_blockchain()[-1].block.to_hash())