import xmlrpc.client
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from random import sample 
import time
from transaction import LogicalTransaction

TIMEOUT = 1
MAX_TRIES = 10

class Wallet:
	""" Wallet class interacts with a blockchain node to write and read data

	Attributes
	----------
	public : public_key
		The public key for the user of this wallet
	private : private_key
		The private key associated with the public key
	node_addresses : str[]
		List of ip address:port of Processor nodes
	nodes : xmlrpc.client[]
		List of rpc clients associated with the processor nodes 

	Methods
	-------
	make_transaction(public_key)
		Sends a coin to the public_key using the nodes in the blockchain
	check_balance(public_key)
		Check the balance of coins in the public key in the blockchain

	"""

	def __init__(self, node_addresses):
		""" Makes the public private key pair and sets up the node rpc clients
		Parameters
		----------
		node_addresses : str[]
			List of ip:port for the blockchain Processor nodes

		"""
		self.private = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
			backend=default_backend()
			)
		self.public = self.private.public_key()
		self.node_addresses = node_addresses
		self.nodes = []
		for node_address in node_addresses:
			self.nodes.append(xmlrpc.client.ServerProxy(node_address))

	def pick_nodes(self):
		""" Function to pick subset of nodes to send transactions to
		Right not picking random subset of the nodes"""
		if self.nodes == []:
			return []
		return sample(self.nodes,1)


	def make_transaction(self, public_key):
		""" send 1 coin from self to public key in the chain

		Parameters
		----------
		public_key : public_key
			The public key the user wants to send 1 coin to
		"""
		# Need to set the source transaction first
		# Need to pick some nodes to send the transaction to
		nodes = self.pick_nodes()
		print("Inside make transaction")
		# Make the transaction from self to the other public address
		# store source transaction info inside the wallet
		# for the Issuer is special issuer transaction
		# For the regular voter is the results of registering to vote
		for tries in range(MAX_TRIES):
			transaction = LogicalTransaction(self.source_transaction_id, public_key, self.source_transaction_data, self.private)
			for node in nodes:
				ret = node.add_transaction(transaction, 0)
				print(ret)
				if ret == False:
					return False
			print("Got to the timeout")
			time.sleep(TIMEOUT)
			longest_bc = []
			for node in nodes:
				bc = node.get_blockchain()
				if len(bc) > len(longest_bc):
					longest_bc = bc
			# find new transaction in the blockchain
			print(len(longest_bc))
			for block in reversed(longest_bc[1:-1]):
				# loop through transactions in the block?
				print(block)
				block = LogicalBlock(None, None, None, None, block)
				for transaction in block.transactions:
					if transaction.dst_pub_key == public_key: # check src_transaction.public_key?
						return transaction.id, transaction.source_transaction_data
			# now repeat above steps
		return None, None




	def check_balance(self, public_key):
		""" Retrieves the balance in a public key on the chain

		Parameters
		----------
		punlic_key : public_key
			The address to check the balance of
		"""
		# traverse all the transactions


class Ballot(Wallet):
	
	def __init__(self, config):
		""" Initilizes based on the config

		Parameters
		---------
		config.node_addresses : str[]
			List of node addresses for the node processors
		config.issuer_address : str
			Address of the Issuer
		"""
		super().__init__(config['node_addresses'])
		self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'])
		self.issuer_address = config['issuer_address']
		self.registered = False
		self.source_transaction_id = -1
		self.source_transaction_data = ""

	def register(self):
		""" Register to vote by sending rpc call to Issuer
		Returns the RPC call's return value
		"""
		public_key_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
		(self.source_transaction_id, self.source_transaction_data) = self.issuer.register(public_key_hex)
		if self.source_transaction_id == None or self.source_transaction_data == None:
			return False
		self.registered = True
		return True

	def vote(self, public_key):
		""" Vote for the person in the public addr 

		Parameters
		----------
		public_key : public_key
			The public key of the person the user wants to vote for

		"""
		if self.registered:
			s_id, s_data = self.make_transaction(public_key)
			if s_id == None or s_data == None:
				return False
			else:
				self.source_transaction_id = s_id
				self.source_transaction_data = s_data
				return True
		return False

	def tally(self, public_keys):
		""" Tally the votes for the public addresses in public key"""
		balances = {}
		for key in public_keys:
			balances[key] = self.check_balance(key)
		return balances

	def verify_vote(self):
		""" Verify my vote is in the blockchain """

class Issuer(Wallet):
	"""
	The Issuer will be an RPC server that the government entity will interact with directly. 
	The Ballots also will directly register themselves to vote tothe Issuer.
	The Issuer will also start up the RPC servers acting as the Processor nodes

	Attributes
	----------
	voters : str[]
		List of public keys that the Issuer has registered.
	pow_config : dict
		Dictionary of proof of work configuration for the election

	Methods
	-------
	start_election
		Starts up the election by publishing the genesis block to the Processor nodes

	register
		Function that takes a public address and gives it a coin

	"""

	def __init__(self, config):
		super().__init__(config['node_addresses'])
		self.voters = []
		self.pow_config = config['pow_config']
		self.source_transaction_id = (0, 0)
		self.source_transaction_data = None

	def start_election(self):
		""" Starts the election on all the nodes with the given POW config"""
		# Maybe in here we need to start up the nodes just on our local machine
		# Actually from here we should just publish the genesis block to all the nodes which signals to start accepting transactions
		public_key_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
		for node in self.nodes:
			node.set_genesis(public_key_hex)


	def register(self, public_key):
		""" Gives the public key a coin on the chain
		Public key comes in as hex form
		"""
		print("Inside here, ", public_key)
		pk_bytes = bytes.fromhex(public_key)
		public_key = load_pem_public_key(pk_bytes, backend=default_backend())
		print(public_key)
		self.voters.append(public_key)
		return self.make_transaction(public_key)

	def list_registered_voters(self):
		""" look up all public key addresses on the block chain"""
		return self.voters 	# Should ideal look this up in the chain

	def tally(self, public_keys):
		""" Tally the votes for specific users"""
		balances = {}
		for key in public_keys:
			balances[key] = self.check_balance(key)
		return balances

	def get_pkey(self, src):
		pass

