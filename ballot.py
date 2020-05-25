import xmlrpc.client

# s = xmlrpc.client.ServerProxy('http://localhost:12346/ISSUER')


# Defines the Ballot Class

class Wallet:

	def __init__(self, node_addresses):
		""" Makes the public private key pair"""
		self.public = None
		self.private = None
		self.node_addresses = node_addresses
		self.nodes = []
		for node_address in node_addresses:
			self.nodes.append(xmlrpc.client.ServerProxy(node_address))


	def make_transaction(self, public_key):
		""" send 1 coin from self to public key in the chain"""

	def check_balance(self, public_key):
		""" return the balance in a public key on the chain"""

class Ballot(Wallet):
	
	def __init__(self, config):
		""" Do some initialization here"""
		super().__init__(config['node_addresses'])
		self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'])
		self.issuer_address = config['issuer_address']

	def register(self):
		""" Register to vote by sending rpc call to Issuer"""
		return self.issuer.register(self.public)

	def vote(self, public_key):
		""" Vote for the person in the public addr """

	def tally(self, public_keys):
		""" Tally the votes for the public addresses in publicAddrs"""

	def verify_vote(self):
		""" Verify my vote is in the blockchain """

class Issuer(Wallet):

	def __init__(self, config):
		super().__init__(config['node_addresses'])
		self.voters = []
		self.pow_config = config['pow_config']

	def register(self, public_key):
		""" give the public key a coin on the chain"""
		self.voters.append(public_key)
		return True
		# look up in the chain probably

	def list_registered_voters(self):
		""" look up all public key addresses on the block chain"""
		return self.voters

	def tally(self, public_keys):
		""" Tally the votes for specific users"""

	def get_pkey(self, src):
		pass

