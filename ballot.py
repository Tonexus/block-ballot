# Defines the Ballot Class

class Wallet:

	def __init__(self, nodes):
		""" Makes the public private key pair"""
		self.public = None
		self.private = None
		self.nodes = nodes


	def make_transaction(public_key):
		""" send 1 coin from self to public key in the chain"""

	def check_balance(public_key):
		""" return the balance in a public key on the chain"""

class Ballot(Wallet):
	
	def __init__(self, nodes, issuer):
		""" Do some initialization here"""
		super(self, nodes)
		self.issuer = issuer

	def register():
		""" Register to vote by sending rpc call to Issuer"""

	def vote(public_key):
		""" Vote for the person in the public addr """

	def tally(public_keys):
		""" Tally the votes for the public addresses in publicAddrs"""

	def verify_vote():
		""" Verify my vote is in the blockchain """

class Issuer(Wallet):

	def __init__(self, nodes, pow_config):
		super(nodes)
		self.voters = []
		self.pow_config = pow_config

	def register(public_key):
		""" give the public key a coin on the chain"""
		self.voters.append(publicKey)
		# look up in the chain probably

	def list_register_voters():
		""" look up all public key addresses on the block chain"""
		return self.voters

	def tally(public_keys):
		""" Tally the votes for specific users

