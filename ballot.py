import xmlrpc.client
import pickle
import logging
import putil

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from random import sample 
import time

from transaction import Transaction
from block import LogicalBlock

TIMEOUT = 1
MAX_TRIES = 1

class Wallet:
    """ Wallet class interacts with a blockchain node to write and read data

    Attributes
    ----------
    public : public_key
        The public key for the user of this wallet
    public_hex : str
        The public key for the user of this wallet in hex form
    private : private_key
        The private key associated with the public key
    node_addresses : str[]
        List of ip address:port of Processor nodes
    nodes : xmlrpc.client[]
        List of rpc clients associated with the processor nodes 
    transaction_hash : str
        Hash of the last transaction this node tried to make

    Methods
    -------
    make_transaction(public_key)
        Sends a coin to the public_key using the nodes in the blockchain
    check_balance(public_key)
        Check the balance of coins in the public key in the blockchain
    set_nodes(node_addresses)
        Sets the node_addresses list. Used as a helper for testing
    pick_nodes()
        Returns a subset of the nodes to send transactions to
    get_blockchain()
        Gets the longest blockchain from node_addresses and validates it
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
        self.public_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        self.node_addresses = node_addresses
        self.nodes = []
        self.transaction_hash = None
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address, allow_none=True))

    def set_nodes(self, node_addresses):
        node_addresses = pickle.loads(node_addresses.data)
        self.node_addresses = node_addresses
        self.nodes = []
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address, allow_none=True))


    def pick_nodes(self):
        """ Function to pick subset of nodes to send transactions to
        Right not picking random subset of the nodes"""
        if self.nodes == []:
            return []
        return self.nodes
        # return sample(self.nodes,1)


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
        # Make the transaction from self to the other public address
        # store source transaction info inside the wallet
        # for the Issuer is special issuer transaction
        # For the regular voter is the results of registering to vote
        if self.source_transaction_id is None and self.transaction_hash is not None:
            # Find my source transaction id
            longest_bc = self.get_blockchain()
            i = len(longest_bc) - 1
            for block in reversed(longest_bc[1:]):
                # loop through transactions in the block?
                j = 0
                for transaction_bc in block.transactions:
                    if self.transaction_hash == transaction_bc.to_hash(): # check src_transaction.public_key?
                        self.source_transaction_id = (i, j)
                        self.source_transaction_data = transaction_bc
                        break
                    j+=1
                if self.source_transaction_id is not None:
                    break
                i-=1
        if self.source_transaction_id is None:
            return None, None, self.transaction_hash
        transaction = Transaction(self.source_transaction_id, public_key, self.source_transaction_data, self.private)
        self.transaction_hash = transaction.to_hash()
        for tries in range(MAX_TRIES):
            test = pickle.dumps(transaction)
            for node in nodes:
                try:
                    ret = node.add_transaction(pickle.dumps(transaction), tries)
                except:
                    ret = True
                if ret == False:
                    return None, None, self.transaction_hash
            time.sleep(TIMEOUT)
            longest_bc = self.get_blockchain()
            i = len(longest_bc) - 1
            for block in reversed(longest_bc[1:]):
                # loop through transactions in the block?
                j = 0
                for transaction_bc in block.transactions:
                    if transaction.to_hash() == transaction_bc.to_hash(): # check src_transaction.public_key?
                        return (i, j), transaction_bc, self.transaction_hash
                    j+=1
                i-=1
            # now repeat above steps
        return None, None, self.transaction_hash

    def get_blockchain(self):
        nodes = self.pick_nodes()
        longest_bc = []
        for node in nodes:
            try:
                bc = node.get_blockchain()
                bc = pickle.loads(bc.data)
            except:
                bc = []
            if len(bc) > len(longest_bc):
                longest_bc = bc
        if putil.valid_blockchain(longest_bc):
            return longest_bc
        return []

    def check_balance(self, public_key):
        """ Retrieves the balance in a public key on the chain

        Parameters
        ----------
        punlic_key : public_key
            The address to check the balance of
        """
        # traverse all the transactions
        if type(public_key) == type(self.public):
            public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).hex()
        longest_bc = self.get_blockchain()
        balance = 0
        transaction_ids = []
        b_id = 1
        for block in longest_bc[1:]:
            t_id = 0
            for transaction in block.transactions:
                if transaction.dst_pub_key == public_key:
                    balance += 1
                    transaction_ids.append((b_id, t_id))
                elif transaction.src_transact_id in transaction_ids:
                    balance -= 1
                t_id += 1
            b_id += 1
        return balance


class Ballot(Wallet):
    """ Ballot class is a Wallet that knows to register with the Issuer and to vote for people.

    Attributes
    ----------
    issuer : xmlrpc.client
        xmlrpc client object to interact with the Issuer
    issuer_address : str
        url address of the Issuer
    registered : bool
        Flag to know if I have already registered
    source_transaction_id : (int, int)
        Source of the registration
    source_transaction_data : str 
        Source of the registration

    Methods
    -------
    register()
        Sends my public key to the Issuer to have them register us
    vote(public_key)
        Vote for the public key provided
    tally()
        Check my own wallet balance
    """
    
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
        self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'], allow_none=True)
        self.issuer_address = config['issuer_address']
        self.registered = False
        self.source_transaction_id = -1
        self.source_transaction_data = ""

    def register(self):
        """ Register to vote by sending rpc call to Issuer
        Returns the RPC call's return value
        """
        if self.registered or self.check_balance(self.public):
            return True
        self.registered = True
        public_key_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        (self.source_transaction_id, self.source_transaction_data, self.transaction_hash, self.issuer_public_hex) = pickle.loads(self.issuer.register(public_key_hex).data)
        if self.source_transaction_id == None or self.source_transaction_data == None:
            return False
        # pk_bytes = bytes.fromhex(self.source_transaction_data.dst_pub_key)
        # self.source_transaction_data.dst_pub_key = load_pem_public_key(pk_bytes, backend=default_backend())
        return True

    def vote(self, public_key):
        """ Vote for the person in the public addr 

        Parameters
        ----------
        public_key : public_key
            The public key of the person the user wants to vote for

        """
        if self.registered:
            s_id, s_data, self.transaction_hash = self.make_transaction(public_key)
            if s_id == None or s_data == None:
                return False
            else:
                self.source_transaction_id = s_id
                self.source_transaction_data = s_data
                return True
        return False

    def tally(self):
        """ Tally the votes for the public addresses in public key"""
        return self.check_balance(self.public)


class Issuer(Wallet):
    """
    The Issuer will be an RPC server that the government entity will interact with directly. 
    The Ballots also will directly register themselves to vote tothe Issuer.
    The Issuer will also start up the RPC servers acting as the Processor nodes

    Attributes
    ----------
    voters : str[]
        List of public keys that the Issuer has registered.
    num_zeros : int
        Number of zeros needed for proof of work
    transactions_per_block : int
        Number of valid transactions per block
    source_transaction_id : (int, int)
        Source of all transactions for registration (genesis block)
    source_transaction_data : None
        Set to none since the Issuer is getting "infinite" coins from the genesis block wallet

    Methods
    -------
    start_election
        Starts up the election by publishing the genesis block to the Processor nodes

    register
        Function that takes a public address and gives it a coin

    list_registered_users
        Return the list of registered users

    get_winner
        Gets the blockchain and 
    """

    def __init__(self, config):
        super().__init__(config['node_addresses'])
        self.voters = []
        self.num_zeros = config['num_zeros']
        self.transactions_per_block = config['transactions_per_block']
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
            try:
                node.set_genesis(public_key_hex, self.num_zeros, self.transactions_per_block)
            except:
                pass
        return True

    def register(self, public_key):
        """ Gives the public key a coin on the chain
        Public key comes in as hex form
        """
        pk_bytes = bytes.fromhex(public_key)
        public_key = load_pem_public_key(pk_bytes, backend=default_backend())
        self.voters.append(public_key)
        try:
            (s_id, s_data, t_hash) = self.make_transaction(public_key)
        except:
            (s_id, s_data, t_hash) = None, None, self.transaction_hash
        return pickle.dumps((s_id, s_data, t_hash, self.public_hex))

    def list_registered_voters(self):
        """ look up all public key addresses on the block chain"""
        return self.voters  # Should ideal look this up in the chain

    def tally(self, public_keys):
        """ Tally the votes for specific users"""
        balances = {}
        for key in public_keys:
            balances[key] = self.check_balance(key)
        return balances

    def get_winner(self):
        """ Gets a dict of key to balance mappings """
        public_key = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        longest_bc = self.get_blockchain()
        balances = {public_key: {'transaction_ids': [], 'balance': 0}}
        transactions_to_keys = [[public_key, public_key],[]]
        b_id = 1
        for block in longest_bc[1:]:
            t_id = 0
            for transaction in block.transactions:
                if transaction.dst_pub_key not in balances:
                    balances[transaction.dst_pub_key] = {'transaction_ids': [], 'balance': 0}
                balances[transaction.dst_pub_key]['balance'] += 1
                balances[transaction.dst_pub_key]['transaction_ids'].append((b_id, t_id))
                transactions_to_keys[b_id].append(transaction.dst_pub_key)
                t_id += 1
            transactions_to_keys.append([])
            b_id += 1
        b_id = 1
        for block in longest_bc[1:]:
            t_id = 0
            for transaction in block.transactions:
                (b, t) = transaction.src_transact_id
                balances[transactions_to_keys[b][t]]['balance'] -= 1
                t_id += 1
            b_id += 1
        return balances


    def get_pkey(self, src):
        pass

