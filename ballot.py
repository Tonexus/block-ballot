import xmlrpc.client
import pickle
import logging

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
        self.public_hex = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).hex()
        self.node_addresses = node_addresses
        self.nodes = []
        self.transaction_hash = None
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
        print("Inside make transaction", public_key)
        # Make the transaction from self to the other public address
        # store source transaction info inside the wallet
        # for the Issuer is special issuer transaction
        # For the regular voter is the results of registering to vote
        if self.source_transaction_id is None and self.transaction_hash is not None:
            # Find my source transaction id
            print('My source transaction id was none')
            longest_bc = []
            for node in nodes:
                bc = node.get_blockchain()
                bc = pickle.loads(bc.data)
                if len(bc) > len(longest_bc):
                    longest_bc = bc
            # find new transaction in the blockchain
            print(len(longest_bc))
            i = len(longest_bc) - 1
            for block in reversed(longest_bc[1:]):

                # loop through transactions in the block?
                print("Inside the for loop inside make_transaction: ", block)
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
        print(self.source_transaction_id, self.transaction_hash)
        if self.source_transaction_id is None:
            return None, None, self.transaction_hash
        transaction = Transaction(self.source_transaction_id, public_key, self.source_transaction_data, self.private)
        self.transaction_hash = transaction.to_hash()
        for tries in range(MAX_TRIES):
            print("After make transaction")
            test = pickle.dumps(transaction)
            print("After pickling")
            for node in nodes:
                print("About to call add transaction")
                ret = node.add_transaction(pickle.dumps(transaction), tries)
                print("Added to the node")
                if ret == False:
                    return None, None, self.transaction_hash
            print("Got to the timeout")
            time.sleep(TIMEOUT)
            longest_bc = []
            for node in nodes:
                bc = node.get_blockchain()
                bc = pickle.loads(bc.data)
                if len(bc) > len(longest_bc):
                    longest_bc = bc
            # find new transaction in the blockchain
            print(len(longest_bc))
            i = len(longest_bc) - 1
            for block in reversed(longest_bc[1:]):

                # loop through transactions in the block?
                print("Inside the for loop inside make_transaction: ", block)
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
            bc = node.get_blockchain()
            bc = pickle.loads(bc.data)
            if len(bc) > len(longest_bc):
                longest_bc = bc
        if self.verify_blockchain(longest_bc):
            self.blockchain = []
            self.genesis_block = None
            return longest_bc
        return []


    def verify_blockchain(self,blockchain):
        """ check length """
        #check pointers
        for i in range(1,len(blockchain)):
            if(blockchain[i].prev_block_hash!=blockchain[i-1].block.to_hash()):
                print("Pointers did not check out")
                return False

        coins_from_issuer={}
        coins_from_voter={}
        self.genesis_block = blockchain[0].block
        if self.genesis_block.issr_pub_key != self.issuer_public_hex:
            print("Genesis Block is different")
            return False
        self.blockchain = blockchain
        for logic_block in blockchain[1:]:
            #check transactions
            for transaction in logic_block.transactions:
                if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter)):
                    print("Not a valid transaction")
                    return False
            #check block.roothash
            tmp_MerkleTree = MerkleTree(logic_block.transactions)
            if(tmp_MerkleTree.get_hash!=logic_block.block.root_hash):
                print("Root hashes are not the same")
                return False
        return True  

    def verify_transaction(self, transaction, coins_from_issuer, coins_from_voter):
        (block_id, transaction_id) = transaction.src_transact_id
        if block_id == 0:
            src_str = self.genesis_block.issr_pub_key
            pk_bytes = bytes.fromhex(src_str)
            src = load_pem_public_key(pk_bytes, backend=default_backend())
        else:
            src_str = self.blockchain[block_id].get_transaction(transaction_id).dst_pub_key
            pk_bytes = bytes.fromhex(src_str)
            src = load_pem_public_key(pk_bytes, backend=default_backend())

        dst = transaction.dst_pub_key

        if(not transaction.verify(src)):
            return False

        if(src_str != self.genesis_block.issr_pub_key):
            if coins_from_issuer[src_str] == 0:
                return False
        else:
            if dst not in coins_from_issuer:
                return True
            else:
                return False
        return True


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
        nodes = self.pick_nodes()
        longest_bc = []
        for node in nodes:
            bc = node.get_blockchain()
            bc = pickle.loads(bc.data)
            if len(bc) > len(longest_bc):
                longest_bc = bc
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
        print("Calling register")
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
            node.set_genesis(public_key_hex, self.num_zeros, self.transactions_per_block)
        return True

    def register(self, public_key):
        """ Gives the public key a coin on the chain
        Public key comes in as hex form
        """
        print("Inside here, ", public_key)
        pk_bytes = bytes.fromhex(public_key)
        public_key = load_pem_public_key(pk_bytes, backend=default_backend())
        self.voters.append(public_key)
        (s_id, s_data, t_hash) = self.make_transaction(public_key)
        print("After unpacking the ")
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
        public_key = self.public.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).hex()
        nodes = self.pick_nodes()
        longest_bc = []
        for node in nodes:
            bc = node.get_blockchain()
            bc = pickle.loads(bc.data)
            if len(bc) > len(longest_bc):
                longest_bc = bc
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
                # if (b, t) == (0, 0):
                    # balances[transaction.dst_pub_key]['balance'] -= 1
                t_id += 1
            b_id += 1
        return balances


    def get_pkey(self, src):
        pass

