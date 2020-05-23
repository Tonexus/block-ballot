
from block import Block
import xmlrpc.client
class ProcessNode(object):

    def __init__(self, initblockchain, node_addresses, id):
        self.blockchain = initblockchain
        self.node_addresses = node_addresses
        self.nodes = []
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address))

        self.coins_map={}
        self.s_coins_map={}
        self.id = id

    def verify_blockchain(self,blockchain1, blockchain2):
        """ check length """
        if(blockchain1!=None and blockchain1.length>=blockchain2.length):
            return False
        
        """ other check """
        pass

    def update_blockchain(self, blockchain, id):
        if(self.verify_blockchain(self.blockchain,blockchain)):
            self.blockchain = blockchain
        else:
            self.nodes[id].update_blockchain(self.blockchain, self.id)

        pass

    def RPC_update_blockchain(self):
        for node in self.nodes:
            node.update_blockchain(self.blockchain, self.id)
        pass

    def verify_block(self, newblock):     
        pass

    def verify_transaction(self, transaction):
        pass

    def add_transaction(self, transaction, id):
        if(self.verify_transaction(transaction)):
            
            return True
        else:
            return False
        
    def RPC_add_transaction(self, transaction):
        for node in self.nodes:
            node.add_transaction(transaction, self.id)
        pass

    def add_block(self, newblock, id):  
        if(not self.verify_block(newblock)):
            return False
        else:
            return True

        pass

    def RPC_add_block(self, newblock):
        for node in self.nodes:
            node.add_block(newblock, self.id)
        pass

    def get_blockchain(self):
        return self.blockchain

    def RPC_get_blockchain(self, id):
        self.nodes[id].get_blockchain()
        pass

    def tally(self, public_keys):
    	""" Tally the votes for the public addresses in publicAddrs"""

    def verify_vote(self):  
        """ Verify my vote is in the blockchain """
        pass

    def check_equal(self):
        pass

    def check_connection(self):
        return True
    
    def RPC_check_connection(self):
        for node in self.nodes:
            if(node.check_connection()):
                return True
        return False        

    def get_coins_info(self, name):
        return self.coins_map[name]

    def get_s_coins_info(self, name):
        return self.s_coins_map[name]

    def mining(self):
        pass

pro = ProcessNode(None,[],0)
