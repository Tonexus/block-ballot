
from block import Block
import xmlrpc.client
class ProcessNode(object):

    def __init__(self, initblockchain, node_addresses):
        self.blockchain = initblockchain
        self.node_addresses = node_addresses
        self.nodes = []
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address))

    def verify_blockchain(self,blockchain1, blockchain2):
        """ check length """
        if(blockchain1!=None and blockchain1.length>=blockchain2.length):
            return False
        
        """ other check """
        pass

    def update_blockchain(self, blockchain):
        if(self.verify_blockchain(self.blockchain,blockchain)):
            self.blockchain = blockchain
        pass

    def RPC_update_blockchain(self):
        for node in self.nodes:
            node.update_blockchain(self.blockchain)
        pass

    def verify_block(self, newblock):     
        pass

    def add_block(self, newblock):  
        if(not self.verify_block(newblock)):
            return False
        pass

    def RPC_add_block(self, newblock):
        for node in self.nodes:
            node.add_block(newblock)
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

pro = ProcessNode(None,[])