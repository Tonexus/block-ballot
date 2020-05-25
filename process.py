
from block import Block,LogicalBlock
from ballot import Issuer
from merkle import MerkleTree
import xmlrpc.client
import threading

class ProcessNode(object):

    def __init__(self, initblockchain, node_addresses, node_id, issuer_id, voters_map, config):
        self.blockchain = initblockchain
        self.blockheaders = []
        self.node_addresses = node_addresses
        self.nodes = []
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address))

        self.coins_from_issuer={}
        self.coins_from_voter={}
        self.cur_coins_from_issuer={}
        self.cur_coins_from_voter={}

        self.s_coins_map={}
        self.id = node_id

        self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'])
        self.issuer_id = issuer_id
        self.voters_map = voters_map

        self.pending_transactions=[]

        self.lock = threading.Lock()

        self.interrupt_mining = 1

        self.pre_0 = 10

    def get_pkey(self, id):
        if(self.voters_map[id]==None):
            self.voters_map[id] = self.issuer.get_pkey(id)
        return self.voters_map[id]

    #replace bc1 with bc2
    def verify_blockchain(self,blockchain1, blockchain2):
        """ check length """
        if(blockchain1!=None and len(blockchain1)>=len(blockchain2)):
            return False
        
        #check pointers
        for i in range(1,len(blockchain2)):
            if(blockchain2[i].prev_block_hash!=blockchain2[i-1].block.to_hash()):
                return False

        coins_from_issuer={}
        coins_from_voter={}
        for logic_block in blockchain2:
            #check transactions
            for transaction in logic_block.transactions:
                if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter)):
                    return False
            #check block.roothash
            tmp_MerkleTree = MerkleTree(logic_block.transactions)
            if(tmp_MerkleTree.get_hash!=logic_block.block.root_hash):
                return False

        self.coins_from_issuer = coins_from_issuer
        self.coins_from_voter = coins_from_voter

        self.cur_coins_from_issuer = coins_from_issuer
        self.cur_coins_from_voter = coins_from_voter
        self.pending_transactions=[]

        return True        


    def update_blockchain(self, blockchain, id):
        #lock here
        self.lock.acquire()
        if(self.verify_blockchain(self.blockchain,blockchain)):
            self.interrupt_mining=1
            self.blockchain = blockchain
            self.lock.release()
        else:
            self.lock.release()
            t1 = threading.Thread(self.nodes[id].update_blockchain(self.blockchain, self.id))
            t1.start()

    def RPC_update_blockchain(self):
        for node in self.nodes:
            t1 = threading.Thread(node.update_blockchain, (self.blockchain, self.id))
            t1.start()

    def verify_block(self, newblock):    
        if(newblock.prev_block_hash!=self.blockchain[len(self.blockchain)-1].block.to_hash()):
            return False

        coins_from_issuer=self.coins_from_issuer.copy()
        coins_from_voter=self.coins_from_voter.copy()
        
        #check transactions
        for transaction in newblock.transactions:
            if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter)):
                return False
        #check block.roothash
        tmp_MerkleTree = MerkleTree(newblock.transactions)
        if(tmp_MerkleTree.get_hash!=newblock.block.root_hash):
            return False

        self.coins_from_issuer = coins_from_issuer
        self.coins_from_voter = coins_from_voter

        self.cur_coins_from_issuer = coins_from_issuer
        self.cur_coins_from_voter = coins_from_voter
        self.pending_transactions=[]

        return True       

    def verify_transaction(self, transaction, coins_from_issuer, coins_from_voter):
        src = transaction.get_src()
        dst = transaction.get_dst()
        src_pkey = self.get_pkey(src)
        if(src_pkey==None):
            return False
        if(not transaction.Verify(src_pkey)):
            return False

        if(self.get_pkey(dst)==None):
                return False

        if(src!=self.issuer_id):
            if(coins_from_issuer[src]==0):
                return False
            coins_from_issuer[src]-=1
            coins_from_voter[dst]+=1
        else:
            coins_from_issuer[dst]+=1

        return True


    def add_transaction(self, transaction, id):
        #lock here
        self.lock.acquire()
        if(self.verify_transaction(transaction, self.cur_coins_from_issuer, self.cur_coins_from_voter)):
            self.pending_transactions.append(transaction)
            self.interrupt_mining=1
            self.lock.release()
            return True
        else:
            self.lock.release()
            return False
        
    def RPC_add_transaction(self, transaction):
        for node in self.nodes:
            t1 = threading.Thread(node.add_transaction,(transaction, self.id))
            t1.start()

    def add_block(self, newblock, id):  
        #lock here
        self.lock.acquire()
        if(not self.verify_block(newblock)):
            self.lock.release()
            t1 = threading.Thread(self.nodes[id].update_blockchain,(self.blockchain))
            t1.start()
            return False
        else:
            self.blockchain.append(newblock)
            self.lock.release()
            return True

    def RPC_add_block(self, newblock):
        for node in self.nodes:
            t1 = threading.Thread(node.add_block,(newblock, self.id))
            t1.start()

    def get_blockchain(self):
        return self.blockchain

    def get_len_hash(self):
        return len(self.blockchain), self.blockchain[len(self.blockchain)-1].block.to_hash()
    
    def get_block_headers(self):
        return self.blockheaders

    def verfity_blockheaders(self,blockheaders):
        for i in range(1,len(blockheaders)):
            if(blockheaders[i].prev_hash!=blockheaders[i-1].to_hash()):
                return False
        return True

    def get_block(self, bid):
        return self.blockchain[bid]

    def RPC_get_block(self, bid, nid):
        self.blockchain[bid] = self.nodes[nid].get_block(bid)

    def headers_first_DL(self, group, len_bc):
        self.blockheaders = []
        
        flag = 0
        for id in group:
            blockheaders = self.nodes[id].get_block_headers()
            if(self.verfity_blockheaders(blockheaders)):
                flag = 1
                break
            else:
                group.remove(id)

        if(flag==0):
            return False

        self.blockchain = [None for i in range(len_bc)]
        coins_from_issuer={}
        coins_from_voter={}
        len_gp = len(group)

        cur = 1
        for i in range(0,len_bc,len_gp):
            for j in range(len_gp):
                if(i+j>=len_bc):
                    break
                t1 = threading.Thread(self.get_block,(i,group[j]))
                t1.start()

            end = min(i+j, len_bc)
            #check pointers
            for k in range(cur, end):
                if(self.blockchain[k].prev_block_hash!=self.blockchain[k-1].block.to_hash()):
                    group.remove(k-cur)
                    return False

            for k in range(cur, end):
                logic_block = self.blockchain[cur]
                #check transactions
                for transaction in logic_block.transactions:
                    if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter)):
                        group.remove(k-cur)
                        return False
                #check block.roothash
                tmp_MerkleTree = MerkleTree(logic_block.transactions)
                if(tmp_MerkleTree.get_hash!=logic_block.block.root_hash):
                    group.remove(k-cur)
                    return False
            
            cur = cur+len_gp

        self.coins_from_issuer = coins_from_issuer
        self.coins_from_voter = coins_from_voter

        self.cur_coins_from_issuer = coins_from_issuer
        self.cur_coins_from_voter = coins_from_voter
        self.pending_transactions=[]
        
        return True

    def RPC_get_blockchain(self):
        len_hash_map = {}
        len_hash_list = []
        for i in range(len(self.nodes)):
            t_len, t_hash = self.nodes[i].get_len_hash()
            key = str(t_len)+"::"+str(t_hash)
            if(len_hash_map[key]==None):
                len_hash_map[key] = []
            len_hash_map[key].append(i)

        for key in len_hash_map.keys():
            strs = key.split("::")
            len_hash_list.append([strs[0],strs[1]])

        len_hash_list.sort(reverse=True, key=lambda x:x[0]) 

        for group_key in len_hash_list:
            key = group_key[0]+"::"+group_key[1]
            group = len_hash_map[key]

            while(len(group)!=0):
                if(self.headers_first_DL(group, int(group_key[0]))):
                    return True

        return False            

    def tally(self, public_keys):
    	""" Tally the votes for the public addresses in publicAddrs"""

    def verify_vote(self):  
        """ Verify my vote is in the blockchain """
        pass

    def check_connection(self):
        return True
    
    def RPC_check_connection(self):
        for node in self.nodes:
            if(node.check_connection()):
                return True
        return False        

    def getnext(self,nonce):
        return nonce+1

    def check_hash(self,hash):
        pass

    def mining(self):
        nonce = 0
        pre_hash = 0
        
        newblock = LogicalBlock(pre_hash, len(self.blockchain), self.pending_transactions, nonce)
        while(True):
            if(self.interrupt_mining==1):
                nonce=0
                pre_hash = self.blockchain[len(self.blockchain)-1].block.to_hash()
                newblock = LogicalBlock(pre_hash, len(self.blockchain), self.pending_transactions, nonce)
                self.interrupt_mining = 0

            #newblock = LogicalBlock(pre_hash, len(self.blockchain), self.pending_transactions, nonce)
            newblock.block = newblock.build_block_data(nonce)
            if(self.check_hash(newblock.block.to_hash())):
                self.add_block(newblock,-1)
                self.RPC_add_block(newblock)
                self.interrupt_mining = 1
                break;    

            nonce = self.getnext(nonce)


pro = ProcessNode(None,[],0,"", {}, {'issuer_address':'http://localhost:12345/ISSUER'})
