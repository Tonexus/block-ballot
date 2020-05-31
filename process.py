
from block import Block,LogicalBlock,GenesisBlock
from ballot import Issuer
from merkle import MerkleTree
from transaction import LogicalTransaction

import xmlrpc.client
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

class ProcessNode(object):

    def __init__(self, initblockchain, node_addresses, node_id, issuer_id, voters_map, config):
        self.blockchain = initblockchain
        self.blockheaders = []
        self.node_addresses = node_addresses
        self.nodes = []
        for node_address in node_addresses:
            self.nodes.append(xmlrpc.client.ServerProxy(node_address))

        #wallet records on blockchain
        self.coins_from_issuer={}
        self.coins_from_voter={}
        #wallet records plus pending_transactions
        self.cur_coins_from_issuer={}
        self.cur_coins_from_voter={}

        #self.s_coins_map={}
        self.id = node_id

        self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'])
        self.issuer_id = issuer_id
        self.voters_map = voters_map

        self.pending_transactions=[]

        self.lock = threading.Lock()

        self.interrupt_mining = 1

        self.pre_0 = 10

    #get a voter's public key
    def get_pkey(self, id):
        if(self.voters_map[id]==None):
            self.voters_map[id] = self.issuer.get_pkey(id)
        return self.voters_map[id]

    def set_genesis(self, public_key):
        print("Set genesis called")
        pk_bytes = bytes.fromhex(public_key)
        public_key = load_pem_public_key(pk_bytes, backend=default_backend())
        self.genesis_block = GenesisBlock(public_key, "")
        logical_block = LogicalBlock("", 0, None, None)
        logical_block.block = self.genesis_block
        self.blockchain = [logical_block]
        self.blockheaders = []

        #wallet records on blockchain
        self.coins_from_issuer={}
        self.coins_from_voter={}
        #wallet records plus pending_transactions
        self.cur_coins_from_issuer={}
        self.cur_coins_from_voter={}

        #self.s_coins_map={}

        self.pending_transactions=[]

        self.interrupt_mining = 1

    #replace bc1 with bc2
    #1.check length of blockchains
    #2.check pointers of blockchains
    #3.check each transaction
    #4.check root hash of merkle tree
    #5.update some state data
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

    #other process nodes or Issuer can call this
    #if the blockchain is verified, update self.blockchain with it
    #else let the caller update their with self.blockchain
    def update_blockchain(self, blockchain, id):
        #lock here
        self.lock.acquire()
        if(self.verify_blockchain(self.blockchain,blockchain)):
            self.interrupt_mining=1
            self.blockchain = blockchain
            self.lock.release()
        else:
            self.lock.release()
            if(id==-1):
                return 
            t1 = threading.Thread(self.nodes[id].update_blockchain(self.blockchain, self.id))
            t1.start()


    def RPC_update_blockchain(self):
        for node in self.nodes:
            t1 = threading.Thread(node.update_blockchain, (self.blockchain, self.id))
            t1.start()

    #similar to verify blockchain
    #if succeeds, update state data
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

    #1.check the validation of sender and receiver
    #2.check signature
    #3.check with the wallet records
    def verify_transaction(self, transaction, coins_from_issuer, coins_from_voter):
        (block_id, transaction_id) = transaction.src_transact_id
        if block_id == 0:
            src = blockchain[0].issr_pub_key
        else:
            src = self.blockchain[block_id].get_transaction(transaction_id).dst_pub_key
        dst = transaction.get_dst()
        # src_pkey = self.get_pkey(src)
        # if(src_pkey==None):
        #     return False
        if(not transaction.Verify(src)):
            return False

        # if(self.get_pkey(dst)==None):
        #         return False

        if(src!=self.issuer_id):
            if(coins_from_issuer[src]==0):
                return False
            coins_from_issuer[src]-=1
            coins_from_voter[dst]+=1
        else:
            coins_from_issuer[dst]+=1

        return True

    #can call by other process nodes or just this node 
    def add_transaction(self, transaction, id):
        #lock here
        self.lock.acquire()
        print(transaction)
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

    #if the verification fails, let the caller update their with self.blockchain
    def add_block(self, newblock, id):  
        #lock here
        self.lock.acquire()
        if(not self.verify_block(newblock)):
            self.lock.release()
            if(id==-1):
                return False
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

    #get the len of blockchain and current block hash
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

    #download and update one block
    def RPC_get_block(self, bid, nid):
        self.blockchain[bid] = self.nodes[nid].get_block(bid)

    #choose a group of nodes with same len and hash
    #download headers and verify
    #download blocks parellel and verify at the same time
    #if fail, retry
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

    #initialization
    #download the blockchain from a group of nodes in parellel
    #choose from the group with largest len, if fails, choose next group
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
            if(int(group_key[0])<=len(self.blockchain)):
                break
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

    #the hash path in Merkle Tree
    def get_hash_path(self, block_id, transaction_id):
        return self.blockchain[block_id].get_hash_path(transaction_id)

    #return hash of (hash1, hash2)
    def test_hash_path(self, hash1, hash2):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(hash1))
        digest.update(bytes.fromhex(hash2))
        return digest.finalize().hex()

    #Simplified Payment Verification
    #1.just loadload headers and hash path of the transacton in the Merkle tree
    #2.verify them, if half of the nodes succeed, return True
    def SPV_transaction(self, block_id, transaction_id, transaction_hash):
        
        con_cnt = 0
        spv_cnt = 0
        cur_hash  = transaction_hash
        for node in self.nodes:
            if(node.check_connection()):
                con_cnt += 1

            block_headers = node.get_block_headers()
            if(not self.verfity_blockheaders(block_headers)):
                continue
            hash_path = node.get_hash_path(block_id, transaction_id)
            if(len(hash_path)==0 or len(block_headers)<=block_id):
                continue

            for i in range(len(hash_path)):
                cur_hash = self.test_hash_path(cur_hash, hash_path[i])

            if(cur_hash != block_headers[block_id].root_hash):
                continue
            else:
                spv_cnt+=1

        if(spv_cnt*2>con_cnt):
            return True
        else:
            return False        

    def getnext(self,nonce):
        return nonce+1
    def check_hash(self, hash):
        #pre 0
        return True

    
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
                break 

            nonce = self.getnext(nonce)


pro = ProcessNode(None,[],0,"", {}, {'issuer_address':'http://localhost:12345/ISSUER'})
