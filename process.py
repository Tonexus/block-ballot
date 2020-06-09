from block import Block,LogicalBlock,GenesisBlock
from ballot import Issuer
from merkle import MerkleTree
from transaction import Transaction

import threading

import xmlrpc.client
import threading
import pickle

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

DEFAULT_TRANSACTIONS_PER_BLOCK = 3
def hex2(n):
    x = '%x' % (n,)
    return ('0' * (len(x) % 2)) + x

class ProcessNode(object):

    def __init__(self, initblockchain, node_addresses, node_id, issuer_id, voters_map, config):
        self.blockchain = initblockchain
        self.blockheaders = []
        self.node_addresses = node_addresses
        self.nodes = []
        for i in range(len(node_addresses)):
            if i != node_id:
                self.nodes.append(xmlrpc.client.ServerProxy(node_addresses[i], allow_none=True))

        #wallet records on blockchain
        # self.coins_from_issuer={}
        # self.coins_from_voter={}
        #wallet records plus pending_transactions
        self.cur_coins_from_issuer={}
        self.cur_coins_from_voter={}

        #self.s_coins_map={}
        self.id = node_id

        self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'], allow_none=True)
        self.issuer_id = issuer_id
        self.voters_map = voters_map

        self.pending_transactions=[]

        self.lock = threading.Lock()

        self.interrupt_mining = 1

        self.pre_0 = 10
        self.private = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
            )
        self.public = self.private.public_key()
        self.is_mining = False
        self.mining_thread = None
        self.recieved_new_block = False
        self.transactions_per_block = DEFAULT_TRANSACTIONS_PER_BLOCK
        self.mining_transactions = []



    #get a voter's public key
    def get_pkey(self, id):
        if(self.voters_map[id]==None):
            self.voters_map[id] = self.issuer.get_pkey(id)
        return self.voters_map[id]

    def set_genesis(self, public_key, num_zeros, num_transactions):
        # print("Set genesis called")
        pk_bytes = bytes.fromhex(public_key)
        public_key = load_pem_public_key(pk_bytes, backend=default_backend())
        self.genesis_block = GenesisBlock(public_key, "", num_zeros)
        logical_block = LogicalBlock("", 0, None, None)
        logical_block.block = self.genesis_block
        self.blockchain = [logical_block]
        self.blockheaders = []

        #wallet records on blockchain
        # self.coins_from_issuer={}
        # self.coins_from_voter={}
        #wallet records plus pending_transactions
        self.cur_coins_from_issuer={}
        self.cur_coins_from_voter={}

        #self.s_coins_map={}

        self.pending_transactions=[]

        self.interrupt_mining = 1
        self.issuer_id = public_key
        self.transactions_per_block = num_transactions
        self.mining_thread = None
        if self.mining_thread:
            self.mining_thread.terminate()
        self.mining_thread = None
        self.is_mining = False
        self.mining_transactions = []
        self.recieved_new_block = False
        print("End of set genesis block, length of blockchain should be 1 but is: ", len(self.blockchain))


    #replace bc1 with bc2
    #1.check length of blockchains
    #2.check pointers of blockchains
    #3.check each transaction
    #4.check root hash of merkle tree
    #5.update some state data     ours         other
    def verify_blockchain(self, blockchain):
        """ check length """
        
        #check pointers
        for i in range(1,len(blockchain)):
            if blockchain[i].prev_block_hash != blockchain[i-1].block.to_hash():
                return None, None

        coins_from_issuer={}
        coins_from_voter={}
        transactions = []
        blockchain = []
        for logic_block in blockchain:
            #check transactions
            if self.verify_block(logic_block, blockchain, coins_from_issuer, coins_from_voter):
                blockchain.append(logic_block)
                self.update_metadata(logic_block, blockchain, coins_from_issuer, coins_from_voter)
                # update meta_data
            else:
                return None, None
            # for transaction in logic_block.transactions:
            #     if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter, transactions)):
            #         return False
            #     transactions.append(transaction)
            # #check block.roothash
            # tmp_MerkleTree = MerkleTree(logic_block.transactions)
            # if(tmp_MerkleTree.get_hash!=logic_block.block.root_hash):
            #     return False

        # self.coins_from_issuer = coins_from_issuer
        # self.coins_from_voter = coins_from_voter

        # self.cur_coins_from_issuer = coins_from_issuer
        # self.cur_coins_from_voter = coins_from_voter
        # self.pending_transactions=[]

        return coins_from_issuer, coins_from_voter        

    #other process nodes or Issuer can call this
    #if the blockchain is verified, update self.blockchain with it
    #else let the caller update their with self.blockchain
    def update_blockchain(self, blockchain, id):
        #lock here
        self.lock.acquire()
        if(self.verify_blockchain(blockchain)):
            self.interrupt_mining=1
            self.blockchain = blockchain
            self.cur_coins_from_issuer = {}
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
    def verify_block(self, newblock, blockchain, coins_from_issuer, coins_from_voter):
        # print("Verify block called")
        if blockchain is None:
            return False
        if len(blockchain) == 0:
            if type(newblock.block) is GenesisBlock: # ?
                print("The first block of an empty blockchain is a GenesisBlock")
                return True
            else:
                print("The first block in chain is not a genesis block", type(newblock), type(newblock.block))
                return False
        if(newblock.prev_block_hash!=blockchain[len(blockchain)-1].block.to_hash()):
            print('Prev hash isnt right')
            return False

        # coins_from_issuer=self.cur_coins_from_issuer.copy()
        # coins_from_voter=self.cur_coins_from_voter.copy()
        
        #check transactions
        # print("About to forloop inside verify_block")
        if len(newblock.transactions) != self.transactions_per_block + 1:
            print('Num transactions incorrect', len(newblock.transactions), self.transactions_per_block)
            return False
        block_transactions = []
        for transaction in newblock.transactions[1:]:
            # print("About to call verify transactions")
            if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter, block_transactions, blockchain)):
                print("Transaction not valid inside verify block")
                return False
            # add to minig_transactions
            block_transactions.append(transaction)
            # print("Outside if")
        #check block.roothash
        tmp_MerkleTree = MerkleTree(newblock.transactions)
        if(tmp_MerkleTree.get_hash()!=newblock.block.root_hash):
            # print("About to return false after the merkel tree")
            return False

        # self.coins_from_issuer = coins_from_issuer
        # self.coins_from_voter = coins_from_voter

        # self.cur_coins_from_issuer = coins_from_issuer
        # self.cur_coins_from_voter = coins_from_voter
        # self.pending_transactions=[]

        return True       

    #1.check the validation of sender and receiver
    #2.check signature
    #3.check with the wallet records
    # Logical Transaction
    def verify_transaction(self, transaction, coins_from_issuer, coins_from_voter, block_transactions, blockchain):
        (block_id, transaction_id) = transaction.src_transact_id
        if block_id == 0:
            src_str = blockchain[0].block.issr_pub_key
            pk_bytes = bytes.fromhex(src_str)
            src = load_pem_public_key(pk_bytes, backend=default_backend())
        else:
            src_str = blockchain[block_id].get_transaction(transaction_id).dst_pub_key
            pk_bytes = bytes.fromhex(src_str)
            src = load_pem_public_key(pk_bytes, backend=default_backend())

        dst = transaction.dst_pub_key
        # src_pkey = self.get_pkey(src)
        # if(src_pkey==None):
        #     return False
        # print("before verify", type(transaction))
        if(not transaction.verify(src)):
            return False
        # print("After verify")
        # if(self.get_pkey(dst)==None):
        #         return False

        if(src_str != blockchain[0].block.issr_pub_key):
            # print("VERIFY_TRANSACTIN: inside if")
            # if src not in coins_from_issuer:
            #     coins_from_issuer[src] = 0
            # if dst not in coins_from_voter:
            #     coins_from_voter[dst] = 0
            if src_str not in coins_from_issuer:
                return False
            if coins_from_issuer[src_str] == 0:
                return False
            for transaction_bc in block_transactions:
                    if transaction_bc.src_transact_id == (block_id, transaction_id): #and transaction_bc.to_hash() != transaction.to_hash():
                        return False
            # coins_from_issuer[src]-=1
            # coins_from_voter[dst]+=1
        else:
            # print("Inside else, coin from Issuer", dst)
            # print("DST is: ", dst)
            # print("The Keys: ", coins_from_issuer.keys())
            if dst not in coins_from_issuer:
                for transaction_bc in block_transactions:
                    if transaction_bc.dst_pub_key == dst:
                        return False
                return True
            else:
                return False

        return True

    def update_metadata(self, new_block, blockchain, coins_from_issuer, coins_from_voter):
        for transaction in new_block.transactions[1:]:
            (block_id, transaction_id) = transaction.src_transact_id
            if block_id == 0:
                src_str = blockchain[0].block.issr_pub_key
                pk_bytes = bytes.fromhex(src_str)
                src = load_pem_public_key(pk_bytes, backend=default_backend())
            else:
                src_str = blockchain[block_id].get_transaction(transaction_id).dst_pub_key
                pk_bytes = bytes.fromhex(src_str)
                src = load_pem_public_key(pk_bytes, backend=default_backend())
            dst = transaction.dst_pub_key

            if(src_str != blockchain[0].block.issr_pub_key):
                # Voter sending vote to other voter
                # # print("Inside the if part", self.cur_coins_from_issuer)
                if src_str not in coins_from_issuer:
                    # # print("Inside not coins from issuer")
                    return False
                    # self.cur_coins_from_issuer[src] = 0
                if dst not in coins_from_voter:
                    coins_from_voter[dst] = 0
                if coins_from_issuer[src_str]==0 :
                    return False
                # # print("METADATA updating-----------")
                coins_from_issuer[src_str]-=1
                coins_from_voter[dst]+=1
            else:
                # Issuer issuing a vote
                # # print("METADATA: Else")
                coins_from_issuer[dst] = 1
        return True


    #can call by other process nodes or just this node 
    def add_transaction(self, transaction, id):
        #lock here
        self.lock.acquire()
        # print(transaction)
        # print("Type of transaction: ",type(transaction))
        transaction = pickle.loads(transaction.data)
        # print("After pickle.load")
        if(self.verify_transaction(transaction, self.cur_coins_from_issuer, self.cur_coins_from_voter, [], self.blockchain)):
            # print("Inside if on add_transaction", id)
            self.pending_transactions.append(transaction)
            if len(self.pending_transactions) == self.transactions_per_block and not self.is_mining:
                # Call mining
                # self.is_mining = True
                self.interrupt_mining=1
                self.lock.release()
                # spawn new process unless already mining?
                self.mining_thread = threading.Thread(target=self.mining, args=())
                self.mining_thread.start()
                # self.mining()
                return True
            self.lock.release()
            return True
        else:
            # print("Inside else, inside add_transaction, about to return false")
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
        if id != self.id:
            newblock = pickle.loads(newblock.data)
        print("Length of self.blockchain: ", len(self.blockchain))
        if(not self.verify_block(newblock, self.blockchain, self.cur_coins_from_issuer, self.cur_coins_from_voter)):
            # The block is not valid
            print('Shoudlnt happen since block is valid')
            # recovery on ourselves if we don't have the longest blockchain
            # for node in nodes:
            #     get the longest blockchain
            # if valid then make that ours
            if(id==self.id):
                self.lock.release()
                return False
            # get their blockchain
            # if theirs is longer then verify and set to ours
            # else i don't care if theyre behind
            other_bc = pickle.loads(self.nodes[id].get_blockchain().data)
            if len(other_bc) > len(self.blockchain) and other_bc[0].block.issr_pub_key == self.blockchain[0].block.issr_pub_key:
                coins_from_issuer, coins_fromvoters = self.verify_blockchain(other_bc)
                if coins_from_issuer is None:
                    self.lock.release()
                    return False
                else:
                    self.cur_coins_from_issuer = coins_from_issuer
                    self.cur_coins_from_voter = coins_from_voter
                    self.blockchain = other_bc
                    self.lock.release()
                    return True
            # t1 = threading.Thread(target=self.nodes[id].update_blockchain,args=(self.blockchain))
            # t1.start()
            self.lock.release()
            return False
        else:
            # print("The block is valid")
            # update pending transactions
            # else:
                # we called add_block on ourselves
                # probabl;y do nothing else
            # readd mining_transactions to pending maybe
            
            if self.is_mining and id is not self.id:
                self.recieved_new_block = True
                # self.mining_thread.terminate()
                if len(self.mining_transactions) > 0:
                    self.pending_transactions = self.mining_transactions[1:] + self.pending_transactions
                    self.mining_transactions = []

            #     # if receive block from someone else
            #     self.mining_thread.stop()
            #     temp store pending and mining transactions
            #     set those to []
                
            #     for transaction in self.mining_transactions:
            #         self.add_transaction(transaction) if valid
            #     for transaciton in pending:
            #         self.add_transactin(transation) if valid
            self.blockchain.append(newblock)
            # update the metadata
            self.update_metadata(newblock, self.blockchain, self.cur_coins_from_issuer, self.cur_coins_from_voter)
            self.lock.release()
            return True

    def RPC_add_block(self, newblock):
        for node in self.nodes:
            print(newblock)
            newblock = pickle.dumps(newblock)
            node.add_block(newblock, self.id)
            # t1 = threading.Thread(target=node.add_block,args=(newblock, self.id))
            # t1.start()

    def get_blockchain(self):
        return pickle.dumps(self.blockchain)

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
                    if(not self.verify_transaction(transaction, coins_from_issuer, coins_from_voter, [], self.blockchain)):
                        group.remove(k-cur)
                        return False
                #check block.roothash
                tmp_MerkleTree = MerkleTree(logic_block.transactions)
                if(tmp_MerkleTree.get_hash!=logic_block.block.root_hash):
                    group.remove(k-cur)
                    return False
            
            cur = cur+len_gp

        # self.coins_from_issuer = coins_from_issuer
        # self.coins_from_voter = coins_from_voter

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
        num_zeros = int(self.blockchain[0].block.num_zeros)
        if hash[-num_zeros:] == '0'*num_zeros:
            return True
        return False




    def mining(self):
        # self.recieved_new_block
        self.lock.acquire()
        self.is_mining = True
        nonce = 0
        pre_hash = self.blockchain[-1].block.to_hash()
        # print("About to make block in mining")
        reward_transaction = Transaction((0,1), self.public, None, self.private)
        # print("After making reward transaction")
        to_remove = []
        for transaction in self.pending_transactions:
            if self.verify_transaction(transaction, self.cur_coins_from_issuer, self.cur_coins_from_voter, self.mining_transactions, self.blockchain):
                self.mining_transactions.append(transaction)
            to_remove.append(transaction)
            if len(self.mining_transactions) == self.transactions_per_block:
                break
        for t in to_remove:
            self.pending_transactions.remove(t)
        # print('Length of pending transactions after removing elements in mining(): ', len(self.pending_transactions))
        if len(self.mining_transactions) < self.transactions_per_block:
            self.pending_transactions = self.mining_transactions
            self.mining_transactions = []
            self.is_mining = False
            self.lock.release()
            return
            # verify transaction again with maybe a side pending transactions list

        self.mining_transactions = [reward_transaction] + self.mining_transactions
        # self.pending_transactions = self.pending_transactions[self.transactions_per_block:]
        # # print('The length of the mining_transactions is: ', len(self.mining_transactions))
        # self.pending_transactions.insert(0, reward_transaction)
        # make a new list of mining transactions
        # # print("After prepending transaction")
        newblock = LogicalBlock(pre_hash, len(self.blockchain), self.mining_transactions, hex2(nonce))
        self.lock.release()
        # print("Made block in mining")
        while(not self.recieved_new_block): #not self.recieved_new_block):
            if(self.interrupt_mining==1):
                nonce=0
                # print("About to call to_hash")
                pre_hash = self.blockchain[len(self.blockchain)-1].block.to_hash()
                # print("About to call new block", pre_hash)

                newblock = LogicalBlock(pre_hash, len(self.blockchain), self.mining_transactions, hex2(nonce))
                self.interrupt_mining = 0

            #newblock = LogicalBlock(pre_hash, len(self.blockchain), self.pending_transactions, nonce)
            # print("About to call build_block")
            newblock.block = newblock.build_block_data(hex2(nonce))
            if(self.check_hash(newblock.block.to_hash())): # and not self.recieved_new_block):
                # print("Inisde the if statement", self.nodes, newblock.__dict__)
                # set miningtransactios to empty list
                # acquire lock
                # other.add_block()
                if not self.add_block(newblock,self.id):
                    self.lock.acquire()
                    self.pending_transactions = self.mining_transactions[1:] + self.pending_transactions
                    self.mining_transactions = []
                    self.lock.release()
                    break
                # print("About to call rpc add block")
                self.RPC_add_block(newblock)
                # print("After RPC add block")
                self.interrupt_mining = 1
                self.mining_transactions = []
                break 
            nonce = self.getnext(nonce)
        if self.recieved_new_block:
            self.recieved_new_block = False
        # print('Size of pending transactions after done mining: ',len(self.pending_transactions))
        if len(self.pending_transactions) >= self.transactions_per_block: # and not self.recieved_new_block:
            self.mining()
        self.is_mining = False

pro = ProcessNode(None,[],0,"", {}, {'issuer_address':'http://localhost:12345/ISSUER'})
