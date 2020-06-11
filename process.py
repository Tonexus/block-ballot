import xmlrpc.client
import threading
import pickle
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from block import LogicalBlock, GenesisBlock
from merkle import MerkleTree
from transaction import Transaction
import putil

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
            if i == node_id:
                self.nodes.append(None)
            else:
                self.nodes.append(xmlrpc.client.ServerProxy(node_addresses[i], allow_none=True))

        # wallet metadata on blockchain
        self.cur_coins_from_issuer = {}
        self.cur_coins_from_voter = {}
        print('My id is: ', node_id)
        self.id = node_id

        self.issuer = xmlrpc.client.ServerProxy(config['issuer_address'], allow_none=True)
        self.issuer_id = issuer_id
        self.voters_map = voters_map

        self.pending_transactions = []

        self.lock = threading.Lock()
        self.nodes_lock = threading.Lock()

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

        # try setting blockchain if someone else already online
        for node in self.nodes:
            if node is not None:
                try:
                    other_bc = node.get_blockchain()
                    if len(other_bc) > len(self.blockchain) and other_bc[0].block.to_hash() == self.blockchain[0].to_hash():
                        coins_from_issuer, coins_from_voter = putil.valid_blockchain(other_bc)
                        if coins_from_issuer is not None:
                            self.blockchain = other_bc
                            self.cur_coins_from_issuer = coins_from_issuer
                            self.cur_coins_from_voter = coins_from_voter
                except:
                    pass

    #get a voter's public key
    def get_pkey(self, id):
        if self.voters_map[id] is None:
            self.voters_map[id] = self.issuer.get_pkey(id)
        return self.voters_map[id]

    def set_genesis(self, public_key, num_zeros, num_transactions):
        pk_bytes = bytes.fromhex(public_key)
        public_key = load_pem_public_key(pk_bytes, backend=default_backend())
        self.genesis_block = GenesisBlock(public_key, "", num_zeros, DEFAULT_TRANSACTIONS_PER_BLOCK + 1)
        logical_block = LogicalBlock("", 0, None, None)
        logical_block.block = self.genesis_block
        self.blockchain = [logical_block]
        self.blockheaders = []

        # wallet metadata on blockchain
        self.cur_coins_from_issuer = {}
        self.cur_coins_from_voter = {}

        self.pending_transactions = []

        self.interrupt_mining = 1
        self.issuer_id = public_key
        self.transactions_per_block = num_transactions
        self.mining_thread = None
        if self.mining_thread:
            self.mining_thread.terminate() # BAD
        self.mining_thread = None
        self.is_mining = False
        self.mining_transactions = []
        self.recieved_new_block = False
        print("End of set genesis block, length of blockchain should be 1 but is: ", len(self.blockchain))      

    #other process nodes or Issuer can call this
    #if the blockchain is verified, update self.blockchain with it
    #else let the caller update their with self.blockchain
    def update_blockchain(self, blockchain, id):
        #lock here
        self.lock.acquire()

        dic1, dic2 = putil.valid_blockchain(blockchain)
        if dic1 is not None and dic2 is not None:
            self.interrupt_mining=1
            self.blockchain = blockchain
            self.cur_coins_from_issuer = dic1
            self.cur_coins_from_voter = dic2
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

    #can call by other process nodes or just this node 
    def add_transaction(self, transaction, id):
        #lock here
        self.lock.acquire()
        # print(transaction)
        # print("Type of transaction: ",type(transaction))
        transaction = pickle.loads(transaction.data)
        # print("After pickle.load")
        if putil.valid_transaction(transaction, self.blockchain, self.cur_coins_from_issuer, []):
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
        print('Inside add_block and my id is: ', self.id, ': The id that called this is: ', id)
        if id != self.id:
            newblock = pickle.loads(newblock.data)
            print(newblock)
            # print(pickle.loads(newblock))
        print("Length of self.blockchain: ", len(self.blockchain))
        if not putil.valid_block(newblock, self.blockchain, self.cur_coins_from_issuer):
            if id == self.id:
                print('The block was not valid and we called it on ourselves.')
                self.lock.release()
                return False
            print('The block was not valid and someone else called it on us.')

            # get their blockchain
            # if theirs is longer then verify and set to ours
            # else i don't care if theyre behind
            # self.nodes_lock.acquire()
            print('The other guy"s address is:', self.node_addresses[id])
            rpc_obj = xmlrpc.client.ServerProxy(self.node_addresses[id], allow_none=True)
            other_bc = pickle.loads(rpc_obj.get_blockchain().data)
            print('Get blockchain has returned')
            # self.nodes_lock.release()
            if len(other_bc) > len(self.blockchain) and other_bc[0].block.to_hash() == self.blockchain[0].block.to_hash():
                coins_from_issuer, coins_from_voter = putil.valid_blockchain(other_bc)
                if coins_from_issuer is None:
                    print('Other persons blockchain was not valid')
                    self.lock.release()
                    return False
                else:
                    print('Other blockchain is valid and longer then us')
                    self.cur_coins_from_issuer = coins_from_issuer
                    self.cur_coins_from_voter = coins_from_voter
                    self.blockchain = other_bc
                    self.lock.release()
                    return True
            print('Other blockchain was not valid or not longer then us')
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
            if id == self.id:
                print('Valid block received from ourselves')
            else:
                print('Valid block recieved from someone else')
            if self.is_mining and id is not self.id:
                print('Recieved valid block from somone else. ID = ', id)
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
            putil.update_metadata(newblock, self.blockchain, self.cur_coins_from_issuer, self.cur_coins_from_voter)
            self.lock.release()
            return True

    def RPC_add_block(self, newblock):
        # self.nodes_lock.acquire()
        newblock = pickle.dumps(newblock)
        for i in range(len(self.node_addresses)):
            if i == self.id:
                continue
            rpc_obj = xmlrpc.client.ServerProxy(self.node_addresses[i], allow_none=True)
            ret = rpc_obj.add_block(newblock, self.id)
            # t1 = threading.Thread(target=node.add_block,args=(newblock, self.id))
            # t1.start()

    def get_blockchain(self):
        print('Get blockchain called')
        return pickle.dumps(self.blockchain)

    #get the len of blockchain and current block hash
    def get_len_hash(self):
        return len(self.blockchain), self.blockchain[len(self.blockchain)-1].block.to_hash()
    
    def get_block_headers(self):
        blockheaders = []
        for logicalblock in self.blockchain:
            blockheaders.append(logicalblock.block)
        return blockheaders

    def verfity_blockheaders(self,blockheaders):
        for i in range(1,len(blockheaders)):
            if(blockheaders[i].prev_hash!=blockheaders[i-1].to_hash()):
                return False
        return True

    def get_block(self, bid):
        return self.blockchain[bid]

    #download and update one block
    def RPC_get_block(self, bid, node):
        self.blockchain[bid] = node.get_block(bid)

    #choose a group of nodes with same len and hash
    #download headers and verify
    #download blocks parellel and verify at the same time
    #if fail, retry
    def headers_first_DL(self, group, len_bc):

        nodes = []
        for i in range(len(self.node_addresses)):
            if i == self.id:
                continue
            rpc_obj = xmlrpc.client.ServerProxy(self.node_addresses[i], allow_none=True)
            nodes.append(rpc_obj)
        
        self.blockheaders = []
        
        flag = 0
        for id in group:
            blockheaders = nodes[id].get_block_headers()
            if(self.verfity_blockheaders(blockheaders)):
                flag = 1
            else:
                group.remove(id)

        if(flag==0):
            return False

        self.blockchain = [None for i in range(len_bc)]
        coins_from_issuer={}
        coins_from_voter={}
        len_gp = len(group)

        #cur = 1

        t = []
        for i in range(0,len_bc,len_gp):
            for j in range(len_gp):
                if(i+j>=len_bc):
                    break
                t[j] = threading.Thread(self.RPC_get_block,(i,nodes[group[j]]))
                t[j].start()

            for j in range(len_gp):
                t[j].join()

            end = min(i+len_gp, len_bc)
            #check pointers
            for k in range(i, end):
                if(k==0):
                    if not isinstance(self.blockchain[0].block, GenesisBlock):
                        group.remove(group[k-i])
                        return False
                if(k!=0 and self.blockchain[k].prev_block_hash!=self.blockchain[k-1].block.to_hash()):
                    group.remove(group[k-i])
                    return False

            for k in range(i, end):
                logic_block = self.blockchain[k]
                #check blocks
                if not putil.valid_block(logic_block, self.blockchain[:k], coins_from_issuer):
                    group.remove(k-i)
                    return False
                else:
                    putil.update_metadata(logic_block, self.blockchain[:k], coins_from_issuer, coins_from_voter)
                #check block.roothash
                # tmp_MerkleTree = MerkleTree(logic_block.transactions)
                # if tmp_MerkleTree.get_hash() != logic_block.block.root_hash:
                #     group.remove(k-i)
                #     return False

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

        self.lock.acquire()
        nodes = []
        for i in range(len(self.node_addresses)):
            if i == self.id:
                continue
            rpc_obj = xmlrpc.client.ServerProxy(self.node_addresses[i], allow_none=True)
            nodes.append(rpc_obj)

        len_hash_map = {}
        len_hash_list = []
        for i in range(len(nodes)):
            t_len, t_hash = nodes[i].get_len_hash()
            key = str(t_len)+"::"+str(t_hash)
            if(key not in len_hash_map):
                len_hash_map[key] = []
            len_hash_map[key].append(i)

        for key in len_hash_map.keys():
            strs = key.split("::")
            len_hash_list.append([strs[0],strs[1]])

        len_hash_list.sort(reverse=True, key=lambda x:x[0]) 

        for group_key in len_hash_list:
            if(self.blockchain is not None and int(group_key[0])<=len(self.blockchain)):
                break
            key = group_key[0]+"::"+group_key[1]
            group = len_hash_map[key]

            while(len(group)!=0):
                if(self.headers_first_DL(group, int(group_key[0]))):
                    self.lock.release()
                    return True

        self.lock.release()
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
        return self.blockchain[block_id].tree.get_hash_path(transaction_id)

    #return hash of (hash1, hash2)
    def test_hash_path(self, hash1, hash2):
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(bytes.fromhex(hash1))
        digest.update(bytes.fromhex(hash2))
        return digest.finalize().hex()

    def get_transaction_position(self, transaction_hash):

        for i in range(len(self.blockchain)):
            transactions = self.blockchain[i].block.transacitons
            if transactions is not None:
                for j in range(len(transactions)):
                    if(transactions[j].to_hash()==transaction_hash):
                        return i,j

        return None, None                

    #Simplified Payment Verification
    #1.just loadload headers and hash path of the transacton in the Merkle tree
    #2.verify them, if half of the nodes succeed, return True
    def SPV_transaction(self, block_id, transaction_id, transaction_hash):
        nodes = []
        for i in range(len(self.node_addresses)):
            if i == self.id:
                continue
            rpc_obj = xmlrpc.client.ServerProxy(self.node_addresses[i], allow_none=True)
            nodes.append(rpc_obj)
        
        con_cnt = 0
        spv_cnt = 0
        cur_hash  = transaction_hash
        for node in nodes:
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

        if(spv_cnt*2>=con_cnt):
            return True
        else:
            return False        

    def getnext(self,nonce):
        return nonce + 1 % (1 << 32)
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
        nonce = random.randint(0, 1 << 32)
        pre_hash = self.blockchain[-1].block.to_hash()
        # print("About to make block in mining")
        reward_transaction = Transaction((0,1), self.public, None, self.private)
        # print("After making reward transaction")
        to_remove = []
        self.mining_transactions = []
        for transaction in self.pending_transactions:
            if putil.valid_transaction(transaction, self.blockchain, self.cur_coins_from_issuer, self.mining_transactions):
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
            if(self.check_hash(newblock.block.to_hash()) and not self.recieved_new_block):
                # print("Inisde the if statement", self.nodes, newblock.__dict__)
                # set miningtransactios to empty list
                # acquire lock
                # other.add_block()
                if not self.add_block(newblock, self.id):
                    self.lock.acquire()
                    self.pending_transactions = self.mining_transactions[1:] + self.pending_transactions
                    self.mining_transactions = []
                    self.lock.release()
                    break
                print("About to call rpc add block", newblock)
                self.RPC_add_block(newblock)
                print("After RPC add block")
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
