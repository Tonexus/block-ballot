import json

class Transaction:
    def __init__(self, src_block, src_transact, dst_addr):
        # id of source block of transaction
        self.src_block = src_block
        self.src_transact = src_transact
        self.dst_addr = dst_addr

    def to_string(self, blockchain, prv_key):
        self_dict = {
            "dst_addr": self.dst_addr,
            # can actually be whatever if signature is that of issuer
            "hash": blockchain[self.src_block].get_transaction(self.src_transact),
            "signature": prv_key.sign("Something")
        }
        return json.dumps(self_dict)
