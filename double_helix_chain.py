import hashlib
import json
import time
from typing import List, Dict

# -------------------------
# Block Classes
# -------------------------

class TransactionBlock:
    def __init__(self, index: int, transactions: List[Dict], prev_hash: str, paired_hash: str, meta: Dict):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.paired_hash = paired_hash
        self.nonce = 0
        self.meta = meta
        self.merkle_root = self.compute_merkle_root()
        self.hash = self.compute_hash()

    def compute_merkle_root(self):
        tx_str = ''.join([json.dumps(tx, sort_keys=True) for tx in self.transactions])
        return hashlib.sha256(tx_str.encode()).hexdigest()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "prev_hash": self.prev_hash,
            "paired_hash": self.paired_hash,
            "merkle_root": self.merkle_root,
            "nonce": self.nonce,
            "meta": self.meta
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


class ValidationBlock:
    def __init__(self, index: int, prev_hash: str, paired_hash: str, validation_proofs: List[str], meta: Dict):
        self.index = index
        self.timestamp = time.time()
        self.prev_hash = prev_hash
        self.paired_hash = paired_hash
        self.validation_proofs = validation_proofs
        self.nonce = 0
        self.meta = meta
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "paired_hash": self.paired_hash,
            "validation_proofs": self.validation_proofs,
            "nonce": self.nonce,
            "meta": self.meta
        }, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()


# -------------------------
# Double Helix Chain
# -------------------------

class DoubleHelixChain:
    def __init__(self):
        self.strandA: List[TransactionBlock] = []
        self.strandB: List[ValidationBlock] = []
        # Initialize genesis blocks
        genesis_tx = TransactionBlock(0, [], "0"*64, "0"*64, {"priority":"normal"})
        genesis_val = ValidationBlock(0, "0"*64, genesis_tx.hash, [], {"priority":"normal"})
        genesis_tx.paired_hash = genesis_val.hash
        self.strandA.append(genesis_tx)
        self.strandB.append(genesis_val)

    def add_transaction_block(self, transactions: List[Dict], meta: Dict = {"priority":"normal"}):
        prevA = self.strandA[-1]
        prevB = self.strandB[-1]
        new_block = TransactionBlock(prevA.index+1, transactions, prevA.hash, prevB.hash, meta)
        self.strandA.append(new_block)
        return new_block

    def add_validation_block(self, validation_proofs: List[str], meta: Dict = {"priority":"normal"}):
        prevA = self.strandA[-1]
        prevB = self.strandB[-1]
        new_block = ValidationBlock(prevB.index+1, prevB.hash, prevA.hash, validation_proofs, meta)
        self.strandB.append(new_block)
        return new_block

    def verify_integrity(self):
        # Cross-strand verification
        for a_block, b_block in zip(self.strandA, self.strandB):
            if a_block.paired_hash != b_block.hash or b_block.paired_hash != a_block.hash:
                print(f"Integrity fail at Block {a_block.index}")
                return False
        print("Double Helix Chain is valid!")
        return True


# -------------------------
# Example Usage
# -------------------------

if __name__ == "__main__":
    chain = DoubleHelixChain()

    # Add some transactions
    tx_block = chain.add_transaction_block([{"sender":"Alice","receiver":"Bob","amount":10}])
    val_block = chain.add_validation_block([tx_block.hash])

    # Add another pair
    tx_block2 = chain.add_transaction_block([{"sender":"Charlie","receiver":"Dave","amount":25}])
    val_block2 = chain.add_validation_block([tx_block2.hash])

    # Verify chain
    chain.verify_integrity()
