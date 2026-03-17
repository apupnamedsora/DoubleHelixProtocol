import hashlib
import json
import time
from typing import List, Dict


class TransactionBlock:
    def __init__(self, index, transactions, prev_hash, paired_hash, meta):
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
        tx_str = "".join([json.dumps(tx, sort_keys=True) for tx in self.transactions])
        return hashlib.sha256(tx_str.encode()).hexdigest()

    def compute_hash(self):
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "transactions": self.transactions,
                "prev_hash": self.prev_hash,
                "paired_hash": self.paired_hash,
                "merkle_root": self.merkle_root,
                "nonce": self.nonce,
                "meta": self.meta,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(block_string).hexdigest()


class ValidationBlock:
    def __init__(self, index, prev_hash, paired_hash, validation_proofs, meta):
        self.index = index
        self.timestamp = time.time()
        self.prev_hash = prev_hash
        self.paired_hash = paired_hash
        self.validation_proofs = validation_proofs
        self.nonce = 0
        self.meta = meta
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "prev_hash": self.prev_hash,
                "paired_hash": self.paired_hash,
                "validation_proofs": self.validation_proofs,
                "nonce": self.nonce,
                "meta": self.meta,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(block_string).hexdigest()


class DoubleHelixChain:
    def __init__(self):
        self.strandA = []
        self.strandB = []

        genesis_tx = TransactionBlock(0, [], "0" * 64, "0" * 64, {"priority": "normal"})
        genesis_val = ValidationBlock(0, "0" * 64, genesis_tx.hash, [], {"priority": "normal"})

        genesis_tx.paired_hash = genesis_val.hash

        self.strandA.append(genesis_tx)
        self.strandB.append(genesis_val)

    def add_transaction_block(self, transactions, meta={"priority": "normal"}):
        prevA = self.strandA[-1]
        prevB = self.strandB[-1]

        new_block = TransactionBlock(
            prevA.index + 1,
            transactions,
            prevA.hash,
            prevB.hash,
            meta,
        )

        self.strandA.append(new_block)
        return new_block

    def add_validation_block(self, validation_proofs, meta={"priority": "normal"}):
        prevA = self.strandA[-1]
        prevB = self.strandB[-1]

        new_block = ValidationBlock(
            prevB.index + 1,
            prevB.hash,
            prevA.hash,
            validation_proofs,
            meta,
        )

        self.strandB.append(new_block)
        return new_block

    def verify_integrity(self):
        for a, b in zip(self.strandA, self.strandB):
            if a.paired_hash != b.hash or b.paired_hash != a.hash:
                print("Integrity failure")
                return False

        print("Double Helix Chain valid")
        return True


if __name__ == "__main__":
    chain = DoubleHelixChain()

    tx = chain.add_transaction_block(
        [{"sender": "Alice", "receiver": "Bob", "amount": 10}]
    )

    chain.add_validation_block([tx.hash])

    chain.verify_integrity()
