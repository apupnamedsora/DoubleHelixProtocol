import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def meets_difficulty(hash_hex: str, difficulty: int) -> bool:
    return hash_hex.startswith("0" * difficulty)


@dataclass
class TransactionBlock:
    index: int
    timestamp: float
    transactions: List[Dict[str, Any]]
    prev_hash: str
    paired_hash: str
    nonce: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)
    merkle_root: str = ""
    hash: str = ""

    def compute_merkle_root(self) -> str:
        if not self.transactions:
            return sha256_hex(b"")
        tx_str = "".join(canonical_json(tx) for tx in self.transactions)
        return sha256_hex(tx_str.encode())

   def payload(self) -> dict:
    return {
        "index": self.index,
        "timestamp": self.timestamp,
        "transactions": self.transactions,
        "prev_hash": self.prev_hash,
        "nonce": self.nonce,
        "merkle_root": self.merkle_root,
        "meta": self.meta,
    }

    def compute_hash(self) -> str:
    return sha256_hex(canonical_json(self.payload()).encode())

def seal(self) -> None:
    self.merkle_root = self.compute_merkle_root()
    self.hash = self.compute_hash()


@dataclass
class ValidationBlock:
    index: int
    timestamp: float
    prev_hash: str
    paired_hash: str
    validation_proofs: List[str]
    nonce: int = 0
    meta: Dict[str, Any] = field(default_factory=dict)
    hash: str = ""

    def payload(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
            "paired_hash": self.paired_hash,
            "validation_proofs": self.validation_proofs,
            "nonce": self.nonce,
            "meta": self.meta,
        }

    def compute_hash(self) -> str:
        return sha256_hex(canonical_json(self.payload()).encode())

    def seal(self) -> None:
        self.hash = self.compute_hash()


class DoubleHelixProtocol:
    """
    DNA-inspired dual-strand protocol with:
    - Strand A: transaction blocks
    - Strand B: validation blocks
    - optional threaded provisional mining
    - final re-mining after cross-linking
    - mismatch detection
    - repair / quarantine logic
    """

    def __init__(
        self,
        difficulty_a: int = 2,
        difficulty_b: int = 2,
        use_threads: bool = False,
    ):
        self.strandA: List[TransactionBlock] = []
        self.strandB: List[ValidationBlock] = []
        self.difficulty_a = difficulty_a
        self.difficulty_b = difficulty_b
        self.use_threads = use_threads
        self.quarantine: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self._create_genesis_pair()

    # -------------------------
    # Genesis
    # -------------------------

    def _create_genesis_pair(self) -> None:
        ts = time.time()

        genesis_tx = TransactionBlock(
            index=0,
            timestamp=ts,
            transactions=[],
            prev_hash="0" * 64,
            paired_hash="GENESIS_B_PLACEHOLDER",
            meta={"priority": "normal", "type": "genesis"},
        )
        genesis_tx.seal()

        genesis_val = ValidationBlock(
            index=0,
            timestamp=ts,
            prev_hash="0" * 64,
            paired_hash=genesis_tx.hash,
            validation_proofs=[genesis_tx.hash],
            meta={"priority": "normal", "type": "genesis"},
        )
        genesis_val.seal()

        genesis_tx.paired_hash = genesis_val.hash
        genesis_tx.seal()

        # Genesis is structural, not mined to difficulty.
        self.strandA.append(genesis_tx)
        self.strandB.append(genesis_val)

    # -------------------------
    # Mining helpers
    # -------------------------

    def _mine_transaction_candidate(
        self,
        index: int,
        prev_hash: str,
        paired_hash: str,
        transactions: List[Dict[str, Any]],
        meta: Dict[str, Any],
        timestamp: float,
        result_box: Dict[str, TransactionBlock],
    ) -> None:
        block = TransactionBlock(
            index=index,
            timestamp=timestamp,
            transactions=transactions,
            prev_hash=prev_hash,
            paired_hash=paired_hash,
            meta=meta,
        )
        block.merkle_root = block.compute_merkle_root()

        while True:
            candidate_hash = block.compute_hash()
            if meets_difficulty(candidate_hash, self.difficulty_a):
                block.hash = candidate_hash
                result_box["tx"] = block
                return
            block.nonce += 1

    def _mine_validation_candidate(
        self,
        index: int,
        prev_hash: str,
        paired_hash: str,
        validation_proofs: List[str],
        meta: Dict[str, Any],
        timestamp: float,
        result_box: Dict[str, ValidationBlock],
    ) -> None:
        block = ValidationBlock(
            index=index,
            timestamp=timestamp,
            prev_hash=prev_hash,
            paired_hash=paired_hash,
            validation_proofs=validation_proofs,
            meta=meta,
        )

        while True:
            candidate_hash = block.compute_hash()
            if meets_difficulty(candidate_hash, self.difficulty_b):
                block.hash = candidate_hash
                result_box["val"] = block
                return
            block.nonce += 1

    def _mine_tx_in_place(self, block: TransactionBlock) -> TransactionBlock:
        block.merkle_root = block.compute_merkle_root()
        while True:
            candidate_hash = block.compute_hash()
            if meets_difficulty(candidate_hash, self.difficulty_a):
                block.hash = candidate_hash
                return block
            block.nonce += 1

    def _mine_val_in_place(self, block: ValidationBlock) -> ValidationBlock:
        while True:
            candidate_hash = block.compute_hash()
            if meets_difficulty(candidate_hash, self.difficulty_b):
                block.hash = candidate_hash
                return block
            block.nonce += 1

    def _remine_transaction_block(self, block: TransactionBlock) -> TransactionBlock:
        block.nonce = 0
        block.merkle_root = block.compute_merkle_root()
        return self._mine_tx_in_place(block)

    def _remine_validation_block(self, block: ValidationBlock) -> ValidationBlock:
        block.nonce = 0
        return self._mine_val_in_place(block)

    # -------------------------
    # Public mining API
    # -------------------------

    def mine_pair(
        self,
        transactions: List[Dict[str, Any]],
        validation_proofs: Optional[List[str]] = None,
        tx_meta: Optional[Dict[str, Any]] = None,
        val_meta: Optional[Dict[str, Any]] = None,
    ) -> Tuple[TransactionBlock, ValidationBlock]:
        tx_meta = tx_meta or {"priority": "normal", "lane": "A"}
        val_meta = val_meta or {"priority": "normal", "lane": "B"}

        with self._lock:
            prevA = self.strandA[-1]
            prevB = self.strandB[-1]
            index = len(self.strandA)

        timestamp = time.time()

        provisional_proofs = validation_proofs or []
        if not provisional_proofs:
            provisional_proofs = [sha256_hex(canonical_json(transactions).encode())]

        if self.use_threads:
            tx_result: Dict[str, TransactionBlock] = {}
            val_result: Dict[str, ValidationBlock] = {}

            tx_thread = threading.Thread(
                target=self._mine_transaction_candidate,
                args=(
                    index,
                    prevA.hash,
                    "PENDING_B",
                    transactions,
                    tx_meta,
                    timestamp,
                    tx_result,
                ),
            )
            val_thread = threading.Thread(
                target=self._mine_validation_candidate,
                args=(
                    index,
                    prevB.hash,
                    "PENDING_A",
                    provisional_proofs,
                    val_meta,
                    timestamp,
                    val_result,
                ),
            )

            tx_thread.start()
            val_thread.start()
            tx_thread.join()
            val_thread.join()

            tx_block = tx_result["tx"]
            val_block = val_result["val"]
        else:
            tx_block = TransactionBlock(
                index=index,
                timestamp=timestamp,
                transactions=transactions,
                prev_hash=prevA.hash,
                paired_hash="PENDING_B",
                meta=tx_meta,
            )
            tx_block.merkle_root = tx_block.compute_merkle_root()
            self._mine_tx_in_place(tx_block)

            val_block = ValidationBlock(
                index=index,
                timestamp=timestamp,
                prev_hash=prevB.hash,
                paired_hash="PENDING_A",
                validation_proofs=provisional_proofs,
                meta=val_meta,
            )
            self._mine_val_in_place(val_block)

        # Cross-link and re-mine so final PoW includes real partner references.
        val_block.paired_hash = tx_block.hash
        val_block = self._remine_validation_block(val_block)

        tx_block.paired_hash = val_block.hash
        tx_block = self._remine_transaction_block(tx_block)

        # Final lock-in pass: ensure B points to final A, then A points to final B.
        val_block.paired_hash = tx_block.hash
        val_block = self._remine_validation_block(val_block)

        tx_block.paired_hash = val_block.hash
        tx_block = self._remine_transaction_block(tx_block)

        with self._lock:
            if tx_block.index != len(self.strandA) or val_block.index != len(self.strandB):
                raise RuntimeError("Chain advanced during mining; retry block pair.")

            self.strandA.append(tx_block)
            self.strandB.append(val_block)

        return tx_block, val_block

    # -------------------------
    # Validation helpers
    # -------------------------

    def _is_valid_tx_block(
        self,
        block: TransactionBlock,
        prev_block: Optional[TransactionBlock],
    ) -> bool:
        if block.hash != block.compute_hash():
            return False

        if block.index != 0 and not meets_difficulty(block.hash, self.difficulty_a):
            return False

        if block.merkle_root != block.compute_merkle_root():
            return False

        if prev_block is None:
            return block.prev_hash == "0" * 64

        return block.prev_hash == prev_block.hash

    def _is_valid_val_block(
        self,
        block: ValidationBlock,
        prev_block: Optional[ValidationBlock],
    ) -> bool:
        if block.hash != block.compute_hash():
            return False

        if block.index != 0 and not meets_difficulty(block.hash, self.difficulty_b):
            return False

        if prev_block is None:
            return block.prev_hash == "0" * 64

        return block.prev_hash == prev_block.hash

    def _tx_confidence(self, index: int) -> int:
        block = self.strandA[index]
        prev_block = self.strandA[index - 1] if index > 0 else None
        score = 0

        if self._is_valid_tx_block(block, prev_block):
            score += 4
        if index < len(self.strandB) and self.strandB[index].paired_hash == block.hash:
            score += 3
        if index < len(self.strandB) and block.paired_hash == self.strandB[index].hash:
            score += 3
        if index + 1 < len(self.strandA) and self.strandA[index + 1].prev_hash == block.hash:
            score += 2
        if block.meta.get("type") == "genesis":
            score += 2

        return score

    def _val_confidence(self, index: int) -> int:
        block = self.strandB[index]
        prev_block = self.strandB[index - 1] if index > 0 else None
        score = 0

        if self._is_valid_val_block(block, prev_block):
            score += 4
        if index < len(self.strandA) and self.strandA[index].paired_hash == block.hash:
            score += 3
        if index < len(self.strandA) and block.paired_hash == self.strandA[index].hash:
            score += 3
        if index + 1 < len(self.strandB) and self.strandB[index + 1].prev_hash == block.hash:
            score += 2
        if block.meta.get("type") == "genesis":
            score += 2

        return score

    # -------------------------
    # Mismatch detection / repair
    # -------------------------

    def detect_mismatches(self) -> List[Dict[str, Any]]:
        mismatches: List[Dict[str, Any]] = []

        max_len = min(len(self.strandA), len(self.strandB))
        for i in range(max_len):
            a = self.strandA[i]
            b = self.strandB[i]

            pair_ok = (a.paired_hash == b.hash) and (b.paired_hash == a.hash)
            a_ok = self._is_valid_tx_block(a, self.strandA[i - 1] if i > 0 else None)
            b_ok = self._is_valid_val_block(b, self.strandB[i - 1] if i > 0 else None)

            if not (pair_ok and a_ok and b_ok):
                mismatches.append(
                    {
                        "index": i,
                        "pair_ok": pair_ok,
                        "a_ok": a_ok,
                        "b_ok": b_ok,
                        "a_confidence": self._tx_confidence(i),
                        "b_confidence": self._val_confidence(i),
                    }
                )

        return mismatches

    def repair_mismatch_at(self, index: int) -> str:
        if index <= 0 or index >= len(self.strandA) or index >= len(self.strandB):
            return f"Cannot repair index {index}"

        a = self.strandA[index]
        b = self.strandB[index]
        prev_a = self.strandA[index - 1]
        prev_b = self.strandB[index - 1]

        a_ok = self._is_valid_tx_block(a, prev_a)
        b_ok = self._is_valid_val_block(b, prev_b)
        a_conf = self._tx_confidence(index)
        b_conf = self._val_confidence(index)

        if a_ok and not b_ok:
            b.prev_hash = prev_b.hash
            b.paired_hash = a.hash
            if not b.validation_proofs:
                b.validation_proofs = [a.hash, a.merkle_root]
            b = self._remine_validation_block(b)
            self.strandB[index] = b

            a.paired_hash = b.hash
            a = self._remine_transaction_block(a)
            self.strandA[index] = a

            self._repair_forward_links_from(index + 1)
            return f"Repaired Strand B at index {index} using Strand A"

        if b_ok and not a_ok:
            a.prev_hash = prev_a.hash
            a.paired_hash = b.hash
            a.merkle_root = a.compute_merkle_root()
            a = self._remine_transaction_block(a)
            self.strandA[index] = a

            b.paired_hash = a.hash
            b = self._remine_validation_block(b)
            self.strandB[index] = b

            self._repair_forward_links_from(index + 1)
            return f"Repaired Strand A at index {index} using Strand B"

        if a_ok and b_ok:
            if a_conf >= b_conf:
                b.paired_hash = a.hash
                b = self._remine_validation_block(b)
                self.strandB[index] = b

                a.paired_hash = b.hash
                a = self._remine_transaction_block(a)
                self.strandA[index] = a

                self._repair_forward_links_from(index + 1)
                return f"Resolved pair mismatch at index {index}; anchored on Strand A"

            a.paired_hash = b.hash
            a = self._remine_transaction_block(a)
            self.strandA[index] = a

            b.paired_hash = a.hash
            b = self._remine_validation_block(b)
            self.strandB[index] = b

            self._repair_forward_links_from(index + 1)
            return f"Resolved pair mismatch at index {index}; anchored on Strand B"

        self.quarantine.append(
            {
                "index": index,
                "reason": "Both strands invalid",
                "a_hash": a.hash,
                "b_hash": b.hash,
                "timestamp": time.time(),
            }
        )
        return f"Quarantined index {index}; both strands invalid"

    def _repair_forward_links_from(self, start_index: int) -> None:
        for i in range(start_index, min(len(self.strandA), len(self.strandB))):
            prev_a = self.strandA[i - 1]
            prev_b = self.strandB[i - 1]
            a = self.strandA[i]
            b = self.strandB[i]

            a.prev_hash = prev_a.hash
            b.prev_hash = prev_b.hash

            b.paired_hash = a.hash
            b = self._remine_validation_block(b)

            a.paired_hash = b.hash
            a = self._remine_transaction_block(a)

            b.paired_hash = a.hash
            b = self._remine_validation_block(b)

            self.strandA[i] = a
            self.strandB[i] = b

    def auto_repair(self) -> List[str]:
        results: List[str] = []
        for mismatch in self.detect_mismatches():
            results.append(self.repair_mismatch_at(mismatch["index"]))
        return results

    # -------------------------
    # Full verification
    # -------------------------

    def verify(self) -> bool:
        if len(self.strandA) != len(self.strandB):
            print("Integrity failure: strand lengths differ")
            return False

        for i, (a_block, b_block) in enumerate(zip(self.strandA, self.strandB)):
            prev_a = self.strandA[i - 1] if i > 0 else None
            prev_b = self.strandB[i - 1] if i > 0 else None

            if not self._is_valid_tx_block(a_block, prev_a):
                print(f"Integrity failure: Strand A block {i} invalid")
                return False

            if not self._is_valid_val_block(b_block, prev_b):
                print(f"Integrity failure: Strand B block {i} invalid")
                return False

            if a_block.paired_hash != b_block.hash:
                print(f"Integrity failure: Strand A block {i} pairing mismatch")
                return False

            if b_block.paired_hash != a_block.hash:
                print(f"Integrity failure: Strand B block {i} pairing mismatch")
                return False

        print("Double Helix Protocol is valid")
        return True

    # -------------------------
    # Corruption helpers
    # -------------------------

    def corrupt_tx_block(self, index: int, field_name: str, new_value: Any) -> None:
        setattr(self.strandA[index], field_name, new_value)

    def corrupt_val_block(self, index: int, field_name: str, new_value: Any) -> None:
        setattr(self.strandB[index], field_name, new_value)


if __name__ == "__main__":
    protocol = DoubleHelixProtocol(
        difficulty_a=2,
        difficulty_b=2,
        use_threads=False,
    )

    print("\nMining paired blocks...\n")
    for i in range(1, 5):
        txs = [
            {
                "sender": f"user{i}",
                "receiver": f"user{i+1}",
                "amount": i * 10,
            }
        ]

        tx_block, val_block = protocol.mine_pair(
            transactions=txs,
            validation_proofs=[f"proof-{i}"],
            tx_meta={"priority": "normal", "lane": "A"},
            val_meta={"priority": "normal", "lane": "B"},
        )

        print(
            f"Mined pair #{tx_block.index} | "
            f"A hash={tx_block.hash[:16]}... | "
            f"B hash={val_block.hash[:16]}..."
        )

    print("\nInitial integrity check:")
    protocol.verify()

    print("\nCorrupting Strand B block 2 paired_hash...")
    protocol.corrupt_val_block(2, "paired_hash", "X" * 64)

    print("\nDetected mismatches:")
    mismatches = protocol.detect_mismatches()
    for mismatch in mismatches:
        print(mismatch)

    print("\nAuto-repair results:")
    for result in protocol.auto_repair():
        print(result)

    print("\nFinal integrity check:")
    protocol.verify()

    print("\nQuarantine log:")
    print(protocol.quarantine)
