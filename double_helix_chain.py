# /double_helix_chain.py
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# -------------------------
# Core utilities
# -------------------------

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_dumps_sorted(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _canonical_bytes(obj: Any) -> bytes:
    return _json_dumps_sorted(obj).encode("utf-8")


def _meets_difficulty(hash_hex: str, difficulty: int) -> bool:
    if difficulty < 0:
        raise ValueError("difficulty must be >= 0")
    return hash_hex.startswith("0" * difficulty)


def compute_merkle_root(transactions: List[Dict[str, Any]]) -> str:
    """
    Deterministic Merkle root over canonical JSON transactions.

    - Empty => sha256(b"")
    - Odd leaf count => duplicate last
    """
    if not transactions:
        return _sha256_hex(b"")

    leaves = [_sha256_hex(_canonical_bytes(tx)) for tx in transactions]
    while len(leaves) > 1:
        if len(leaves) % 2 == 1:
            leaves.append(leaves[-1])
        nxt: List[str] = []
        for i in range(0, len(leaves), 2):
            nxt.append(_sha256_hex((leaves[i] + leaves[i + 1]).encode("utf-8")))
        leaves = nxt
    return leaves[0]


def dna_complement_proof(merkle_root_hex: str) -> str:
    """
    DNA-like complement encoding:
    - map each hex nibble to A/C/G/T via nibble % 4
    - complement bases: A<->T, C<->G
    """
    base_map = "ACGT"
    comp = {"A": "T", "T": "A", "C": "G", "G": "C"}
    out: List[str] = []
    for ch in merkle_root_hex.lower():
        nib = int(ch, 16)
        out.append(comp[base_map[nib % 4]])
    return "".join(out)


def work_per_block_hex_zeros(difficulty: int) -> int:
    """
    Expected trials for `difficulty` leading hex zeros is 16^difficulty.
    """
    if difficulty < 0:
        raise ValueError("difficulty must be >= 0")
    return 16**difficulty


# -------------------------
# Validator signatures (HMAC threshold)
# -------------------------

@dataclass(frozen=True)
class ValidatorSet:
    """
    Simple threshold authorization using HMAC-SHA256 signatures.

    This is not public-key crypto; it's a deterministic stand-in using shared secrets.
    All verifiers must know the validator secrets to verify signatures.
    """
    secrets: Dict[str, bytes]  # validator_id -> secret key bytes
    threshold: int

    def __post_init__(self) -> None:
        if self.threshold <= 0:
            raise ValueError("threshold must be >= 1")
        if self.threshold > len(self.secrets):
            raise ValueError("threshold cannot exceed number of validators")

    def sign(self, validator_id: str, message: bytes) -> str:
        key = self.secrets[validator_id]
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def verify(self, validator_id: str, message: bytes, signature_hex: str) -> bool:
        key = self.secrets.get(validator_id)
        if key is None:
            return False
        expected = hmac.new(key, message, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature_hex)

    def verify_threshold(self, message: bytes, signatures: Dict[str, str]) -> bool:
        valid = 0
        for vid, sig in signatures.items():
            if self.verify(vid, message, sig):
                valid += 1
            if valid >= self.threshold:
                return True
        return False


# -------------------------
# Chain data structures
# -------------------------

@dataclass
class TransactionBlock:
    index: int
    timestamp: float
    transactions: List[Dict[str, Any]]
    merkle_root: str
    prev_hash: str
    meta: Dict[str, Any]
    nonce: int
    rung_digest: str
    paired_hash: str
    hash: str

    @staticmethod
    def derive_hash(rung_digest: str) -> str:
        return _sha256_hex((rung_digest + "|A").encode("utf-8"))


@dataclass
class ValidationBlock:
    index: int
    timestamp: float
    prev_hash: str
    validation_proofs: List[str]  # [complement_proof, external_proof_0, ...]
    meta: Dict[str, Any]
    nonce: int
    rung_digest: str
    paired_hash: str
    hash: str

    @staticmethod
    def derive_hash(rung_digest: str) -> str:
        return _sha256_hex((rung_digest + "|B").encode("utf-8"))


@dataclass(frozen=True)
class RungInput:
    index: int
    timestamp: float
    prev_hash_a: str
    prev_hash_b: str
    transactions: List[Dict[str, Any]]
    validation_proofs: List[str]
    meta_a: Dict[str, Any]
    meta_b: Dict[str, Any]
    nonce: int

    def to_canonical_dict(self) -> Dict[str, Any]:
        merkle = compute_merkle_root(self.transactions)
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "prev_hash_a": self.prev_hash_a,
            "prev_hash_b": self.prev_hash_b,
            "transactions": self.transactions,
            "merkle_root": merkle,
            "validation_proofs": self.validation_proofs,
            "meta_a": self.meta_a,
            "meta_b": self.meta_b,
            "nonce": self.nonce,
        }


@dataclass(frozen=True)
class MutationCertificate:
    """
    Authorization for a mutation ("DNA repair") at a given rung.
    Stored in strandB external proofs as a canonical JSON string.
    """
    chain_id: str
    target_index: int
    old_a_hash: str
    old_b_hash: str
    new_merkle_root: str
    reason: str
    issued_at: float
    signatures: Dict[str, str]  # validator_id -> signature_hex

    def message_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "target_index": self.target_index,
            "old_a_hash": self.old_a_hash,
            "old_b_hash": self.old_b_hash,
            "new_merkle_root": self.new_merkle_root,
            "reason": self.reason,
            "issued_at": self.issued_at,
        }

    def message_bytes(self) -> bytes:
        return _canonical_bytes(self.message_dict())

    def to_json(self) -> str:
        return _json_dumps_sorted(
            {
                "type": "mutation_certificate",
                **self.message_dict(),
                "signatures": self.signatures,
            }
        )

    @staticmethod
    def from_json(payload: str) -> "MutationCertificate":
        obj = json.loads(payload)
        if obj.get("type") != "mutation_certificate":
            raise ValueError("not a mutation_certificate")
        return MutationCertificate(
            chain_id=obj["chain_id"],
            target_index=int(obj["target_index"]),
            old_a_hash=obj["old_a_hash"],
            old_b_hash=obj["old_b_hash"],
            new_merkle_root=obj["new_merkle_root"],
            reason=obj["reason"],
            issued_at=float(obj["issued_at"]),
            signatures=dict(obj["signatures"]),
        )


# -------------------------
# DNA chain with repair + fitness fork choice
# -------------------------

FitnessFn = Callable[["DoubleHelixDNAChain"], float]


class DoubleHelixDNAChain:
    """
    DNA invariants:
    - Append only as rungs: A[i], B[i] together.
    - Index-aligned pairing: A[i] <-> B[i].
    - Equal length.
    - Complementarity: B.validation_proofs[0] == dna_complement_proof(A.merkle_root).
    - Repair mutations require threshold validator authorization (MutationCertificate).
    """

    def __init__(self, chain_id: str, difficulty_a: int = 0, difficulty_b: int = 0) -> None:
        self.chain_id = chain_id
        self.difficulty_a = difficulty_a
        self.difficulty_b = difficulty_b
        self.strandA: List[TransactionBlock] = []
        self.strandB: List[ValidationBlock] = []
        self._mine_genesis()

    # ---- rung creation ----

    def _build_rung_input(
        self,
        *,
        index: int,
        prev_hash_a: str,
        prev_hash_b: str,
        transactions: List[Dict[str, Any]],
        validation_proofs: List[str],
        meta_a: Dict[str, Any],
        meta_b: Dict[str, Any],
        timestamp: float,
        nonce: int,
    ) -> RungInput:
        return RungInput(
            index=index,
            timestamp=timestamp,
            prev_hash_a=prev_hash_a,
            prev_hash_b=prev_hash_b,
            transactions=transactions,
            validation_proofs=validation_proofs,
            meta_a=meta_a,
            meta_b=meta_b,
            nonce=nonce,
        )

    def _compute_rung_digest(self, rung_in: RungInput) -> Tuple[str, str]:
        d = rung_in.to_canonical_dict()
        merkle_root = d["merkle_root"]
        rung_digest = _sha256_hex(_canonical_bytes(d))
        return rung_digest, merkle_root

    def _materialize_blocks(self, rung_in: RungInput) -> Tuple[TransactionBlock, ValidationBlock]:
        rung_digest, merkle_root = self._compute_rung_digest(rung_in)

        a_hash = TransactionBlock.derive_hash(rung_digest)
        b_hash = ValidationBlock.derive_hash(rung_digest)

        a = TransactionBlock(
            index=rung_in.index,
            timestamp=rung_in.timestamp,
            transactions=rung_in.transactions,
            merkle_root=merkle_root,
            prev_hash=rung_in.prev_hash_a,
            meta=rung_in.meta_a,
            nonce=rung_in.nonce,
            rung_digest=rung_digest,
            paired_hash=b_hash,
            hash=a_hash,
        )
        b = ValidationBlock(
            index=rung_in.index,
            timestamp=rung_in.timestamp,
            prev_hash=rung_in.prev_hash_b,
            validation_proofs=rung_in.validation_proofs,
            meta=rung_in.meta_b,
            nonce=rung_in.nonce,
            rung_digest=rung_digest,
            paired_hash=a_hash,
            hash=b_hash,
        )
        return a, b

    def _rung_meets_pow(self, a: TransactionBlock, b: ValidationBlock) -> bool:
        ok_a = True if self.difficulty_a == 0 else _meets_difficulty(a.hash, self.difficulty_a)
        ok_b = True if self.difficulty_b == 0 else _meets_difficulty(b.hash, self.difficulty_b)
        return ok_a and ok_b

    def _mine_genesis(self) -> None:
        self.mine_pair(
            transactions=[],
            external_proofs=[],
            meta_a={"genesis": True, "priority": "normal"},
            meta_b={"genesis": True, "priority": "normal"},
            timestamp=time.time(),
        )
        self.strandA[0].prev_hash = "0" * 64
        self.strandB[0].prev_hash = "0" * 64
        self._re_mine_from(0)

    def mine_pair(
        self,
        transactions: List[Dict[str, Any]],
        *,
        external_proofs: Optional[List[str]] = None,
        meta_a: Optional[Dict[str, Any]] = None,
        meta_b: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> Tuple[TransactionBlock, ValidationBlock]:
        """
        Atomic rung append.

        Complementarity enforced:
          validation_proofs = [dna_complement_proof(merkle_root)] + external_proofs
        """
        meta_a = dict(meta_a) if meta_a is not None else {"priority": "normal"}
        meta_b = dict(meta_b) if meta_b is not None else {"priority": "normal"}
        external_proofs = list(external_proofs) if external_proofs is not None else []

        idx = len(self.strandA)
        if idx != len(self.strandB):
            raise RuntimeError("Invariant broken: strands must have equal length")

        prev_a = "0" * 64 if idx == 0 else self.strandA[-1].hash
        prev_b = "0" * 64 if idx == 0 else self.strandB[-1].hash
        ts = time.time() if timestamp is None else float(timestamp)

        merkle_root = compute_merkle_root(transactions)
        complement0 = dna_complement_proof(merkle_root)
        proofs = [complement0] + external_proofs

        nonce = 0
        while True:
            rung_in = self._build_rung_input(
                index=idx,
                prev_hash_a=prev_a,
                prev_hash_b=prev_b,
                transactions=transactions,
                validation_proofs=proofs,
                meta_a=meta_a,
                meta_b=meta_b,
                timestamp=ts,
                nonce=nonce,
            )
            a, b = self._materialize_blocks(rung_in)
            if self._rung_meets_pow(a, b):
                self.strandA.append(a)
                self.strandB.append(b)
                return a, b
            nonce += 1

    # ---- repair mutations ("beneficial mutations") ----

    def propose_mutation(
        self,
        validators: ValidatorSet,
        *,
        target_index: int,
        new_transactions: List[Dict[str, Any]],
        reason: str,
        signer_ids: List[str],
        issued_at: Optional[float] = None,
    ) -> MutationCertificate:
        """
        Creates a threshold-signed MutationCertificate.
        """
        if target_index <= 0:
            raise ValueError("refuse to mutate genesis (target_index must be >= 1)")
        if target_index >= len(self.strandA):
            raise IndexError("target_index out of range")

        old_a = self.strandA[target_index]
        old_b = self.strandB[target_index]
        new_merkle = compute_merkle_root(new_transactions)

        issued = time.time() if issued_at is None else float(issued_at)
        msg_obj = {
            "chain_id": self.chain_id,
            "target_index": target_index,
            "old_a_hash": old_a.hash,
            "old_b_hash": old_b.hash,
            "new_merkle_root": new_merkle,
            "reason": reason,
            "issued_at": issued,
        }
        msg_bytes = _canonical_bytes(msg_obj)

        sigs: Dict[str, str] = {}
        for vid in signer_ids:
            sigs[vid] = validators.sign(vid, msg_bytes)

        cert = MutationCertificate(
            chain_id=self.chain_id,
            target_index=target_index,
            old_a_hash=old_a.hash,
            old_b_hash=old_b.hash,
            new_merkle_root=new_merkle,
            reason=reason,
            issued_at=issued,
            signatures=sigs,
        )
        return cert

    def apply_mutation(
        self,
        validators: ValidatorSet,
        *,
        certificate: MutationCertificate,
        new_transactions: List[Dict[str, Any]],
        extra_external_proofs: Optional[List[str]] = None,
    ) -> None:
        """
        Applies an authorized mutation by:
        - verifying certificate matches current rung hashes and new merkle root
        - verifying threshold signatures
        - embedding certificate JSON in B external proofs
        - re-mining from target_index to tip (repair cascade)
        """
        if certificate.chain_id != self.chain_id:
            raise ValueError("certificate chain_id mismatch")
        i = certificate.target_index
        if i <= 0:
            raise ValueError("refuse to mutate genesis")
        if i >= len(self.strandA):
            raise IndexError("target_index out of range")

        a = self.strandA[i]
        b = self.strandB[i]

        if a.hash != certificate.old_a_hash or b.hash != certificate.old_b_hash:
            raise ValueError("certificate does not match current rung hashes")

        new_merkle = compute_merkle_root(new_transactions)
        if new_merkle != certificate.new_merkle_root:
            raise ValueError("new_transactions merkle_root does not match certificate")

        if not validators.verify_threshold(certificate.message_bytes(), certificate.signatures):
            raise ValueError("insufficient valid signatures")

        extra_external_proofs = list(extra_external_proofs) if extra_external_proofs is not None else []

        # Apply: update transactions + stash mutation cert in external proofs on B at same rung.
        self.strandA[i].transactions = new_transactions

        # Preserve existing external proofs (after complement) if any.
        existing_ext = b.validation_proofs[1:] if b.validation_proofs else []
        mutation_payload = certificate.to_json()
        new_external = [mutation_payload] + extra_external_proofs + existing_ext
        # Temporarily set B proofs; _re_mine_from will rebuild complement proof + keep ext.
        self.strandB[i].validation_proofs = [""] + new_external  # placeholder complement

        self._re_mine_from(i)

    def _re_mine_from(self, start_index: int) -> None:
        """
        Re-mines from start_index to tip, fixing prev_hash backbone and re-deriving
        complement proof and rung hashes/PoW.
        """
        for i in range(start_index, len(self.strandA)):
            prev_a = "0" * 64 if i == 0 else self.strandA[i - 1].hash
            prev_b = "0" * 64 if i == 0 else self.strandB[i - 1].hash

            a_old = self.strandA[i]
            b_old = self.strandB[i]
            ts = a_old.timestamp

            # Keep external proofs after complement (index 1+).
            ext = b_old.validation_proofs[1:] if b_old.validation_proofs else []

            nonce = a_old.nonce
            while True:
                merkle = compute_merkle_root(a_old.transactions)
                complement0 = dna_complement_proof(merkle)
                proofs = [complement0] + ext

                rung_in = self._build_rung_input(
                    index=i,
                    prev_hash_a=prev_a,
                    prev_hash_b=prev_b,
                    transactions=a_old.transactions,
                    validation_proofs=proofs,
                    meta_a=a_old.meta,
                    meta_b=b_old.meta,
                    timestamp=ts,
                    nonce=nonce,
                )
                a_new, b_new = self._materialize_blocks(rung_in)
                if self._rung_meets_pow(a_new, b_new):
                    self.strandA[i] = a_new
                    self.strandB[i] = b_new
                    break
                nonce += 1

    # ---- verification ----

    def verify_integrity(self, *, validators: Optional[ValidatorSet] = None) -> bool:
        """
        If validators is provided, mutation certificates found in external proofs
        are verified for threshold signatures and correct targeting.
        """
        if len(self.strandA) != len(self.strandB):
            print("Integrity fail: strands length mismatch.")
            return False
        if not self.strandA:
            print("Integrity fail: empty chain.")
            return False

        for i in range(len(self.strandA)):
            a = self.strandA[i]
            b = self.strandB[i]

            expected_prev_a = "0" * 64 if i == 0 else self.strandA[i - 1].hash
            expected_prev_b = "0" * 64 if i == 0 else self.strandB[i - 1].hash
            if a.prev_hash != expected_prev_a:
                print(f"Integrity fail: strandA prev_hash mismatch at rung {i}.")
                return False
            if b.prev_hash != expected_prev_b:
                print(f"Integrity fail: strandB prev_hash mismatch at rung {i}.")
                return False
            if a.nonce != b.nonce:
                print(f"Integrity fail: nonce mismatch within rung {i}.")
                return False

            merkle = compute_merkle_root(a.transactions)
            if a.merkle_root != merkle:
                print(f"Integrity fail: merkle_root mismatch at rung {i}.")
                return False

            if not b.validation_proofs:
                print(f"Integrity fail: missing validation_proofs at rung {i}.")
                return False

            expected_comp0 = dna_complement_proof(merkle)
            if b.validation_proofs[0] != expected_comp0:
                print(f"Integrity fail: complementarity mismatch at rung {i}.")
                return False

            rung_in = self._build_rung_input(
                index=i,
                prev_hash_a=a.prev_hash,
                prev_hash_b=b.prev_hash,
                transactions=a.transactions,
                validation_proofs=b.validation_proofs,
                meta_a=a.meta,
                meta_b=b.meta,
                timestamp=a.timestamp,
                nonce=a.nonce,
            )
            rung_digest, merkle2 = self._compute_rung_digest(rung_in)
            if merkle2 != merkle:
                print(f"Integrity fail: canonical merkle mismatch at rung {i}.")
                return False

            expected_a_hash = TransactionBlock.derive_hash(rung_digest)
            expected_b_hash = ValidationBlock.derive_hash(rung_digest)

            if a.rung_digest != rung_digest or b.rung_digest != rung_digest:
                print(f"Integrity fail: rung_digest mismatch at rung {i}.")
                return False
            if a.hash != expected_a_hash:
                print(f"Integrity fail: strandA hash mismatch at rung {i}.")
                return False
            if b.hash != expected_b_hash:
                print(f"Integrity fail: strandB hash mismatch at rung {i}.")
                return False

            if a.paired_hash != b.hash or b.paired_hash != a.hash:
                print(f"Integrity fail: paired_hash mismatch at rung {i}.")
                return False

            if self.difficulty_a > 0 and not _meets_difficulty(a.hash, self.difficulty_a):
                print(f"Integrity fail: strandA PoW mismatch at rung {i}.")
                return False
            if self.difficulty_b > 0 and not _meets_difficulty(b.hash, self.difficulty_b):
                print(f"Integrity fail: strandB PoW mismatch at rung {i}.")
                return False

            if validators is not None and i >= 1:
                # Verify any mutation certs in external proofs.
                for ext in b.validation_proofs[1:]:
                    if not isinstance(ext, str):
                        continue
                    if '"type":"mutation_certificate"' not in ext.replace(" ", ""):
                        continue
                    try:
                        cert = MutationCertificate.from_json(ext)
                    except Exception:
                        print(f"Integrity fail: invalid mutation_certificate JSON at rung {i}.")
                        return False
                    if cert.chain_id != self.chain_id or cert.target_index != i:
                        print(f"Integrity fail: mutation_certificate targets wrong chain/rung at {i}.")
                        return False
                    if cert.old_a_hash == a.hash and cert.old_b_hash == b.hash:
                        # Certificate claiming "mutation" but pointing at current hashes is suspicious.
                        # Allow it (can represent a no-op), but it must still be correctly signed.
                        pass
                    if cert.new_merkle_root != a.merkle_root:
                        print(f"Integrity fail: mutation_certificate merkle mismatch at rung {i}.")
                        return False
                    if not validators.verify_threshold(cert.message_bytes(), cert.signatures):
                        print(f"Integrity fail: mutation_certificate signatures invalid at rung {i}.")
                        return False

        print("Double Helix DNA Chain is valid!")
        return True

    # ---- replication & equivalence ----

    def replicate(self) -> "DoubleHelixDNAChain":
        clone = DoubleHelixDNAChain(chain_id=self.chain_id, difficulty_a=self.difficulty_a, difficulty_b=self.difficulty_b)
        clone.strandA = []
        clone.strandB = []
        for a, b in zip(self.strandA, self.strandB):
            clone.strandA.append(
                TransactionBlock(
                    index=a.index,
                    timestamp=a.timestamp,
                    transactions=json.loads(_json_dumps_sorted(a.transactions)),
                    merkle_root=a.merkle_root,
                    prev_hash=a.prev_hash,
                    meta=json.loads(_json_dumps_sorted(a.meta)),
                    nonce=a.nonce,
                    rung_digest=a.rung_digest,
                    paired_hash=a.paired_hash,
                    hash=a.hash,
                )
            )
            clone.strandB.append(
                ValidationBlock(
                    index=b.index,
                    timestamp=b.timestamp,
                    prev_hash=b.prev_hash,
                    validation_proofs=list(b.validation_proofs),
                    meta=json.loads(_json_dumps_sorted(b.meta)),
                    nonce=b.nonce,
                    rung_digest=b.rung_digest,
                    paired_hash=b.paired_hash,
                    hash=b.hash,
                )
            )
        return clone

    def is_equivalent_to(self, other: "DoubleHelixDNAChain") -> bool:
        if (self.chain_id, self.difficulty_a, self.difficulty_b) != (other.chain_id, other.difficulty_a, other.difficulty_b):
            return False
        if len(self.strandA) != len(other.strandA):
            return False
        for (a1, b1), (a2, b2) in zip(zip(self.strandA, self.strandB), zip(other.strandA, other.strandB)):
            if (a1.hash, b1.hash, a1.prev_hash, b1.prev_hash, a1.paired_hash, b1.paired_hash) != (
                a2.hash,
                b2.hash,
                a2.prev_hash,
                b2.prev_hash,
                a2.paired_hash,
                b2.paired_hash,
            ):
                return False
        return True

    # ---- work and fork-choice ----

    def total_work(self) -> int:
        """
        Simple expected-work model: each rung contributes 16^difficulty_a + 16^difficulty_b.
        """
        per_rung = work_per_block_hex_zeros(self.difficulty_a) + work_per_block_hex_zeros(self.difficulty_b)
        return per_rung * len(self.strandA)

    @property
    def tip_timestamp(self) -> float:
        return self.strandA[-1].timestamp

    def score(self, *, fitness_fn: Optional[FitnessFn] = None, fitness_weight: float = 0.0) -> float:
        fitness = float(fitness_fn(self)) if fitness_fn is not None else 0.0
        return float(self.total_work()) + float(fitness_weight) * fitness

    @staticmethod
    def choose_best(
        chains: Iterable["DoubleHelixDNAChain"],
        *,
        fitness_fn: Optional[FitnessFn] = None,
        fitness_weight: float = 0.0,
    ) -> "DoubleHelixDNAChain":
        """
        Fork choice:
          1) highest score = total_work + λ * fitness
          2) then longest (rungs)
          3) then earliest tip timestamp
        """
        chains_list = list(chains)
        if not chains_list:
            raise ValueError("no chains provided")

        def key(c: "DoubleHelixDNAChain") -> Tuple[float, int, float]:
            return (c.score(fitness_fn=fitness_fn, fitness_weight=fitness_weight), len(c.strandA), -c.tip_timestamp)

        return max(chains_list, key=key)


# /tests/test_Double_helix_chain.py
import pytest

from Double_helix_chain import DoubleHelixDNAChain, ValidatorSet


def _validators() -> ValidatorSet:
    return ValidatorSet(
        secrets={
            "v1": b"secret-v1",
            "v2": b"secret-v2",
            "v3": b"secret-v3",
        },
        threshold=2,
    )


def test_authorized_mutation_repair() -> None:
    vals = _validators()
    chain = DoubleHelixDNAChain(chain_id="dna-1", difficulty_a=1, difficulty_b=1)
    chain.mine_pair([{"n": 1}], external_proofs=["app-proof"])
    chain.mine_pair([{"n": 2}], external_proofs=[])

    cert = chain.propose_mutation(
        vals,
        target_index=1,
        new_transactions=[{"n": 999, "benefit": "better"}],
        reason="beneficial mutation",
        signer_ids=["v1", "v2"],
    )
    chain.apply_mutation(vals, certificate=cert, new_transactions=[{"n": 999, "benefit": "better"}])

    assert chain.verify_integrity(validators=vals) is True


def test_unauthorized_mutation_rejected() -> None:
    vals = _validators()
    chain = DoubleHelixDNAChain(chain_id="dna-1", difficulty_a=1, difficulty_b=1)
    chain.mine_pair([{"n": 1}], external_proofs=[])
    chain.mine_pair([{"n": 2}], external_proofs=[])

    cert = chain.propose_mutation(
        vals,
        target_index=1,
        new_transactions=[{"n": 999}],
        reason="attempted mutation",
        signer_ids=["v1"],  # threshold is 2 -> insufficient
    )

    with pytest.raises(ValueError, match="insufficient valid signatures"):
        chain.apply_mutation(vals, certificate=cert, new_transactions=[{"n": 999}])


def test_fork_choice_with_fitness() -> None:
    # Same work, different "fitness": pick higher fitness when weight > 0
    a = DoubleHelixDNAChain(chain_id="dna-1", difficulty_a=1, difficulty_b=1)
    b = DoubleHelixDNAChain(chain_id="dna-1", difficulty_a=1, difficulty_b=1)

    a.mine_pair([{"value": 1}], external_proofs=[])
    b.mine_pair([{"value": 1}], external_proofs=[])

    def fitness_fn(c: DoubleHelixDNAChain) -> float:
        # Prefer chains whose last tx has "benefit": True
        tip_tx = c.strandA[-1].transactions[0]
        return 1.0 if tip_tx.get("benefit") is True else 0.0

    # Make b "fitter"
    b.strandA[-1].transactions[0]["benefit"] = True
    # Re-mine from that rung to make it consistent
    b._re_mine_from(1)

    best = DoubleHelixDNAChain.choose_best([a, b], fitness_fn=fitness_fn, fitness_weight=1000.0)
    assert best is b
