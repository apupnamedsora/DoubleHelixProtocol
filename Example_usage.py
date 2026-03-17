from double_helix_chain import DoubleHelixChain

chain = DoubleHelixChain(difficulty_a=2, difficulty_b=2)

for i in range(5):
    txs = [
        {
            "sender": f"user{i}",
            "receiver": f"user{i+1}",
            "amount": (i + 1) * 5,
        }
    ]
    chain.mine_paired_blocks(
        transactions=txs,
        validation_proofs=[f"validation-proof-{i}"],
    )

print("Before corruption:")
chain.verify_integrity()

chain.corrupt_tx_block(3, "paired_hash", "BAD" * 21 + "B")

print("\nDetected mismatches:")
for item in chain.detect_mismatches():
    print(item)

print("\nRepairing...")
for result in chain.auto_repair():
    print(result)

print("\nAfter repair:")
chain.verify_integrity()

print("\nQuarantine:")
print(chain.quarantine)
