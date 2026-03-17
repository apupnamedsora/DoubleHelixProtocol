from double_helix_protocol import DoubleHelixProtocol


def run_demo():
    print("\n🧬 Initializing Double Helix Protocol...\n")

    protocol = DoubleHelixProtocol(
        difficulty_a=2,
        difficulty_b=2,
        use_threads=False  # safer for your environment
    )

    # -------------------------
    # Mining Phase
    # -------------------------
    print("⛏️ Mining paired blocks...\n")

    for i in range(1, 6):
        txs = [
            {
                "sender": f"user{i}",
                "receiver": f"user{i+1}",
                "amount": i * 7
            }
        ]

        tx_block, val_block = protocol.mine_pair(
            transactions=txs,
            validation_proofs=[f"proof-{i}"]
        )

        print(
            f"Pair #{tx_block.index} | "
            f"A: {tx_block.hash[:12]}... | "
            f"B: {val_block.hash[:12]}..."
        )

    # -------------------------
    # Integrity Check
    # -------------------------
    print("\n🔍 Checking integrity...")
    protocol.verify()

    # -------------------------
    # Introduce Corruption
    # -------------------------
    print("\n⚠️ Introducing corruption...")

    # Break pairing on one block
    protocol.corrupt_val_block(2, "paired_hash", "X" * 64)

    # Break transaction data on another
    protocol.corrupt_tx_block(3, "transactions", [{"sender": "evil", "amount": 9999}])

    # -------------------------
    # Detect Mismatches
    # -------------------------
    print("\n🧠 Detecting mismatches...\n")

    mismatches = protocol.detect_mismatches()

    if not mismatches:
        print("No mismatches detected (suspiciously perfect...)")
    else:
        for m in mismatches:
            print(
                f"Index {m['index']} | "
                f"pair_ok={m['pair_ok']} | "
                f"A_ok={m['a_ok']} | "
                f"B_ok={m['b_ok']} | "
                f"A_conf={m['a_confidence']} | "
                f"B_conf={m['b_confidence']}"
            )

    # -------------------------
    # Repair Phase
    # -------------------------
    print("\n🛠️ Attempting repair...\n")

    results = protocol.auto_repair()

    for r in results:
        print(r)

    # -------------------------
    # Final Integrity Check
    # -------------------------
    print("\n🔎 Final integrity check...")
    protocol.verify()

    # -------------------------
    # Quarantine Report
    # -------------------------
    print("\n☣️ Quarantine log:")

    if not protocol.quarantine:
        print("No blocks quarantined. System healed successfully.")
    else:
        for item in protocol.quarantine:
            print(item)


# -------------------------
# Entry Point
# -------------------------

if __name__ == "__main__":
    run_demo()
