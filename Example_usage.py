from double_helix_chain import DoubleHelixChain

chain = DoubleHelixChain()

for i in range(5):
    tx = chain.add_transaction_block(
        [{"sender": f"user{i}", "receiver": f"user{i+1}", "amount": i * 10}]
    )
    chain.add_validation_block([tx.hash])

chain.verify_integrity()
