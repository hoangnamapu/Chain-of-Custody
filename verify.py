import os
import hashlib
import struct
from Data_Struct import Block #, BLOCK_SIZE, unpack_block Commented this out, issues w/ how it was done. Fixing code otherwise.

def hash_block(block_bytes):
    """Compute SHA-256 hash of a block (used for prev_hash linkage)."""
    return hashlib.sha256(block_bytes).digest()

def verify():
    filepath = os.getenv("BCHOC_FILE_PATH", "blockchain.dat")

    if not os.path.exists(filepath):
        print("> Blockchain file not found.")
        exit(1)

    blocks = []

    try:
        with open(filepath, "rb") as f:
            while True:
                block_bytes = f.read(Block.BLOCK_SIZE)
                if not block_bytes or len(block_bytes) < Block.BLOCK_SIZE:
                    break
                blocks.append(block_bytes)
    except Exception as e:
        print("> Failed to read blockchain file:", e)
        exit(1)

    print(f"> Transactions in blockchain: {len(blocks)}")

    prev_hash = b'\x00' * 32  # Genesis block
    seen_hashes = set()

    valid_states = {
        "INITIAL", "CHECKEDIN", "CHECKEDOUT",
        "DISPOSED", "DESTROYED", "RELEASED"
    }

    for i in range(len(blocks)):
        curr_block_bytes = blocks[i]
        curr_block = Block.unpack_block(curr_block_bytes)
        curr_hash = hash_block(curr_block_bytes)

        # Rule 1: prev_hash must match
        if curr_block.prev_hash != prev_hash:
            print("ERROR")
            print(curr_hash.hex())
            exit(1)

        # Rule 2: No duplicate prev_hash (except genesis)
        if curr_block.prev_hash in seen_hashes and i != 0:
            print("ERROR")
            print(curr_hash.hex())
            exit(1)

        # Rule 3: Data length must match actual payload length
        data_valid = (len(curr_block.data_payload) == curr_block.declared_data_len)
        if not data_valid:
            print("ERROR")
            print(curr_hash.hex())
            exit(1)

        # Rule 4: State must be one of the allowed values
        if curr_block.state.strip() not in valid_states:
            print("ERROR")
            print(curr_hash.hex())
            exit(1)

        # Rule 5: Timestamp should be non-negative float (sanity check)
        if curr_block.timestamp < 0:
            print("ERROR")
            print(curr_hash.hex())
            exit(1)

        seen_hashes.add(curr_block.prev_hash)
        prev_hash = curr_hash

    print("State of blockchain: CLEAN")
    exit(0)
