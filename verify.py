import os
import sys
import hashlib
import struct
from Data_Struct import Block, unpack_block, BLOCK_HEADER_SIZE, BLOCK_HEADER_FORMAT, PREV_HASH_SIZE

def calculate_block_hash(block_bytes: bytes) -> bytes:
    # Compute SHA-256 hash of a block (used for prev_hash linkage).
    return hashlib.sha256(block_bytes).digest()

def verify():
    filepath = os.getenv("BCHOC_FILE_PATH")
    if not filepath:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot verify.", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(filepath):
        print("> Blockchain file not found.")
        print("> Transactions in blockchain: 0")
        print("State of blockchain: CLEAN")
        sys.exit(0)

    blocks_bytes = []
    try:
        with open(filepath, "rb") as f:
            file_size = os.path.getsize(filepath)
            current_pos = 0
            while current_pos < file_size:
                f.seek(current_pos)
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE:
                    if current_pos + len(header_bytes) == file_size:
                        break
                    else:
                        print(f"ERROR (File corruption): Incomplete header found at offset {current_pos}.", file=sys.stderr)
                        sys.exit(1)
                try:
                    unpacked_header_partial = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                    declared_data_len = unpacked_header_partial[7]
                except struct.error:
                    print(f"ERROR (File corruption): Cannot unpack header at offset {current_pos}.", file=sys.stderr)
                    sys.exit(1)
                block_size = BLOCK_HEADER_SIZE + declared_data_len
                if current_pos + block_size > file_size:
                    print(f"ERROR (File corruption): Block data incomplete at offset {current_pos}.", file=sys.stderr)
                    sys.exit(1)
                f.seek(current_pos)
                full_block_bytes = f.read(block_size)
                blocks_bytes.append(full_block_bytes)
                current_pos += block_size
    except IOError as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during file reading: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"> Transactions in blockchain: {len(blocks_bytes)}")

    prev_block_hash_expected = b'\x00' * PREV_HASH_SIZE  # Genesis block
    seen_parent_hashes = set()

    # Allowed states for state validation
    valid_states = {
        "INITIAL", "CHECKEDIN", "CHECKEDOUT",
        "DISPOSED", "DESTROYED", "RELEASED"
    }

    for i in range(len(blocks_bytes)):
        curr_block_bytes = blocks_bytes[i]
        curr_block_hash = calculate_block_hash(curr_block_bytes)
        curr_block_data = unpack_block(curr_block_bytes)
        if curr_block_data is None:
            print("ERROR")
            print(f"> Bad block: {curr_block_hash.hex()}")
            print(f"> Unpacking failed for this block bytes.", file=sys.stderr)
            print("State of blockchain: ERROR")
            sys.exit(1)

        # Rule 1: prev_hash must match
        if curr_block_data['previous_hash'] != prev_block_hash_expected:
            print("ERROR")
            print(f"> Bad block: {curr_block_hash.hex()}")
            print("> Parent block: NOT FOUND")
            print("State of blockchain: ERROR")
            sys.exit(1)

        # Rule 2: No duplicate prev_hash (except genesis)
        if curr_block_data['previous_hash'] in seen_parent_hashes:
            if not (i == 0 and curr_block_data['previous_hash'] == b'\x00' * PREV_HASH_SIZE):
                print("ERROR")
                print(f"> Bad block: {curr_block_hash.hex()}")
                print("> Two blocks were found with the same parent.")
                print("State of blockchain: ERROR")
                sys.exit(1)

        if curr_block_data['previous_hash'] != b'\x00' * PREV_HASH_SIZE:
            seen_parent_hashes.add(curr_block_data['previous_hash'])

        # Rule 3: Data length must match actual payload length
        if not curr_block_data['data_valid']:
            print("ERROR")
            print(f"> Bad block: {curr_block_hash.hex()}")
            print("> Block contents do not match block checksum.")
            print("State of blockchain: ERROR")
            sys.exit(1)

        # Rule 4: State must be one of the allowed values
        if curr_block_data['state_str'] not in valid_states and curr_block_data['state_str'] != "INITIAL":
            print("ERROR")
            print(f"> Bad block: {curr_block_hash.hex()}")
            print(f"> Invalid state '{curr_block_data['state_str']}' found.", file=sys.stderr)
            print("State of blockchain: ERROR")
            sys.exit(1)

        # Rule 5: Timestamp should be non-negative float (sanity check)
        if curr_block_data['timestamp_float'] < 0:
            print("ERROR")
            print(f"> Bad block: {curr_block_hash.hex()}")
            print(f"> Invalid negative timestamp ({curr_block_data['timestamp_float']}) found.", file=sys.stderr)
            print("State of blockchain: ERROR")
            sys.exit(1)

        prev_block_hash_expected = curr_block_hash

    print("State of blockchain: CLEAN")
    sys.exit(0)