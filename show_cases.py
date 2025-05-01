import os
import sys
import uuid
import struct
import Data_Struct

try:
    from Data_Struct import (
        PROJECT_AES_KEY, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES, ALLOWED_OWNERS
    )
except ImportError as e:
    print(f"ERROR (in show_cases.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def is_valid_password(password: str) -> bool:
    #Checks if the provided password matches any allowed owner/creator password from environment variables.
    allowed_passwords = {
        os.getenv("BCHOC_PASSWORD_POLICE"),
        os.getenv("BCHOC_PASSWORD_LAWYER"),
        os.getenv("BCHOC_PASSWORD_ANALYST"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
    }
    allowed_passwords.discard(None)
    return password in allowed_passwords

def handle_show_cases(args):
    #Handles the 'bchoc show cases' command.
    #Requires a valid owner password.
    #Lists all unique decrypted case IDs found in the blockchain.
    # provided_password = args.p

    # if not is_valid_password(provided_password):
    #     print("Invalid password", file=sys.stderr)
    #     sys.exit(1)

    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot show cases.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(blockchain_file_path):
        print("Blockchain file not found. No cases to show.")
        sys.exit(0)

    unique_case_ids = set()

    try:
        with open(blockchain_file_path, 'rb') as f:
            file_size = os.path.getsize(blockchain_file_path)
            current_pos = 0

            while current_pos < file_size:
                # Read header to determine block size
                f.seek(current_pos)
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE:
                    break  # End of file or corrupt

                try:
                    unpacked_header = struct.unpack(Data_Struct.BLOCK_HEADER_FORMAT, header_bytes)
                    declared_data_len = unpacked_header[7]
                except Exception:
                    break  # Corrupt header, stop processing

                block_size = Data_Struct.BLOCK_HEADER_SIZE + declared_data_len

                f.seek(current_pos)
                full_block_bytes = f.read(block_size)
                if len(full_block_bytes) != block_size:
                    print(f"ERROR SHOW_CASES: Read {len(full_block_bytes)}, expected {block_size}", file=sys.stderr)
                    break  # Stop processing

                # Unpack using Data_Struct's function which attempts decryption
                block_data = Data_Struct.unpack_block(full_block_bytes)

                if block_data and block_data.get('state_str') != "INITIAL":
                    # Get the potentially decrypted Case ID from the unpack result
                    decrypted_case_uuid = block_data.get('decrypted_case_uuid')

                    if decrypted_case_uuid is not None:
                        # Add successfully decrypted UUIDs to the set
                        unique_case_ids.add(decrypted_case_uuid)

                current_pos += block_size

    except IOError as e:
        print(f"Error: Failed to read blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
        sys.exit(1)
    except (ValueError, struct.error) as e:
        print(f"Error processing blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while processing blockchain blocks: {e}", file=sys.stderr)
        sys.exit(1)

    # After the loop and sorting
    sorted_case_ids = sorted(list(unique_case_ids))
    for case_uuid in reversed(sorted_case_ids):
        print(case_uuid)

    sys.exit(0)