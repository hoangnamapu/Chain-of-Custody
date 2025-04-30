import os
import sys
import uuid
from Data_Struct import (
    unpack_block,
    decrypt_aes_ecb,
    AES_BLOCK_SIZE_BYTES,
    PROJECT_AES_KEY,
    BLOCK_HEADER_SIZE
)

def decrypt_case_id_static(encrypted: bytes, key: bytes) -> uuid.UUID | None:
    try:
        # Only take first 16 bytes (actual AES ciphertext)
        decrypted = decrypt_aes_ecb(key, encrypted[:AES_BLOCK_SIZE_BYTES])
        return uuid.UUID(bytes=decrypted)
    except Exception:
        return None

def handle_show_cases(args):
    file_path = os.getenv("BCHOC_FILE_PATH")
    if not file_path or not os.path.exists(file_path):
        print("ERROR: BCHOC_FILE_PATH not set or file not found.", file=sys.stderr)
        sys.exit(1)

    case_ids = set()

    with open(file_path, 'rb') as f:
        while True:
            header = f.read(BLOCK_HEADER_SIZE)
            if not header or len(header) < BLOCK_HEADER_SIZE:
                break

            data_len = int.from_bytes(header[-4:], 'little')
            data = f.read(data_len)
            block_bytes = header + data

            block = unpack_block(block_bytes)
            if not block or block['state_str'].upper() == "INITIAL":
                continue

                block_size = BLOCK_HEADER_SIZE + declared_data_len

                if current_pos + block_size > file_size:
                    print(f"Error reading blockchain: Block data incomplete at offset {current_pos}. File may be truncated.", file=sys.stderr)
                    sys.exit(1)

                f.read(declared_data_len)

                f.seek(current_pos)
                full_block_bytes = f.read(block_size)
                block_data = unpack_block(full_block_bytes)

                if block_data and block_data['state_str'] != "INITIAL":
                    encrypted_case_id_padded = block_data['encrypted_case_id']
                    try:
                        # Case IDs are not encrypted, just the first 16 bytes of the padded field
                        try:
                        # Extract the 16-byte ciphertext from the 32-byte padded field
                        ciphertext = encrypted_case_id_padded[:AES_BLOCK_SIZE_BYTES]
                        if len(ciphertext) != AES_BLOCK_SIZE_BYTES:
                             raise ValueError(f"Ciphertext length ({len(ciphertext)}) is not {AES_BLOCK_SIZE_BYTES} for case ID.")

                        # Decrypt using standard AES ECB (handles unpadding)
                        decrypted_bytes = decrypt_aes_ecb(PROJECT_AES_KEY, ciphertext)

                        # The result should be the 16 original UUID bytes
                        if len(decrypted_bytes) != 16:
                            raise ValueError(f"Decrypted case ID length is not 16 bytes ({len(decrypted_bytes)}).")

                        case_uuid = uuid.UUID(bytes=decrypted_bytes)
                        unique_case_ids.add(case_uuid) # Add the UUID object itself
                    except (ValueError, TypeError) as e:
                        # Catch specific decryption/conversion errors
                        print(f"Warning: Skipping block at offset {current_pos} due to Case ID processing error: {e}", file=sys.stderr)
                        pass # Continue to next block
                    except Exception as e:
                        # Catch unexpected errors
                        print(f"Warning: Unexpected error processing case ID in block at offset {current_pos}: {e}", file=sys.stderr)
                        pass # Continue to next block

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


            case_id = decrypt_case_id_static(block['encrypted_case_id'], PROJECT_AES_KEY)
            if case_id:
                case_ids.add(str(case_id))

    for cid in sorted(case_ids):
        print(cid)
