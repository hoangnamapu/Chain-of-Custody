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

            case_id = decrypt_case_id_static(block['encrypted_case_id'], PROJECT_AES_KEY)
            if case_id:
                case_ids.add(str(case_id))

    for cid in sorted(case_ids):
        print(cid)
