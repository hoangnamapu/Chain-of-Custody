import os
import sys
import uuid
import hashlib
from datetime import datetime, timezone
from Data_Struct import (
    decrypt_aes_ecb,
    unpack_block, Block, BLOCK_HEADER_SIZE
)

def derive_key_from_password(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()

def decrypt_case_id_static(encrypted: bytes, key: bytes) -> uuid.UUID:
    decrypted = decrypt_aes_ecb(key, encrypted[:16])
    return uuid.UUID(bytes=decrypted)

def decrypt_evidence_id_static(encrypted: bytes, key: bytes) -> int:
    decrypted = decrypt_aes_ecb(key, encrypted[:16])
    return int.from_bytes(decrypted[:4], 'big')

def handle_checkout(args):
    try:
        evidence_id_input = int(args.i)
    except ValueError:
        print("ERROR: Evidence ID must be an integer.", file=sys.stderr)
        sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH")
    if not file_path or not os.path.exists(file_path):
        print("ERROR: BCHOC_FILE_PATH not set or file missing.", file=sys.stderr)
        sys.exit(1)

    key = derive_key_from_password(args.p)
    latest_block = None

    with open(file_path, 'rb') as f:
        while True:
            block_bytes = f.read(BLOCK_HEADER_SIZE)
            if not block_bytes or len(block_bytes) < BLOCK_HEADER_SIZE:
                break
            data_length = int.from_bytes(block_bytes[-4:], 'little')
            data = f.read(data_length)
            block_dict = unpack_block(block_bytes + data)
            if block_dict is None:
                continue
            try:
                eid = decrypt_evidence_id_static(block_dict['encrypted_evidence_id'], key)
                if eid == evidence_id_input:
                    latest_block = block_dict
            except Exception:
                continue

    if not latest_block:
        print("ERROR: No matching evidence ID.", file=sys.stderr)
        sys.exit(1)

    state = latest_block['state_str'].upper()
    if state == "CHECKEDOUT":
        print("ERROR: Already checked out.", file=sys.stderr)
        sys.exit(1)
    elif state in ("DISPOSED", "DESTROYED", "RELEASED"):
        print("ERROR: Cannot checkout a removed item.", file=sys.stderr)
        sys.exit(1)
    elif state not in ("ADDED", "CHECKEDIN"):
        print("ERROR: Invalid state for checkout.", file=sys.stderr)
        sys.exit(1)

    try:
        new_block = Block(
            previous_hash=latest_block['previous_hash'],
            case_id=decrypt_case_id_static(latest_block['encrypted_case_id'], key),
            evidence_item_id=evidence_id_input,
            state="CHECKEDOUT",
            creator=os.getenv("BCHOC_CREATOR", "unknown"),
            owner="Police",
            data=b"Checked out",
            aes_key=key  # Make sure your Block class accepts this
        )
    except Exception as e:
        print(f"ERROR: Failed to create new block: {e}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, 'ab') as f:
        f.write(new_block.pack())

    print("Checkout complete.")
