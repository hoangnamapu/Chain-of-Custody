import os
import sys
import uuid
from Data_Struct import (
    PROJECT_AES_KEY, decrypt_aes_ecb,
    unpack_block, Block, BLOCK_HEADER_SIZE, ALLOWED_OWNERS
)

def decrypt_case_id_static(encrypted: bytes, key: bytes) -> uuid.UUID:
    decrypted = decrypt_aes_ecb(key, encrypted[:16])
    return uuid.UUID(bytes=decrypted)

def decrypt_evidence_id_static(encrypted: bytes, key: bytes) -> int:
    decrypted = decrypt_aes_ecb(key, encrypted[:16])
    return int.from_bytes(decrypted[:4], 'big')

def handle_remove(args):
    try:
        evidence_id_input = int(args.i)
    except ValueError:
        print("ERROR: Evidence ID must be an integer.", file=sys.stderr)
        sys.exit(1)

    removal_state = args.why.upper()
    if removal_state not in ("DISPOSED", "DESTROYED", "RELEASED"):
        print(f"ERROR: Invalid removal reason '{removal_state}'.", file=sys.stderr)
        sys.exit(1)

    owner = args.o if args.o else "Police"
    if removal_state == "RELEASED":
        if not args.o:
            print("ERROR: Owner must be provided when reason is RELEASED.", file=sys.stderr)
            sys.exit(1)
        if owner not in ALLOWED_OWNERS:
            print(f"ERROR: Invalid owner '{owner}' for RELEASED.", file=sys.stderr)
            sys.exit(1)

    file_path = os.getenv("BCHOC_FILE_PATH")
    if not file_path or not os.path.exists(file_path):
        print("ERROR: BCHOC_FILE_PATH not set or file missing.", file=sys.stderr)
        sys.exit(1)

    # Load entire chain
    blocks = []
    with open(file_path, 'rb') as f:
        while True:
            header = f.read(BLOCK_HEADER_SIZE)
            if not header or len(header) < BLOCK_HEADER_SIZE:
                break
            data_length = int.from_bytes(header[-4:], 'little')
            data = f.read(data_length)
            full_block = header + data
            block = unpack_block(full_block)
            if block:
                blocks.append(block)

    # Filter by evidence ID
    matching_blocks = []
    for block in blocks:
        try:
            eid = decrypt_evidence_id_static(block['encrypted_evidence_id'], PROJECT_AES_KEY)
            if eid == evidence_id_input:
                matching_blocks.append(block)
        except:
            continue

    if not matching_blocks:
        print("ERROR: No matching evidence ID found.", file=sys.stderr)
        sys.exit(1)

    # Find latest block in hash chain
    hash_map = {hashlib.sha256(b['raw_bytes']).digest(): b for b in matching_blocks}
    head = None
    for b in matching_blocks:
        if all(b['raw_bytes'] != other['previous_hash'] for other in matching_blocks):
            head = b
    if not head:
        print("ERROR: Could not find tip of hash chain for this item.", file=sys.stderr)
        sys.exit(1)

    current_state = head['state_str'].upper()
    if current_state in ("DISPOSED", "DESTROYED", "RELEASED"):
        print("ERROR: Item already removed.", file=sys.stderr)
        sys.exit(1)

    try:
        new_block = Block(
            previous_hash=hashlib.sha256(head['raw_bytes']).digest(),
            case_id=decrypt_case_id_static(head['encrypted_case_id'], PROJECT_AES_KEY),
            evidence_item_id=evidence_id_input,
            state=removal_state,
            creator=os.getenv("BCHOC_CREATOR", "unknown"),
            owner=owner,
            data=f"Removed with reason {removal_state}".encode('utf-8')
        )
    except Exception as e:
        print(f"ERROR: Failed to create remove block: {e}", file=sys.stderr)
        sys.exit(1)

    with open(file_path, 'ab') as f:
        f.write(new_block.pack())

    print("Remove complete.")
