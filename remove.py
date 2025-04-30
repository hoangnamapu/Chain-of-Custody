import os
import sys
from datetime import datetime, timezone
from Data_Struct import (
    PROJECT_AES_KEY, encrypt_aes_ecb, decrypt_aes_ecb,
    unpack_block, Block, BLOCK_HEADER_SIZE,
    STATE_CHECKEDIN, STATE_DISPOSED, STATE_DESTROYED, STATE_RELEASED
)

# Define valid states for removal
VALID_REASONS = {
    "DISPOSED": STATE_DISPOSED,
    "DESTROYED": STATE_DESTROYED,
    "RELEASED": STATE_RELEASED
}

def handle_remove(args):
    try:
        # --- Argument parsing ---
        evidence_id = int(args.i)
        reason = args.why
        password = args.p
        owner_input = args.o

        if reason not in VALID_REASONS:
            print("ERROR: Invalid removal reason.", file=sys.stderr)
            sys.exit(1)

        if reason == "RELEASED" and not owner_input:
            print("ERROR: RELEASED reason requires an owner (-o).", file=sys.stderr)
            sys.exit(1)

        if password != os.getenv("BCHOC_PASSWORD_CREATOR"):
            print("ERROR: Invalid creator password.", file=sys.stderr)
            sys.exit(1)

        file_path = os.getenv("BCHOC_FILE_PATH")
        if not file_path or not os.path.exists(file_path):
            print("ERROR: BCHOC_FILE_PATH not set or file missing.", file=sys.stderr)
            sys.exit(1)

        encrypted_evidence_id = encrypt_aes_ecb(PROJECT_AES_KEY, evidence_id.to_bytes(4, "big"))

        # --- Find the most recent block with matching evidence ID ---
        latest_block = None
        with open(file_path, "rb") as f:
            while True:
                block_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(block_bytes) < BLOCK_HEADER_SIZE:
                    break
                block = unpack_block(block_bytes)
                if block.encrypted_evidence_id[:16] == encrypted_evidence_id[:16]:
                    latest_block = block  # Always update to get latest

        if not latest_block:
            print("ERROR: Evidence ID not found in chain.", file=sys.stderr)
            sys.exit(1)

        if latest_block.state != STATE_CHECKEDIN:
            print("ERROR: Only CHECKEDIN items can be removed.", file=sys.stderr)
            sys.exit(1)

        # --- Prepare new block for removal ---
        removal_state = VALID_REASONS[reason]
        owner_bytes = owner_input.encode() if reason == "RELEASED" else b"\x00" * 12
        timestamp = datetime.now(timezone.utc).timestamp()
        data_field = f"Removed for reason: {reason}".encode()

        new_block = Block(
            prev_hash=latest_block.hash,
            timestamp=timestamp,
            case_id=latest_block.encrypted_case_id,
            evidence_id=latest_block.encrypted_evidence_id,
            state=removal_state,
            creator=latest_block.creator,
            owner=owner_bytes,
            data=data_field
        )

        # --- Append new block to chain ---
        with open(file_path, "ab") as f:
            f.write(new_block.serialize())

        # --- Output for confirmation ---
        print(f"> Evidence item {evidence_id} removed.")
        print(f"> Reason: {reason}")
        print(f"> Time of action: {datetime.now(timezone.utc).isoformat()}")

        sys.exit(0)

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
