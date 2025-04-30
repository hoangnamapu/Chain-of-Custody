# checkin.py

import os
import sys
from datetime import datetime, timezone
from Data_Struct import (
    unpack_block, Block,
    BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES
)

def handle_checkin(args):
    print(f"Executing: checkin (Item: {args.i})")

    file_path = os.getenv("BCHOC_FILE_PATH")
    if not file_path or not os.path.exists(file_path):
        print("ERROR: File not found", file=sys.stderr)
        sys.exit(1)

    # Read all existing blocks
    with open(file_path, 'rb') as f:
        blocks = []
        while chunk := f.read(BLOCK_HEADER_SIZE + AES_BLOCK_SIZE_BYTES):
            block = unpack_block(chunk)
            blocks.append(block)

    # Find latest state of the item
    found = False
    for b in reversed(blocks):
        if b.evidence_id == args.i:
            if b.state == "remove":
                print("ERROR: Cannot checkin an item that has been removed.", file=sys.stderr)
                sys.exit(1)
            elif b.state != "checkout":
                print("ERROR: Cannot checkin unless last state is 'checkout'.", file=sys.stderr)
                sys.exit(1)
            found = True
            break

    if not found:
        print("ERROR: No matching checked-out record for this evidence.", file=sys.stderr)
        sys.exit(1)

    prev_block = blocks[-1]

    new_block = Block(
        case_id=b.case_id,
        evidence_id=b.evidence_id,
        state="checkin",
        owner=args.o,
        creator=os.getenv("BCHOC_CREATOR", "unknown"),
        timestamp=datetime.now(timezone.utc),
        prev_hash=prev_block.hash_block()
    )

    with open(file_path, 'ab') as f:
        f.write(new_block.serialize())

    print("Checkin completed successfully.")
