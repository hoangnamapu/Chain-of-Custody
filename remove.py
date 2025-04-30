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
=======
import uuid
import struct
import hashlib
from datetime import datetime, timezone
import Data_Struct

try:
    from Data_Struct import (
        PROJECT_AES_KEY, encrypt_aes_ecb, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES, Block,
        STATE_SIZE, CREATOR_SIZE, OWNER_SIZE, PREV_HASH_SIZE, EVIDENCE_ID_SIZE,
        BLOCK_HEADER_FORMAT
    )
except ImportError as e:
    print(f"ERROR (in remove.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def is_valid_creator_password(password: str) -> bool:
    """Checks if the provided password matches the creator's password from environment variable."""
    # Get creator password from environment variable
    creator_password = os.getenv("BCHOC_PASSWORD_CREATOR")
    if creator_password is None:
        # This is a configuration error - the creator password env var should be set.
        print("CRITICAL: BCHOC_PASSWORD_CREATOR environment variable not set. Cannot validate creator password.", file=sys.stderr)
        sys.exit(1)  # Exit with critical error if creator password isn't configured

    return password == creator_password

def get_last_block_and_item_state(filepath, item_id_int):
    """
    Finds the last block hash and the current state of the specified item.
    
    Returns a tuple of:
    - last_block_hash: The hash of the last block in the chain
    - current_state: The current state of the item
    - case_id: The case ID associated with the item
    - creator: The original creator of the item
    - item_exists: Boolean indicating if the item exists in the chain
    """
    last_block_hash = b'\x00' * 32  # Default for empty chain
    current_state = None
    case_id = None
    creator = None
    item_exists = False
    block_count = 0
    
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return last_block_hash, current_state, case_id, creator, item_exists, block_count
        
        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            current_pos = 0
            
            while current_pos < file_size:
                f.seek(current_pos)
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                
                if len(header_bytes) < BLOCK_HEADER_SIZE:
                    break
                    
                unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                declared_data_len = unpacked_header[7]
                
                # Calculate total block size
                block_size = BLOCK_HEADER_SIZE + declared_data_len
                
                # Read the full block
                f.seek(current_pos)
                full_block_bytes = f.read(block_size)
                
                # Hash this block for the next block's prev_hash field
                block_hash = hashlib.sha256(full_block_bytes).digest()
                
                # Unpack block data
                block_data = unpack_block(full_block_bytes)
                if block_data:
                    block_count += 1
                    
                    # Check if this block is for our item
                    try:
                        # The evidence ID is stored as a hex string in unpack_block
                        encrypted_evidence_id = block_data['encrypted_evidence_id']
                        evidence_id_bytes = bytes.fromhex(encrypted_evidence_id) if isinstance(encrypted_evidence_id, str) else encrypted_evidence_id
                        
                        # Only use the first 16 bytes (AES block size)
                        evidence_id_bytes = evidence_id_bytes[:16] if len(evidence_id_bytes) >= 16 else evidence_id_bytes
                        
                        decrypted_padded_bytes = decrypt_aes_ecb(PROJECT_AES_KEY, evidence_id_bytes)
                        original_bytes = decrypted_padded_bytes[:4]
                        if len(original_bytes) < 4:
                            raise ValueError("Decrypted bytes insufficient for integer conversion")
                        
                        block_item_id = int.from_bytes(original_bytes, 'big')
                        
                        if block_item_id == item_id_int:
                            item_exists = True
                            current_state = block_data['state_str']
                            
                            # Get the case ID
                            if case_id is None:
                                try:
                                    encrypted_case_id = block_data['encrypted_case_id']
                                    if len(encrypted_case_id) >= 16:
                                        uuid_bytes = encrypted_case_id[:16]
                                        case_id = uuid.UUID(bytes=uuid_bytes)
                                except Exception:
                                    pass
                            
                            # Get the creator
                            if creator is None:
                                creator = block_data['creator_str']
                    except Exception:
                        # Skip this block if decryption fails
                        pass
                
                last_block_hash = block_hash
                current_pos += block_size
                
    except Exception as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
        
    return last_block_hash, current_state, case_id, creator, item_exists, block_count

def handle_remove(args):
    """Handles the 'bchoc remove' command to remove an evidence item."""
    provided_password = args.p
    item_id_str = args.i
    reason = args.why  # Note: Using why instead of y
    owner_info = getattr(args, 'owner', None)  # Optional owner info
    
    # Validate the provided password (must be creator's password)
    if not is_valid_creator_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)
    
    # Get blockchain file path from environment
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot remove item.", file=sys.stderr)
        sys.exit(1)
    
    # Validate item ID (must be an integer)
    try:
        item_id_int = int(item_id_str)
        if not (0 <= item_id_int < 2**32):
            print(f"Error: Item ID '{item_id_str}' is out of the valid 4-byte unsigned integer range.", file=sys.stderr)
            sys.exit(1)
    except ValueError:
        print(f"Error: Invalid item ID format: '{item_id_str}'. Must be an integer.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the blockchain file exists
    if not os.path.exists(blockchain_file_path):
        print(f"Error: Blockchain file '{blockchain_file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    # Find the last block and the item's current state
    last_block_hash, current_state, case_id, creator, item_exists, block_count = get_last_block_and_item_state(
        blockchain_file_path, item_id_int
    )
    
    # Check if the item exists in the blockchain
    if not item_exists:
        print(f"Error: Item ID '{item_id_int}' does not exist in the blockchain.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the item is in CHECKEDIN state (requirement for removal)
    if current_state != "CHECKEDIN":
        print(f"Error: Item ID '{item_id_int}' is not in CHECKEDIN state. Cannot remove.", file=sys.stderr)
        sys.exit(1)
    
    # Validate reason (should be one of DISPOSED, DESTROYED, or RELEASED)
    if reason not in ["DISPOSED", "DESTROYED", "RELEASED"]:
        print(f"Error: Invalid reason '{reason}'. Must be one of DISPOSED, DESTROYED, or RELEASED.", file=sys.stderr)
        sys.exit(1)
    
    # If reason is RELEASED, owner info must be provided
    if reason == "RELEASED" and not owner_info:
        print("Error: Owner information (-o) must be provided when reason is RELEASED.", file=sys.stderr)
        sys.exit(1)
        
    # Set owner role based on the removal reason
    owner_role = ""
    if reason == "RELEASED" and owner_info:
        owner_role = "Police"  # Default owner for RELEASED items
    
    # Add a new block with the removal state
    try:
        with open(blockchain_file_path, 'ab') as f:
            # Create data for the block (owner info if provided)
            data = owner_info.encode('utf-8') if owner_info else b''
            
            # Create a new block
            new_block = Block(
                previous_hash=last_block_hash,
                case_id=case_id,
                evidence_item_id=item_id_int,
                state=reason,  # Use the reason (DISPOSED, DESTROYED, or RELEASED)
                creator=creator,
                owner=owner_role,  # Use determined owner role
                data=data,
                aes_key=PROJECT_AES_KEY
            )
            
            # Write the block to the file
            f.write(new_block.pack())
            
            # Output confirmation message
            print(f"> Case: {case_id}")
            print(f"> Removed item: {item_id_int}")
            print(f"> Reason: {reason}")
            if owner_info:
                print(f"> Owner: {owner_info}")
            print(f"> Time of action: {new_block.get_timestamp_iso()}")
            
    except Exception as e:
        print(f"Error creating removal block: {e}", file=sys.stderr)
        sys.exit(1)
    
    sys.exit(0)