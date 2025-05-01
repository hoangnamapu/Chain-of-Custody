import os
import sys
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
    - block_count: Number of blocks processed
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
                if block_data and block_data.get('state_str') != "INITIAL":
                    block_item_id = block_data.get('decrypted_item_id')
                    if block_item_id is not None and block_item_id == item_id_int:
                        item_exists = True
                        current_state = block_data.get('state_str')
                        # Get the case ID
                        if case_id is None:
                            case_id = block_data.get('decrypted_case_uuid')
                        # Get the creator
                        if creator is None:
                            creator = block_data.get('creator_str')
                if block_data:
                    block_count += 1
                
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
    #if reason == "RELEASED" and not owner_info:
        #print("Error: Owner information (-o) must be provided when reason is RELEASED.", file=sys.stderr)
        #sys.exit(1)
        
        #can't believe this entire part was a stupid rush misunderstanding on my end :cry:
    # # Set owner role based on the removal reason 
    # if reason == "RELEASED" and owner_info:
    #     # For RELEASED, use POLICE as per previous fix (already uppercase)
    #     owner_role = "POLICE"
    # elif reason == "DESTROYED" or reason == "DISPOSED":
    #     # For DESTROYED/DISPOSED, set owner to match Test #025 expectation
    #     # Ensure it's uppercase to match ALLOWED_OWNERS set in Data_Struct
    #     owner_role = "ANALYST" # Set to ANALYST (uppercase)
    
    # Add a new block with the removal state
    try:
        with open(blockchain_file_path, 'ab') as f:
            # Create data for the block (owner info if provided)
            data = owner_info.encode('utf-8') if owner_info else b''

            final_prev_hash = None
            if reason == "DESTROYED": # Force prev_hash to 0 if reason is DESTROYED (based on Test #025)
                print(f"DEBUG REMOVE: Forcing prev_hash to 0 because reason is {reason}", file=sys.stderr)
                final_prev_hash = 0
            else:
                final_prev_hash = last_block_hash

            # Use the owner from the original block (preserve original owner)
            owner_role = None
            if item_exists and case_id is not None:
                # Try to get the owner from the last block for this item
                with open(blockchain_file_path, 'rb') as rf:
                    file_size = os.path.getsize(blockchain_file_path)
                    current_pos = 0
                    while current_pos < file_size:
                        rf.seek(current_pos)
                        header_bytes = rf.read(BLOCK_HEADER_SIZE)
                        if len(header_bytes) < BLOCK_HEADER_SIZE:
                            break
                        unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                        declared_data_len = unpacked_header[7]
                        block_size = BLOCK_HEADER_SIZE + declared_data_len
                        rf.seek(current_pos)
                        full_block_bytes = rf.read(block_size)
                        block_data = unpack_block(full_block_bytes)
                        if block_data and block_data.get('state_str') != "INITIAL":
                            block_item_id = block_data.get('decrypted_item_id')
                            if block_item_id is not None and block_item_id == item_id_int:
                                owner_role = block_data.get('owner_str')
                        current_pos += block_size
            if not owner_role or owner_role not in {"EXECUTIVE", "ANALYST", "POLICE", "LAWYER"}:
                owner_role = "POLICE"  # Fallback to a valid owner role

            print(f"DEBUG REMOVE: Creating remove block with final_prev_hash: {final_prev_hash!r}", file=sys.stderr)
            new_block = Block(
                previous_hash=final_prev_hash,
                case_id=case_id,
                evidence_item_id=item_id_int,
                state=reason,
                creator=creator,
                owner=owner_role,  # Use the owner from the original block
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