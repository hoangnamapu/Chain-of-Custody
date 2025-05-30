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
    print(f"ERROR (in checkin.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def is_valid_owner_password(password: str) -> bool:
    """Checks if the provided password matches any of the allowed owner passwords."""
    # Get owner passwords from environment variables
    allowed_passwords = {
        os.getenv("BCHOC_PASSWORD_POLICE"),
        os.getenv("BCHOC_PASSWORD_LAWYER"),
        os.getenv("BCHOC_PASSWORD_ANALYST"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
        os.getenv("BCHOC_PASSWORD_CREATOR")  # Creator can also checkin items
    }
    # Remove None values (for env vars that weren't set)
    allowed_passwords.discard(None)
    
    return password in allowed_passwords

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
                if block_data and block_data.get('state_str') != "INITIAL":
                    block_item_id = block_data.get('decrypted_item_id')
                    if block_item_id is not None and block_item_id == item_id_int:
                        # Process as needed
                        pass
                if block_data:
                    block_count += 1
                    
                    # Check if this block is for our item
                    block_data = unpack_block(full_block_bytes) # Call the modified unpack_block

                # Use the pre-decrypted values from unpack_block
                if block_data and block_data.get('state_str') != "INITIAL":
                    block_item_id = block_data.get('decrypted_item_id') # Get decrypted ID (int or None)

                    if block_item_id is not None and block_item_id == item_id_int:
                        item_exists = True
                        current_state = block_data.get('state_str') # Get latest state
                        # Get the case ID (use decrypted if available)
                        if case_id is None:
                            case_id = block_data.get('decrypted_case_uuid')
                        # Get the creator (only need the first time)
                        if creator is None:
                            creator = block_data.get('creator_str')

                if block_data:
                    block_count += 1 # Increment block count regardless of item match
                
                last_block_hash = block_hash
                current_pos += block_size
                
    except Exception as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
        
    return last_block_hash, current_state, case_id, creator, item_exists, block_count

def handle_checkin(args):
    """Handles the 'bchoc checkin' command to check in an evidence item."""
    provided_password = args.p
    item_id_str = args.i
    
    # Validate the provided password
    if not is_valid_owner_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)
    
    # Get blockchain file path from environment
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot checkin item.", file=sys.stderr)
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
    
    # Check if the item is already in CHECKEDIN state
    if current_state == "CHECKEDIN":
        print(f"Error: Item ID '{item_id_int}' is already checked in.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the item has already been removed
    if current_state in ["DISPOSED", "DESTROYED", "RELEASED"]:
        print(f"Error: Item ID '{item_id_int}' has been {current_state.lower()}. Cannot checkin.", file=sys.stderr)
        sys.exit(1)
    
    # Add a new block with CHECKEDIN state
    try:
        with open(blockchain_file_path, 'ab') as f:
            # Get the owner role from the provided password (Ensure uppercase)
            owner_role = None
            if provided_password == os.getenv("BCHOC_PASSWORD_POLICE"):
                owner_role = "POLICE" # Uppercase
            elif provided_password == os.getenv("BCHOC_PASSWORD_LAWYER"):
                owner_role = "LAWYER" # Uppercase
            elif provided_password == os.getenv("BCHOC_PASSWORD_ANALYST"):
                owner_role = "ANALYST" # Uppercase
            elif provided_password == os.getenv("BCHOC_PASSWORD_EXECUTIVE"):
                owner_role = "EXECUTIVE" # Uppercase
            elif provided_password == os.getenv("BCHOC_PASSWORD_CREATOR"):
                # If creator password used, assign a default OWNER role in uppercase.
                # Using POLICE as a sensible default if the role exists.
                if os.getenv("BCHOC_PASSWORD_POLICE"):
                    owner_role = "POLICE"
                elif os.getenv("BCHOC_PASSWORD_LAWYER"):
                    owner_role = "LAWYER"
                elif os.getenv("BCHOC_PASSWORD_ANALYST"):
                    owner_role = "ANALYST"
                elif os.getenv("BCHOC_PASSWORD_EXECUTIVE"):
                    owner_role = "EXECUTIVE"
                else:
                    # Fallback if no standard owner roles are defined (unlikely)
                    owner_role = "POLICE" # Using POLICE as a placeholder default
            # Note: The original code had a "Creator" default, which is not in ALLOWED_OWNERS.
            # The logic above assigns a valid OWNER role instead when the creator performs checkin.

            # Create a new block
            new_block = Block(
                previous_hash=last_block_hash,
                case_id=case_id,
                evidence_item_id=item_id_int,
                state="CHECKEDIN",
                creator=creator,
                owner=owner_role,
                data=b'',
                aes_key=PROJECT_AES_KEY
            )
            
            # Write the block to the file
            f.write(new_block.pack())
            
            # Output confirmation message
            print(f"> Case: {case_id}")
            print(f"> Checked in item: {item_id_int}")
            print(f"> Status: CHECKEDIN")
            print(f"> Time of action: {new_block.get_timestamp_iso()}")
            
    except Exception as e:
        print(f"Error creating checkin block: {e}", file=sys.stderr)
        sys.exit(1)
    
    sys.exit(0)
