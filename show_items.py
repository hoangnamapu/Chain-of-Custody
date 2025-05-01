import os
import sys
import uuid
import struct
import hashlib
import Data_Struct

try:
    from Data_Struct import (
        PROJECT_AES_KEY, encrypt_aes_ecb, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES, Block,
        STATE_SIZE, CREATOR_SIZE, OWNER_SIZE, PREV_HASH_SIZE, EVIDENCE_ID_SIZE,
        BLOCK_HEADER_FORMAT
    )
except ImportError as e:
    print(f"ERROR (in show_items.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def is_valid_owner_password(password: str) -> bool:
    """Checks if the provided password matches any allowed owner passwords."""
    # Get owner passwords from environment variables
    allowed_passwords = {
        os.getenv("BCHOC_PASSWORD_POLICE"),
        os.getenv("BCHOC_PASSWORD_LAWYER"),
        os.getenv("BCHOC_PASSWORD_ANALYST"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
        os.getenv("BCHOC_PASSWORD_CREATOR")
    }
    # Remove None values (for env vars that weren't set)
    allowed_passwords.discard(None)
    
    return password in allowed_passwords

def get_case_items(filepath, case_id_uuid):
    """
    Retrieves all items associated with a specific case ID.
    
    Args:
        filepath: Path to the blockchain file
        case_id_uuid: UUID object for the case to query
        
    Returns:
        set: Set of unique item IDs associated with the case
    """
    unique_items = set()
    
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return unique_items
        
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
                
                # Unpack block data
                block_data = unpack_block(full_block_bytes)
                if block_data and block_data['state_str'] != "INITIAL":
                    try:
                        # Attempt to extract and decrypt the case ID
                        encrypted_case_id = block_data['encrypted_case_id']
                        if len(encrypted_case_id) >= 16:
                            uuid_bytes = encrypted_case_id[:16]
                            block_case_id = uuid.UUID(bytes=uuid_bytes)
                            
                            # Check if this block belongs to our case
                            if block_case_id == case_id_uuid:
                                # Extract and decrypt the item ID
                                # Convert hex string to bytes if necessary
                                # Use Data_Struct's specialized evidence ID decryption function
                                encrypted_evidence_id = block_data['encrypted_evidence_id']
                                item_id = Data_Struct.decrypt_evidence_id_from_packed(encrypted_evidence_id)
                                if item_id is None:
                                    continue
                                
                                # Add to the unique items set
                                unique_items.add(item_id)
                    except Exception:
                        # Skip this block if decryption fails
                        pass
                
                current_pos += block_size
                
    except Exception as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return unique_items

def handle_show_items(args):
    """Handles the 'bchoc show items' command to list all items for a case."""
    case_id_str = args.c
    provided_password = args.p
    
    # Validate the provided password
    if not is_valid_owner_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)
    
    # Get blockchain file path from environment
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot show items.", file=sys.stderr)
        sys.exit(1)
    
    # Parse the case ID
    try:
        case_id_uuid = uuid.UUID(case_id_str)
    except ValueError:
        print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the blockchain file exists
    if not os.path.exists(blockchain_file_path):
        print(f"Blockchain file not found. No items to show.")
        sys.exit(0)
    
    # Get all items for the case
    items = get_case_items(blockchain_file_path, case_id_uuid)
    
    # Print all items, remove debug message
    for item_id in sorted(items):
        print(item_id)
    
    sys.exit(0)
