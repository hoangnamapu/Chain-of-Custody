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
    print(f"ERROR (in show_history.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
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

class HistoryEntry:
    """Class to represent a blockchain history entry with relevant metadata"""
    def __init__(self, case_id, item_id, action, timestamp, position, owner=None):
        self.case_id = case_id
        self.item_id = item_id
        self.action = action
        self.timestamp = timestamp
        self.position = position
        self.owner = owner

def get_blockchain_history(filepath, case_id_filter=None, item_id_filter=None):
    """
    Retrieves blockchain history entries for the specified filters.

    Args:
        filepath: Path to the blockchain file
        case_id_filter: Optional UUID object to filter by case ID
        item_id_filter: Optional integer to filter by item ID
        
    Returns:
        list: List of HistoryEntry objects, ordered by position in blockchain
    """
    history_entries = []
    position = 0
    
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return history_entries
        
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
                        # Extract and decrypt case ID
                        encrypted_case_id = block_data['encrypted_case_id']
                        if len(encrypted_case_id) >= 16:
                            uuid_bytes = encrypted_case_id[:16]
                            block_case_id = uuid.UUID(bytes=uuid_bytes)
                            
                            # Extract and decrypt item ID
                            # Convert hex string to bytes if necessary
                            encrypted_evidence_id = block_data['encrypted_evidence_id']
                            evidence_id_bytes = bytes.fromhex(encrypted_evidence_id) if isinstance(encrypted_evidence_id, str) else encrypted_evidence_id
                            
                            # Only use the first 16 bytes (AES block size)
                            evidence_id_bytes = evidence_id_bytes[:16] if len(evidence_id_bytes) >= 16 else evidence_id_bytes
                            
                            decrypted_padded_bytes = decrypt_aes_ecb(PROJECT_AES_KEY, evidence_id_bytes)
                            original_bytes = decrypted_padded_bytes[:4]
                            if len(original_bytes) < 4:
                                raise ValueError("Decrypted bytes insufficient for integer conversion")
                            block_item_id = int.from_bytes(original_bytes, 'big')
                            
                            # Apply filters
                            case_match = case_id_filter is None or block_case_id == case_id_filter
                            item_match = item_id_filter is None or block_item_id == item_id_filter
                            
                            if case_match and item_match:
                                # Create history entry
                                entry = HistoryEntry(
                                    case_id=block_case_id,
                                    item_id=block_item_id,
                                    action=block_data['state_str'],
                                    timestamp=block_data['timestamp_iso'],
                                    position=position,
                                    owner=block_data['owner_str']
                                )
                                history_entries.append(entry)
                        
                    except Exception:
                        # Skip this block if decryption fails
                        pass
                
                position += 1
                current_pos += block_size
                
    except Exception as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    
    return history_entries

def handle_show_history(args):
    """Handles the 'bchoc show history' command to show blockchain history."""
    provided_password = args.p
    case_id_str = getattr(args, 'c', None)
    item_id_str = getattr(args, 'i', None)
    num_entries = getattr(args, 'n', None)
    reverse_order = getattr(args, 'reverse', False)
    
    # Validate the provided password
    if not is_valid_owner_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)
    
    # Get blockchain file path from environment
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot show history.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the blockchain file exists
    if not os.path.exists(blockchain_file_path):
        print(f"Blockchain file not found. No history to show.")
        sys.exit(0)
    
    # Parse case ID filter if provided
    case_id_filter = None
    if case_id_str is not None:
        try:
            case_id_filter = uuid.UUID(case_id_str)
        except ValueError:
            print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
            sys.exit(1)
    
    # Parse item ID filter if provided
    item_id_filter = None
    if item_id_str is not None:
        try:
            item_id_filter = int(item_id_str)
            if not (0 <= item_id_filter < 2**32):
                print(f"Error: Item ID '{item_id_str}' is out of the valid range.", file=sys.stderr)
                sys.exit(1)
        except ValueError:
            print(f"Error: Invalid item ID format: '{item_id_str}'. Must be an integer.", file=sys.stderr)
            sys.exit(1)
    
    # Get blockchain history with applied filters
    history_entries = get_blockchain_history(
        blockchain_file_path, 
        case_id_filter=case_id_filter,
        item_id_filter=item_id_filter
    )
    
    # Apply reverse order if requested
    if reverse_order:
        history_entries.reverse()
    
    # Apply limit if requested
    if num_entries is not None and num_entries > 0:
        history_entries = history_entries[:num_entries]
    
    # Display history entries
    if not history_entries:
        print("No matching history entries found.")
    else:
        for i, entry in enumerate(history_entries):
            if i > 0:
                print()  # Blank line between entries
            print(f"> Case: {entry.case_id}")
            print(f"> Item: {entry.item_id}")
            print(f"> Action: {entry.action}")
            print(f"> Time: {entry.timestamp}")
            if entry.owner and entry.owner.strip():
                print(f"> Owner: {entry.owner}")
    
    sys.exit(0)
