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
                        encrypted_case_id = block_data['encrypted_case_id']
                        block_case_id = Data_Struct.decrypt_case_id_from_packed(encrypted_case_id)
                        encrypted_evidence_id = block_data['encrypted_evidence_id']
                        block_item_id = Data_Struct.decrypt_evidence_id_from_packed(encrypted_evidence_id)

                        if block_case_id is None or block_item_id is None:
                            continue  # Skip blocks with failed decryption

                        # Apply filters
                        case_match = case_id_filter is None or block_case_id == case_id_filter
                        item_match = item_id_filter is None or block_item_id == item_id_filter

                        if case_match and item_match:
                            history_entries.append(HistoryEntry(
                                case_id=block_case_id,
                                item_id=block_item_id,
                                action=block_data['state_str'],
                                timestamp=block_data['timestamp_iso'],
                                position=position,
                                owner=block_data['owner_str']
                            ))

                    except Exception:
                        continue  # Skip block on any error
                
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

    if not is_valid_owner_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1)

    try:
        blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
        if not blockchain_file_path:
            print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot show history.", file=sys.stderr)
            sys.exit(1)

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
        if num_entries is not None and num_entries >= 0:  # Allow n=0
            history_entries = history_entries[:num_entries]
        elif num_entries is not None and num_entries < 0:
            print("Warning: Invalid negative value for -n. Showing all entries.", file=sys.stderr)

        # Display history entries
        if history_entries:  # Only enter this block if the list is NOT empty
            print(f"Executing: show history (Case: {getattr(args, 'c', None)}, Item: {getattr(args, 'i', None)}, Num: {getattr(args, 'n', None)}, Reverse: {getattr(args, 'reverse', False)})")
            first_entry = True
            for i, entry in enumerate(history_entries):
                if not first_entry:
                    print()  # Print blank line between entries
                print(f"> Case: {entry.case_id}")
                print(f"> Item: {entry.item_id}")
                print(f"> Action: {entry.action}")
                print(f"> Time: {entry.timestamp}")
                owner_cleaned = entry.owner.strip('\x00') if entry.owner else ''
                if owner_cleaned and entry.action in ["CHECKEDOUT", "RELEASED"]:
                    print(f"> Owner: {owner_cleaned}")
                first_entry = False

        # If history_entries is empty, the 'if' block is skipped, and nothing is printed.

        sys.exit(0)  # Exit successfully regardless

    except Exception as e:
        print(f"An unexpected error occurred while running the show history command: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
