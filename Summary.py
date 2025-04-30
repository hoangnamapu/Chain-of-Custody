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
    print(f"ERROR (in Summary.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def generate_case_summary(filepath, case_id_uuid):
    """
    Generates a summary of all items for a specific case ID.
    
    Args:
        filepath: Path to the blockchain file
        case_id_uuid: UUID object for the case to summarize
        
    Returns:
        dict: Dictionary with summary information
    """
    summary = {
        'case_id': case_id_uuid,
        'total_items': 0,
        'checked_in': 0,
        'checked_out': 0,
        'disposed': 0,
        'destroyed': 0,
        'released': 0,
        'unique_items': set()
    }
    
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
            return summary
        
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
                                encrypted_evidence_id = bytes.fromhex(block_data['encrypted_evidence_id'])
                                decrypted_padded_bytes = decrypt_aes_ecb(
                                    PROJECT_AES_KEY, 
                                    encrypted_evidence_id
                                )
                                original_bytes = decrypted_padded_bytes[:4]
                                item_id = int.from_bytes(original_bytes, 'big')
                                
                                # Add to the unique items set
                                summary['unique_items'].add(item_id)
                                
                                # Update the appropriate counter based on the state
                                state = block_data['state_str']
                                if state == "CHECKEDIN":
                                    summary['checked_in'] += 1
                                elif state == "CHECKEDOUT":
                                    summary['checked_out'] += 1
                                elif state == "DISPOSED":
                                    summary['disposed'] += 1
                                elif state == "DESTROYED":
                                    summary['destroyed'] += 1
                                elif state == "RELEASED":
                                    summary['released'] += 1
                    except Exception:
                        # Skip this block if decryption fails
                        pass
                
                current_pos += block_size
                
    except Exception as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    
    # Update the total items count
    summary['total_items'] = len(summary['unique_items'])
    
    return summary

def handle_summary(args):
    """Handles the 'bchoc summary' command to show item statistics for a case."""
    case_id_str = args.c
    
    # Get blockchain file path from environment
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot generate summary.", file=sys.stderr)
        sys.exit(1)
    
    # Parse the case ID
    try:
        case_id_uuid = uuid.UUID(case_id_str)
    except ValueError:
        print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
        sys.exit(1)
    
    # Check if the blockchain file exists
    if not os.path.exists(blockchain_file_path):
        print(f"Error: Blockchain file '{blockchain_file_path}' does not exist.", file=sys.stderr)
        sys.exit(1)
    
    # Generate the summary
    summary = generate_case_summary(blockchain_file_path, case_id_uuid)
    
    # Print the summary
    print(f"Case Summary for Case ID: {summary['case_id']}")
    print(f"Total Evidence Items: {summary['total_items']}")
    print(f"Checked In: {summary['checked_in']}")
    print(f"Checked Out: {summary['checked_out']}")
    print(f"Disposed: {summary['disposed']}")
    print(f"Destroyed: {summary['destroyed']}")
    print(f"Released: {summary['released']}")
    
    sys.exit(0)
