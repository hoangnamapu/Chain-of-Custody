import os
import sys
import uuid
import struct
import hashlib
from datetime import datetime, timezone
import Data_Struct # Import the whole module to access unpack_block etc.
import binascii # Although not strictly needed here anymore, keep for consistency

try:
    # Ensure unpack_block is accessible, along with constants
    # We don't directly use encrypt/decrypt here anymore
    from Data_Struct import (
        PROJECT_AES_KEY, BLOCK_HEADER_SIZE, unpack_block,
        BLOCK_HEADER_FORMAT, CASE_ID_SIZE, EVIDENCE_ID_SIZE # Import needed constants
    )
except ImportError as e:
    print(f"ERROR (in Summary.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def generate_case_summary(filepath, case_id_uuid):
    """
    Generates a summary of all items for a specific case ID by using
    the pre-processed data from Data_Struct.unpack_block.
    
    Args:
        filepath: Path to the blockchain file
        case_id_uuid: UUID object for the case to summarize
        
    Returns:
        dict: Dictionary with summary information
    """
    # Keep track of the latest state seen for each item ID within this case
    latest_block_per_item = {}

    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
             # Return zero counts if file doesn't exist or is empty
             return {
                'case_id': case_id_uuid, 'total_items': 0, 'checked_in': 0,
                'checked_out': 0, 'disposed': 0, 'destroyed': 0, 'released': 0,
            }

        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            current_pos = 0
            block_index = 0 # For debugging

            while current_pos < file_size:
                # Read block header to determine size
                f.seek(current_pos)
                block_start_offset = current_pos
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE: break

                try:
                    # Minimal unpack just to get data length
                    # Index 7 corresponds to 'I' (data_length) in BLOCK_HEADER_FORMAT
                    declared_data_len = struct.unpack_from("I", header_bytes, BLOCK_HEADER_SIZE - 4)[0] # Use correct offset and endianness ">"
                except struct.error as e:
                    print(f"ERROR: Failed unpack header offset {block_start_offset} to get data_len: {e}. File corrupt?", file=sys.stderr)
                    sys.exit(1)

                block_size = BLOCK_HEADER_SIZE + declared_data_len
                if block_start_offset + block_size > file_size:
                    print(f"ERROR: Declared block size {block_size} exceeds file size from offset {block_start_offset}. File truncated?", file=sys.stderr)
                    sys.exit(1)

                # Read the full block bytes
                f.seek(block_start_offset)
                full_block_bytes = f.read(block_size)
                if len(full_block_bytes) != block_size:
                     print(f"ERROR: Read {len(full_block_bytes)}, expected {block_size} offset {block_start_offset}. File I/O error?", file=sys.stderr)
                     sys.exit(1)

                # --- Use the modified unpack_block from Data_Struct ---
                block_data = Data_Struct.unpack_block(full_block_bytes)

                # +++ DEBUG PRINTS (now commented out) +++
                # if block_data and block_data.get('state_str') != "INITIAL":
                #     dec_case = block_data.get('decrypted_case_uuid')
                #     dec_item = block_data.get('decrypted_item_id')
                #     print(f"DEBUG SUMMARY [Block {block_index}]: Unpack Result -> "
                #           f"DecCase: {dec_case} (Type: {type(dec_case)}), "
                #           f"DecItem: {dec_item} (Type: {type(dec_item)})", file=sys.stderr)
                # elif block_data:
                #     print(f"DEBUG SUMMARY [Block {block_index}]: Skipping INITIAL block.", file=sys.stderr)
                # else:
                #     # This indicates unpack_block itself failed and returned None
                #     print(f"DEBUG SUMMARY [Block {block_index}]: unpack_block returned None! Offset: {block_start_offset}", file=sys.stderr)
                #     print("ERROR: Failed to unpack block, blockchain may be corrupt.", file=sys.stderr)
                #     sys.exit(1)
                # +++++++++++++++++++++++++++++++

                # Process if unpacked successfully and not the INITIAL block
                if block_data and block_data.get('state_str') != "INITIAL":
                    # --- Check the pre-decrypted fields provided by unpack_block ---
                    block_case_id = block_data.get('decrypted_case_uuid') # Get potentially decrypted UUID (or None)

                    # Compare if decryption was successful and matches target
                    if block_case_id is not None and block_case_id == case_id_uuid:
                        # +++ MATCH PRINT (commented out) +++
                        # print(f"DEBUG SUMMARY [Block {block_index}]: <<< CASE ID MATCHED! >>>", file=sys.stderr)
                        # +++++++++++++++++++++++
                        # Case matched! Now check the pre-decrypted item ID
                        item_id_int = block_data.get('decrypted_item_id') # Get potentially decrypted Item ID (or None)

                        if item_id_int is not None:
                             # Successfully identified both Case and Item ID for this block
                             latest_block_per_item[item_id_int] = block_data
                             # +++ STORE PRINT (commented out) +++
                             # print(f"DEBUG SUMMARY [Block {block_index}]: Storing Item {item_id_int} with state {block_data.get('state_str')}", file=sys.stderr)
                             # +++++++++++++++++++++++
                        else:
                            # +++ ITEM FAIL PRINT (commented out) +++
                            # print(f"DEBUG SUMMARY [Block {block_index}]: Case matched BUT Item ID was None.", file=sys.stderr)
                            # +++++++++++++++++++++++++++
                    # else: # Optional: Add mismatch details if needed
                    #     if block_case_id is None and block_data.get('encrypted_case_id') != b'0'*32:
                    #          print(f"DEBUG SUMMARY [Block {block_index}]: Case ID was None (Decryption failed in unpack).", file=sys.stderr)
                    #     elif block_case_id is not None:
                    #          print(f"DEBUG SUMMARY [Block {block_index}]: Case ID Mismatch (Target: {case_id_uuid}, Found: {block_case_id}).", file=sys.stderr)
                            pass # Continue processing blocks even if this one didn't match, remember to correctly indent it back IF you uncomment all these print statements.

                # --- Move to next block ---
                current_pos += block_size
                block_index += 1

            # --- End of Loop: Calculate Final Counts from latest states ---
            summary_counts = {
                'checked_in': 0, 'checked_out': 0, 'disposed': 0,
                'destroyed': 0, 'released': 0
            }
            for item_id, last_block_data in latest_block_per_item.items():
                 state = last_block_data.get('state_str')
                 if state == "CHECKEDIN": summary_counts['checked_in'] += 1
                 elif state == "CHECKEDOUT": summary_counts['checked_out'] += 1
                 elif state == "DISPOSED": summary_counts['disposed'] += 1
                 elif state == "DESTROYED": summary_counts['destroyed'] += 1
                 elif state == "RELEASED": summary_counts['released'] += 1

    except IOError as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during summary generation: {e}", file=sys.stderr)
        # Potentially return partial or zero counts depending on desired robustness
        # For now, exit
        sys.exit(1)

    # Prepare the final dictionary in the required output format
    final_summary = {
        'case_id': case_id_uuid,
        'total_items': len(latest_block_per_item),
        'checked_in': summary_counts['checked_in'],
        'checked_out': summary_counts['checked_out'],
        'disposed': summary_counts['disposed'],
        'destroyed': summary_counts['destroyed'],
        'released': summary_counts['released'],
    }
    return final_summary


def handle_summary(args):
    """Handles the 'bchoc summary' command to show item statistics for a case."""
    case_id_str = args.c

    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot generate summary.", file=sys.stderr)
        sys.exit(1)

    try:
        case_id_uuid = uuid.UUID(case_id_str)
    except ValueError:
        print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
        sys.exit(1)

    # Check existence *before* calling generate_case_summary
    if not os.path.exists(blockchain_file_path):
        # If file doesn't exist, print a zero summary matching the expected output format
        # This covers Test #066
        print(f"Case Summary for Case ID: {case_id_uuid}")
        print(f"Total Evidence Items: 0")
        print(f"Checked In: 0")
        print(f"Checked Out: 0")
        print(f"Disposed: 0")
        print(f"Destroyed: 0")
        print(f"Released: 0")
        sys.exit(0) # Exit successfully

    # File exists, proceed with generation
    summary = generate_case_summary(blockchain_file_path, case_id_uuid)

    # Print the results from the generated summary
    print(f"Case Summary for Case ID: {summary['case_id']}")
    print(f"Total Evidence Items: {summary['total_items']}")
    print(f"Checked In: {summary['checked_in']}")
    print(f"Checked Out: {summary['checked_out']}")
    print(f"Disposed: {summary['disposed']}")
    print(f"Destroyed: {summary['destroyed']}")
    print(f"Released: {summary['released']}")
    sys.exit(0)
