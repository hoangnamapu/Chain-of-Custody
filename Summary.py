import os
import sys
import uuid
import struct
from datetime import datetime, timezone
import binascii

try:
    from Data_Struct import (
        PROJECT_AES_KEY, encrypt_aes_ecb, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES, Block,
        STATE_SIZE, CREATOR_SIZE, OWNER_SIZE, PREV_HASH_SIZE, EVIDENCE_ID_SIZE,
        BLOCK_HEADER_FORMAT, debug_reverse_evidence_id, CASE_ID_SIZE
    )
except ImportError as e:
    print(f"ERROR (in Summary.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1)

def generate_case_summary(filepath, case_id_uuid):
    summary = {
        'case_id': case_id_uuid,
        'total_items': 0,
        'item_states': {},
        'checked_in_count': 0,
        'checked_out_count': 0,
        'disposed_count': 0,
        'destroyed_count': 0,
        'released_count': 0,
    }
    latest_block_per_item = {}

    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
             return summary

        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            current_pos = 0

            while current_pos < file_size:
                f.seek(current_pos)
                block_start_offset = current_pos
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE: break

                try:
                    unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                    declared_data_len = unpacked_header[7]
                except struct.error as e:
                    print(f"ERROR: Failed unpack header offset {block_start_offset}: {e}", file=sys.stderr)
                    sys.exit(1)

                block_size = BLOCK_HEADER_SIZE + declared_data_len
                if block_start_offset + block_size > file_size:
                    print(f"ERROR: Block size {block_size} exceeds file size offset {block_start_offset}", file=sys.stderr)
                    sys.exit(1)

                f.seek(block_start_offset)
                full_block_bytes = f.read(block_size)
                if len(full_block_bytes) != block_size:
                     print(f"ERROR: Read {len(full_block_bytes)}, expected {block_size} offset {block_start_offset}", file=sys.stderr)
                     sys.exit(1)

                block_data = unpack_block(full_block_bytes)

                if block_data and block_data.get('state_str') != "INITIAL":
                    block_case_id = None
                    item_id_int = None
                    encrypted_case_id_bytes_debug = block_data.get('encrypted_case_id', b'<MISSING>')

                    # --- Try to Extract Case ID ---
                    try:
                        # STEP 1: Get raw bytes from unpack_block
                        encrypted_case_id_bytes = block_data.get('encrypted_case_id')
                        if not encrypted_case_id_bytes or len(encrypted_case_id_bytes) != CASE_ID_SIZE:
                            raise ValueError("Case ID field missing/wrong size")

                        # STEP 2: Strip nulls (shouldn't be strictly needed if storage is correct)
                        encrypted_case_id_ascii = encrypted_case_id_bytes.rstrip(b'\0')

                        # STEP 3: Decode ASCII to get hex string
                        hex_string = encrypted_case_id_ascii.decode('ascii')
                        if len(hex_string) != 32: raise ValueError(f"Hex len {len(hex_string)}, expected 32")

                        # STEP 4: Convert hex string to ciphertext bytes
                        ciphertext_bytes = binascii.unhexlify(hex_string)
                        if len(ciphertext_bytes) != AES_BLOCK_SIZE_BYTES: raise ValueError(f"Ciphertext len {len(ciphertext_bytes)}, expected {AES_BLOCK_SIZE_BYTES}")

                        # STEP 5: Decrypt
                        decrypted_case_id_bytes = decrypt_aes_ecb(PROJECT_AES_KEY, ciphertext_bytes)
                        if len(decrypted_case_id_bytes) < 16: raise ValueError("Decrypted Case ID too short")

                        # STEP 6: Convert to UUID
                        block_case_id = uuid.UUID(bytes=decrypted_case_id_bytes[:16])

                    except Exception as e:
                        # print(f"DEBUG SUMMARY: Case ID extraction failed block {block_index}: {e}", file=sys.stderr)
                        print(f"--- DEBUGGING FAILED CASE ID EXTRACTION (Block {block_index}) ---", file=sys.stderr)

                        # +++ ADD THIS CHECK +++
                        print(f"DEBUG SUMMARY: Value passed to debug_reverse: type={type(encrypted_case_id_bytes_debug)}, len={len(encrypted_case_id_bytes_debug) if isinstance(encrypted_case_id_bytes_debug, bytes) else 'N/A'}, value={encrypted_case_id_bytes_debug!r}", file=sys.stderr)
                        # +++ END ADDED CHECK +++
                        block_case_id = None # Ensure it's None on failure


                    # +++++ DEBUG COMPARISON +++++
                    if block_case_id is not None:
                        is_match = (block_case_id == case_id_uuid)
                        print(f"DEBUG SUMMARY [Block {block_index} @{block_start_offset}]: "
                              f"Target='{case_id_uuid}' Extracted='{block_case_id}' "
                              f"(Match: {is_match})", file=sys.stderr)

                        if is_match:
                            print(f"DEBUG SUMMARY: <<< MATCH FOUND >>>", file=sys.stderr)
                            # --- Try to Extract Item ID only if Case matched ---
                            try:
                                encrypted_evidence_id_bytes = block_data.get('encrypted_evidence_id')
                                if not encrypted_evidence_id_bytes or len(encrypted_evidence_id_bytes) != EVIDENCE_ID_SIZE:
                                    raise ValueError("Evidence ID field missing/wrong size")

                                encrypted_evidence_id_ascii = encrypted_evidence_id_bytes.rstrip(b'\0')
                                hex_string_item = encrypted_evidence_id_ascii.decode('ascii')
                                if len(hex_string_item) != 32: raise ValueError(f"Item Hex len {len(hex_string_item)}, expected 32")
                                ciphertext_bytes_item = binascii.unhexlify(hex_string_item)
                                if len(ciphertext_bytes_item) != AES_BLOCK_SIZE_BYTES: raise ValueError(f"Item Cipher len {len(ciphertext_bytes_item)}, expected {AES_BLOCK_SIZE_BYTES}")

                                decrypted_padded_bytes = decrypt_aes_ecb(PROJECT_AES_KEY, ciphertext_bytes_item)
                                original_bytes = decrypted_padded_bytes[:4]
                                if len(original_bytes) < 4: raise ValueError("Decrypted evidence ID too short.")
                                item_id_int = int.from_bytes(original_bytes, 'big')
                                latest_block_per_item[item_id_int] = block_data # Store data for matched item
                                print(f"DEBUG SUMMARY: ---> Stored Item ID: {item_id_int} State: {block_data.get('state_str')}", file=sys.stderr)

                            except Exception as e:
                                print(f"DEBUG SUMMARY: WARNING - Item ID extraction failed for matched case block {block_index}: {e}", file=sys.stderr)
                                pass # Can't track item state if ID fails
                    # else: # Optional: print if NO match, can be verbose
                    #     print(f"DEBUG SUMMARY [Block {block_index} @{block_start_offset}]: "
                    #           f"Target='{case_id_uuid}' Extracted='{block_case_id}' "
                    #           f"(Match: False) RawCaseField='{encrypted_case_id_bytes_debug.hex()}'", file=sys.stderr)

                    # +++++ END DEBUG +++++

                current_pos += block_size
                block_index += 1

            # --- End of Loop: Calculate Final Counts ---
            print(f"\nDEBUG SUMMARY: --- Final Counting Stage ---", file=sys.stderr)
            print(f"DEBUG SUMMARY: latest_block_per_item contents:", file=sys.stderr)
            for dbg_item_id, dbg_block_data in latest_block_per_item.items():
                 print(f"  Item ID: {dbg_item_id}, Last State: {dbg_block_data.get('state_str', 'MISSING')}, Timestamp: {dbg_block_data.get('timestamp_iso', 'N/A')}", file=sys.stderr)
            print(f"DEBUG SUMMARY: --- Starting Counts Calculation ---", file=sys.stderr)

            summary['total_items'] = len(latest_block_per_item)
            print(f"DEBUG SUMMARY: Calculated total_items: {summary['total_items']}", file=sys.stderr)

            summary['checked_in_count'] = 0
            summary['checked_out_count'] = 0
            summary['disposed_count'] = 0
            summary['destroyed_count'] = 0
            summary['released_count'] = 0

            for item_id, last_block in latest_block_per_item.items():
                 state = last_block.get('state_str')
                 print(f"DEBUG SUMMARY: Processing Item ID: {item_id}, Found State: '{state}'", file=sys.stderr)

                 if state == "CHECKEDIN":
                     summary['checked_in_count'] += 1
                     print(f"DEBUG SUMMARY:   Incremented checked_in_count to {summary['checked_in_count']}", file=sys.stderr)
                 elif state == "CHECKEDOUT":
                     summary['checked_out_count'] += 1
                     print(f"DEBUG SUMMARY:   Incremented checked_out_count to {summary['checked_out_count']}", file=sys.stderr)
                 elif state == "DISPOSED":
                     summary['disposed_count'] += 1
                     print(f"DEBUG SUMMARY:   Incremented disposed_count to {summary['disposed_count']}", file=sys.stderr)
                 elif state == "DESTROYED":
                     summary['destroyed_count'] += 1
                     print(f"DEBUG SUMMARY:   Incremented destroyed_count to {summary['destroyed_count']}", file=sys.stderr)
                 elif state == "RELEASED":
                     summary['released_count'] += 1
                     print(f"DEBUG SUMMARY:   Incremented released_count to {summary['released_count']}", file=sys.stderr)
                 else:
                      print(f"DEBUG SUMMARY:   State '{state}' did not match any known category.", file=sys.stderr)

            print(f"DEBUG SUMMARY: --- Finished Counts Calculation ---", file=sys.stderr)
            print(f"DEBUG SUMMARY: Final Counts - In:{summary['checked_in_count']} Out:{summary['checked_out_count']} Disp:{summary['disposed_count']} Dest:{summary['destroyed_count']} Rel:{summary['released_count']}", file=sys.stderr)

    except IOError as e:
        print(f"Error reading blockchain file '{filepath}': {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during summary generation: {e}", file=sys.stderr)
        sys.exit(1)

    # Prepare the final dictionary
    final_summary = {
        'case_id': summary['case_id'], 'total_items': summary['total_items'],
        'checked_in': summary['checked_in_count'], 'checked_out': summary['checked_out_count'],
        'disposed': summary['disposed_count'], 'destroyed': summary['destroyed_count'],
        'released': summary['released_count'],
    }
    return final_summary


def handle_summary(args):
    case_id_str = args.c
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set.", file=sys.stderr)
        sys.exit(1)

    try:
        case_id_uuid = uuid.UUID(case_id_str)
        # +++++ DEBUG TARGET +++++
        print(f"DEBUG SUMMARY: Target Case ID parsed from args: '{case_id_uuid}' (Type: {type(case_id_uuid)})", file=sys.stderr)
        # +++++ END DEBUG +++++
    except ValueError:
        print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(blockchain_file_path):
        print(f"Case Summary for Case ID: {case_id_uuid}")
        print(f"Total Evidence Items: 0")
        print(f"Checked In: 0")
        print(f"Checked Out: 0")
        print(f"Disposed: 0")
        print(f"Destroyed: 0")
        print(f"Released: 0")
        sys.exit(0)

    summary = generate_case_summary(blockchain_file_path, case_id_uuid)

    print(f"Case Summary for Case ID: {summary['case_id']}")
    print(f"Total Evidence Items: {summary['total_items']}")
    print(f"Checked In: {summary['checked_in']}")
    print(f"Checked Out: {summary['checked_out']}")
    print(f"Disposed: {summary['disposed']}")
    print(f"Destroyed: {summary['destroyed']}")
    print(f"Released: {summary['released']}")
    sys.exit(0)