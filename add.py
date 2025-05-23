import os
import sys
import uuid
import struct
import hashlib #To calculate hash of the previous block
from datetime import datetime, timezone #For block timestamp
import Data_Struct

try:
    #Import necessary components from Data_Struct
    from Data_Struct import (
        PROJECT_AES_KEY, encrypt_aes_ecb, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES,
        STATE_SIZE, CREATOR_SIZE, OWNER_SIZE, PREV_HASH_SIZE, EVIDENCE_ID_SIZE, #Needed for padding/handling raw bytes
        BLOCK_HEADER_FORMAT
    )
    #Import the Block class for creating new block objects
    from Data_Struct import Block #Import the Block class explicitly
except ImportError as e:
    print(f"ERROR (in add.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1) #Exit immediately if dependencies are missing

def is_valid_creator_password(password: str) -> bool:
    #Checks if the provided password matches the creator's password from environment variable.
    #Get creator password from environment variable
    creator_password = os.getenv("BCHOC_PASSWORD_CREATOR")
    if creator_password is None:
        #This is a configuration error - the creator password env var should be set.
        print("CRITICAL: BCHOC_PASSWORD_CREATOR environment variable not set. Cannot validate creator password.", file=sys.stderr)
        sys.exit(1) #Exit with critical error if creator password isn't configured

    return password == creator_password

def get_last_block_info(filepath: str) -> tuple[bytes, int]:
    #Reads the blockchain file, finds the last block, and returns its hash
    #and the total number of blocks.
    #Args:
    #filepath (str): Path to the blockchain file.
    # Returns:
    #tuple[bytes, int]: A tuple containing the hash of the last block
    #                  (32 bytes) and the total count of blocks.
    #                  Returns (32 zero bytes, 0) if the file doesn't exist or is empty.
    #                  Returns (Genesis block hash, 1) if only Genesis exists.
    #Raises:
    #IOError: If file reading fails.
    #ValueError: If the file is corrupt or incomplete blocks are found.
    last_block_hash = b'\x00' * PREV_HASH_SIZE #Default for an empty/non-existent file (before Genesis)
    block_count = 0
    last_block_bytes = None

    try:
        #Check if file exists and is not empty
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
             #This state shouldn't happen if init is run first, but handle defensively.
             #Return default (0 blocks, null hash)
             return last_block_hash, block_count #(b'\x00'*32, 0)

        #Open file and seek to find the last block
        with open(filepath, 'rb') as f:
            #Go to the end of the file
            f.seek(0, os.SEEK_END)
            file_size = f.tell()

            if file_size == 0:
                 #File is empty, return default
                 return last_block_hash, block_count #(b'\x00'*32, 0)

            #We need to iterate *backwards* or store block start positions to find the last block reliably
            #since data length is variable. A simpler approach for now: read all block bytes into memory
            #and process them sequentially to find the last one. This might be inefficient for very large chains,
            #but fits the project scope and the verify.py pattern.

            f.seek(0, os.SEEK_SET) #Go back to the start

            current_pos = 0
            while current_pos < file_size:
                #Read header
                f.seek(current_pos)
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if len(header_bytes) < BLOCK_HEADER_SIZE:
                    #Check if it's just the very end of the file after the last block
                    if current_pos + len(header_bytes) == file_size:
                         break #Reached end of file cleanly after last block
                    else:
                         raise ValueError(f"File truncated or corrupt: Incomplete header at offset {current_pos}")

                try:
                    unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                    declared_data_len = unpacked_header[7]
                except struct.error:
                    raise ValueError(f"File corrupt: Cannot unpack header at offset {current_pos}")

                #Calculate total block size
                block_size = BLOCK_HEADER_SIZE + declared_data_len

                #Ensure we can read the full block
                if current_pos + block_size > file_size:
                     raise ValueError(f"File truncated or corrupt: Block data incomplete at offset {current_pos}")

                #Read the full block bytes
                f.seek(current_pos) #Seek back to the start of this block
                full_block_bytes = f.read(block_size)

                #Store this as the current "last block" bytes
                last_block_bytes = full_block_bytes
                block_count += 1

                #Move to the start of the next potential block
                current_pos += block_size

            #After the loop, last_block_bytes holds the bytes of the very last valid block read
            #If the loop completed, file_size must have been > 0 initially, so last_block_bytes should not be None.
            if last_block_bytes is not None:
                 last_block_hash = hashlib.sha256(last_block_bytes).digest()
                 return last_block_hash, block_count
            else:
                 #This case should technically be covered by the file_size check, but defensive.
                 return b'\x00' * PREV_HASH_SIZE, 0

    except IOError as e:
        #Re-raise IOError to be caught by the caller (handle_add)
        raise IOError(f"Error reading blockchain file '{filepath}': {e}") from e
    except (ValueError, struct.error) as e: #Catch struct.error from unpack as file corruption too
        #Re-raise ValueError for corruption issues
        raise ValueError(f"Error processing blockchain file '{filepath}': {e}") from e
    except Exception as e:
         #Catch any other unexpected errors
        raise RuntimeError(f"An unexpected error occurred while finding the last block: {e}") from e

def get_all_item_ids(filepath: str) -> set[int]:
    #Reads the blockchain file, attempts to decrypt all evidence item IDs,
    #and returns a set of unique decrypted integer item IDs.
    #Uses the PROJECT_AES_KEY for decryption. Does NOT require a user password here.
    #Handles file reading errors internally and exits.
    seen_item_ids = set()

    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
             return seen_item_ids #Return empty set if no file or empty

        with open(filepath, 'rb') as f:
            file_size = os.path.getsize(filepath)
            current_pos = 0

            while current_pos < file_size:
                 f.seek(current_pos)
                 header_bytes = f.read(BLOCK_HEADER_SIZE)
                 if len(header_bytes) < BLOCK_HEADER_SIZE:
                     #Check if it's just the very end of the file after the last block
                     if current_pos + len(header_bytes) == file_size:
                         break #Reached end of file cleanly after last block
                     else:
                          print(f"Error reading existing item IDs: Incomplete header at offset {current_pos}.", file=sys.stderr)
                          sys.exit(1) #Exit on file corruption

                 try:
                     unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
                     declared_data_len = unpacked_header[7]
                 except struct.error:
                      print(f"Error reading existing item IDs: Cannot unpack header at offset {current_pos}.", file=sys.stderr)
                      sys.exit(1) #Exit on file corruption

                 block_size = BLOCK_HEADER_SIZE + declared_data_len
                 if current_pos + block_size > file_size:
                      print(f"Error reading existing item IDs: Block data incomplete at offset {current_pos}.", file=sys.stderr)
                      sys.exit(1) #Exit on file truncation/corruption

                 # We have the header_bytes (containing encrypted_evidence_id at index 3)
                 packed_evidence_id_bytes = unpacked_header[3]

                 # --- Use the specialized decryption logic ---
                 try:
                     # Genesis block check
                     if packed_evidence_id_bytes == b'0' * EVIDENCE_ID_SIZE:
                         pass # Genesis block, skip or let decryption fail safely

                     # Call the specialized decryption helper from Data_Struct
                     item_id_int = Data_Struct.decrypt_evidence_id_from_packed(
                         packed_evidence_id_bytes,
                         Data_Struct.PROJECT_AES_KEY
                     )

                     if item_id_int is not None:
                         seen_item_ids.add(item_id_int)
                     # else: # Optional: Log if decryption failed for a non-genesis block
                     #    if packed_evidence_id_bytes != b'0' * EVIDENCE_ID_SIZE:
                     #        print(f"DEBUG (get_all_item_ids): Failed to decrypt item ID at offset {current_pos}", file=sys.stderr)

                 except Exception as e:
                     print(f"Warning (get_all_item_ids): Unexpected error processing item ID at offset {current_pos}: {e!r}", file=sys.stderr)
                     pass
                 # --- End of specialized decryption logic ---

                 current_pos += block_size #Move to the next block

    except IOError as e:
         print(f"Error reading blockchain file '{filepath}' for item IDs: {e}", file=sys.stderr)
         sys.exit(1) #Exit on file read errors

    except Exception as e:
         print(f"An unexpected error occurred while collecting item IDs: {e}", file=sys.stderr)
         sys.exit(1)

    return seen_item_ids

def handle_add(args):
    #Handles the 'bchoc add' command.
    #Adds one or more items to the blockchain.
    provided_password = args.p
    case_id_str = args.c
    item_id_strings = args.i #This is a list of strings
    creator_str = args.g

    #--- 1. Password Validation (Creator) ---
    #is_valid_creator_password checks env var and exits if not set.
    if not is_valid_creator_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1) #Non-zero exit for invalid password

    #--- 2. Get Blockchain File Path ---
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot add item(s).", file=sys.stderr)
        sys.exit(1)

    #--- 3. Input Validation ---
    try:
        #Validate Case ID (must be valid UUID string)
        case_uuid = uuid.UUID(case_id_str)
    except ValueError:
        print(f"Error: Invalid case ID format: '{case_id_str}'. Must be a valid UUID.", file=sys.stderr)
        sys.exit(1)

    #Validate Creator string length
    try:
        creator_bytes = creator_str.encode('utf-8')
        if len(creator_bytes) > CREATOR_SIZE:
             print(f"Error: Creator name '{creator_str}' exceeds maximum length of {CREATOR_SIZE} bytes.", file=sys.stderr)
             sys.exit(1)
    except UnicodeEncodeError:
         print(f"Error: Creator name '{creator_str}' contains invalid characters.", file=sys.stderr)
         sys.exit(1)

    #Validate Item IDs (must be integers in range, and check uniqueness later)
    item_ids_int = []
    for item_id_str in item_id_strings:
        try:
            item_id_int = int(item_id_str)
            #Check if item ID is within valid 4-byte integer range (0 to 2**32 - 1)
            if not (0 <= item_id_int < 2**32):
                 print(f"Error: Item ID '{item_id_str}' is out of the valid 4-byte unsigned integer range (0 to 4294967295).", file=sys.stderr)
                 sys.exit(1)
            item_ids_int.append(item_id_int)
        except ValueError:
            print(f"Error: Invalid item ID format: '{item_id_str}'. Must be an integer.", file=sys.stderr)
            sys.exit(1)

    #Check for duplicate item IDs *within* the provided list for this single command run
    if len(item_ids_int) != len(set(item_ids_int)):
         print("Error: Duplicate item IDs provided in the same command.", file=sys.stderr)
         sys.exit(1)

    #--- 4. Check for Duplicate Item IDs in Existing Chain ---
    #Read all existing item IDs from the file *before* attempting to add.
    #get_all_item_ids handles file read errors internally by exiting.
    existing_item_ids = get_all_item_ids(blockchain_file_path)

    for item_id in item_ids_int:
        if item_id in existing_item_ids:
            print(f"Error: Item ID '{item_id}' already exists in the blockchain.", file=sys.stderr)
            sys.exit(1) #Non-zero exit for duplicate item ID

    #--- 5. Handle File Existence and Get Hash of the Last Block ---
    file_exists = os.path.exists(blockchain_file_path)
    last_hash_for_new_block = b'\x00' * PREV_HASH_SIZE #Default prev hash before any blocks

    if not file_exists or os.path.getsize(blockchain_file_path) == 0:
        #If file does not exist or is empty, we need to create the Genesis block first.
        #This handles Test #007 ("add before init should create initial block").
        if not file_exists:
             print("Blockchain file not found.") #Match init output
        elif os.path.getsize(blockchain_file_path) == 0:
             print("Blockchain file is empty.") #Indicate empty state

        print("Creating INITIAL block before adding items.")
        try:
            #Replicate the essential Genesis block creation logic from init.py
            genesis_bytes = Data_Struct.create_genesis_block_bytes() #Use Data_Struct prefix
            with open(blockchain_file_path, 'wb') as f:
                f.write(genesis_bytes)
            print("INITIAL block created.") #Match init output for user feedback

            #After creating genesis, the last hash for the *first* item block
            #will be the hash of this newly created genesis block.
            last_hash_for_new_block = hashlib.sha256(genesis_bytes).digest()
            block_count = 1  # <-- Add this line to fix the error
            #file_exists is now True and file size is > 0

        except (IOError, RuntimeError) as e:
             print(f"Error creating initial blockchain file: {e}", file=sys.stderr)
             sys.exit(1)
    else:
        #File exists and is not empty, read the last block info to get its hash
        try:
            #get_last_block_info handles file read/corruption errors internally by exiting.
            last_hash_for_new_block, block_count = get_last_block_info(blockchain_file_path)
            #last_hash_for_new_block is now the hash of the last block (Genesis if only Genesis exists)
            #block_count should be >= 1 if file_exists was true, unless it's corrupt (handled by get_last_block_info)

        except (IOError, ValueError, RuntimeError) as e:
            #get_last_block_info already prints specific errors and exits,
            #but this catch is a fallback for unexpected issues.
            print(f"An error occurred while determining the last block hash from existing file: {e}", file=sys.stderr)
            sys.exit(1)

    #--- 6. Add Each Item as a New Block ---
    try:
        with open(blockchain_file_path, 'ab') as f:
            for i, item_id in enumerate(item_ids_int):
                # For the block that follows the genesis block, set prev_hash=0 (not b'\x00'*32)
                # In all other cases, use the hash of the last block
                if block_count == 1 and i == 0:
                    prev_hash_for_block = 0
                else:
                    prev_hash_for_block = last_hash_for_new_block

                default_owner_for_add = "" # or "" if your Block class allows it

                try:
                    new_block = Block(
                        previous_hash=prev_hash_for_block,
                        case_id=case_uuid,
                        evidence_item_id=item_id,
                        state="CHECKEDIN",
                        creator=creator_str,
                        owner=default_owner_for_add,
                        data=b'',
                        aes_key=PROJECT_AES_KEY
                    )
                except (ValueError, TypeError, RuntimeError) as e:
                    print(f"Internal Error: Failed to create block object for item {item_id}: {e}", file=sys.stderr)
                    sys.exit(1)

                packed_block_bytes = new_block.pack()
                f.write(packed_block_bytes)
                last_hash_for_new_block = hashlib.sha256(packed_block_bytes).digest()

                print(f"> Added item: {item_id}")
                print(f"> Status: CHECKEDIN")
                print(f"> Time of action: {new_block.get_timestamp_iso()}")

    except IOError as e:
        #Catch errors during file writing
        print(f"Error writing to blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
        sys.exit(1) #Non-zero exit

    except Exception as e:
        #Catch any other unexpected errors during the adding process
        print(f"An unexpected error occurred while adding items: {e}", file=sys.stderr)
        sys.exit(1)

    #--- 7. Exit Success ---
    #Only exit 0 if all items were successfully added and file operations completed.
    sys.exit(0)
