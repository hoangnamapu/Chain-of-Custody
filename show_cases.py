import os
import sys
import uuid
import struct #Needed for reading blocks
# import hashlib #Might be needed for block structure validation/reading
import Data_Struct  #Needed for unpacking block headers

try:
    #Import necessary components from Data_Struct
    from Data_Struct import (
        PROJECT_AES_KEY, decrypt_aes_ecb, unpack_block,
        BLOCK_HEADER_SIZE, AES_BLOCK_SIZE_BYTES, ALLOWED_OWNERS #ALLOWED_OWNERS might be useful for password validation check names
    )
except ImportError as e:
    print(f"ERROR (in show_cases.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1) #Exit immediately if dependencies are missing

def is_valid_password(password: str) -> bool:
    #Checks if the provided password matches any allowed owner/creator password from environment variables.
    #Get allowed passwords from environment variables
    #The spec lists Police, Lawyer, Analyst, Executive, and Creator passwords on page 7/8.
    #show commands generally require an owner password (Page 4), but show cases/items/history specifically state 'anyone from the owners'.
    #Let's stick to 'owners' (Police, Lawyer, Analyst, Executive) for 'show' commands based on the detailed requirement list.
    allowed_passwords = {
        os.getenv("BCHOC_PASSWORD_POLICE"),
        os.getenv("BCHOC_PASSWORD_LAWYER"),
        os.getenv("BCHOC_PASSWORD_ANALYST"),
        os.getenv("BCHOC_PASSWORD_EXECUTIVE"),
        #Note: Explicitly *excluding* creator password for 'show' commands based on spec details page 4.
    }
    #Filter out None values in case some env vars are not set
    allowed_passwords.discard(None)

    return password in allowed_passwords

def handle_show_cases(args):
    #Handles the 'bchoc show cases' command.
    #Requires a valid owner password.
    #Lists all unique decrypted case IDs found in the blockchain.
    provided_password = args.p

    #--- 1. Password Validation ---
    if not is_valid_password(provided_password):
        print("> Invalid password", file=sys.stderr)
        sys.exit(1) #Non-zero exit for invalid password

    #--- 2. Get Blockchain File Path ---
    blockchain_file_path = os.getenv("BCHOC_FILE_PATH")
    if not blockchain_file_path:
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot show cases.", file=sys.stderr)
        sys.exit(1) #Non-zero exit if file path is not configured

    #--- 3. Check File Existence ---
    if not os.path.exists(blockchain_file_path):
        #If the file doesn't exist, there are no cases to show. Exit gracefully.
        #The spec doesn't explicitly say what to print, but printing nothing or a message seems reasonable.
        #Let's print a message and exit 0.
        print("Blockchain file not found. No cases to show.")
        sys.exit(0)

    #--- 4. Read and Process Blocks ---
    unique_case_ids = set() #Use a set to store unique UUID objects

    try:
        with open(blockchain_file_path, 'rb') as f:
            block_index = 0 #Keep track of the block number (0 for genesis)
            while True:
                #Read the header size first (logic refined in add.py's get_last_block_info, let's use that pattern)
                #Read the full block using the header + data length to be safe
                f.seek(0, os.SEEK_CUR) #Get current position before reading header
                current_pos = f.tell()
                header_bytes = f.read(BLOCK_HEADER_SIZE)
                if not header_bytes:
                    break #Reached end of file

                if len(header_bytes) < BLOCK_HEADER_SIZE:
                    #Check if it's just the very end of the file after the last block
                    if current_pos + len(header_bytes) == os.path.getsize(blockchain_file_path):
                         break #Reached end of file cleanly after last block
                    else:
                         print(f"Error reading blockchain: Incomplete header at offset {current_pos}.", file=sys.stderr)
                         sys.exit(1) #Exit on file corruption

                try:
                    unpacked_header_partial = struct.unpack(Data_Struct.BLOCK_HEADER_FORMAT, header_bytes)
                    declared_data_len = unpacked_header_partial[7]
                except struct.error:
                     print(f"Error reading blockchain: Cannot unpack header at offset {current_pos}. File may be corrupt.", file=sys.stderr)
                     sys.exit(1)

                block_size = BLOCK_HEADER_SIZE + declared_data_len
                if current_pos + block_size > os.path.getsize(blockchain_file_path):
                     print(f"Error reading blockchain: Block data incomplete at offset {current_pos}. File may be truncated.", file=sys.stderr)
                     sys.exit(1)

                #Read the rest of the block's data payload
                data_bytes = f.read(declared_data_len) #Already read header, read only data here

                #Combine header and data for the full block bytes (needed for hashing if we were verifying, not needed for unpack_block)
                #full_block_bytes = header_bytes + data_bytes #Not strictly needed for this command's logic

                #We have the header_bytes which contains the encrypted case ID at index 2
                #Let's unpack just the header to get the specific fields directly
                try:
                     unpacked_header = struct.unpack(Data_Struct.BLOCK_HEADER_FORMAT, header_bytes)
                except struct.error:
                     print(f"Error reading blockchain: Cannot unpack header at offset {current_pos}. File may be corrupt.", file=sys.stderr)
                     sys.exit(1)

                #Skip the genesis block (block_index 0) as it has a null case ID
                #Or, check the state field - genesis has state 'INITIAL'
                state_str = unpacked_header[4].split(b'\0', 1)[0].decode('utf-8', errors='replace')
                if state_str != "INITIAL": #Skip genesis block by state check

                     #Get the encrypted case ID from the unpacked header (index 2)
                     encrypted_case_id_padded = unpacked_header[2] #This is the full 32 bytes

                     #Attempt to decrypt the case ID
                     try:
                         #Pass the *entire* 32-byte encrypted field to decrypt_aes_ecb.
                         #decrypt_aes_ecb will decrypt the 32 bytes and then attempt PKCS7 unpadding,
                         #which should result in the original 16-byte UUID bytes.
                         decrypted_case_id_bytes = decrypt_aes_ecb(
                             PROJECT_AES_KEY,
                             encrypted_case_id_padded #<-- CORRECTED: Pass the full 32 bytes
                         )
                         #Attempt to convert decrypted bytes to a UUID.
                         #This requires exactly 16 bytes after decryption/unpadding.
                         if len(decrypted_case_id_bytes) != 16:
                             #Decryption/unpadding did not yield a 16-byte UUID, likely corrupt data
                             raise ValueError("Decrypted bytes length is not 16, cannot form UUID")

                         case_uuid = uuid.UUID(bytes=decrypted_case_id_bytes)

                         #Add the UUID object to the set
                         unique_case_ids.add(case_uuid)

                     except (ValueError, TypeError) as e:
                         #Catch errors during decryption (likely invalid padding) or UUID creation.
                         #This block's case ID is likely corrupt or invalid. Skip it.
                         #For debugging, you could print:
                         #print(f"Warning: Could not decrypt or parse Case ID in block at offset {current_pos}. Error: {e}", file=sys.stderr)
                         pass #Skip silently as per one-error guidance unless critical
                     except Exception as e:
                          #Catch any other unexpected error during decryption/UUID creation
                          print(f"Warning: Unexpected error processing case ID in block at offset {current_pos}: {e}", file=sys.stderr)
                          pass #Still skip this block's case ID

                #Move file pointer to the start of the next block
                #The loop header reads the header, then we read the data. The file pointer is now at current_pos + BLOCK_HEADER_SIZE + declared_data_len
                #The next iteration's f.read(BLOCK_HEADER_SIZE) will start from here. No extra f.seek needed.
                pass #File pointer is already at the correct position for the next read.

    except IOError as e:
        #Catch errors during file reading (other than file not found already handled)
        print(f"Error: Failed to read blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
        sys.exit(1) #Non-zero exit

    except (ValueError, struct.error) as e: #Catch struct errors from unpack here too
         print(f"Error processing blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
         sys.exit(1)

    except Exception as e:
        #Catch any other unexpected errors during block processing loop
        print(f"An unexpected error occurred while processing blockchain blocks: {e}", file=sys.stderr)
        sys.exit(1)

    #--- 5. Print Unique Case IDs ---
    #Sort the UUIDs for consistent output (optional but good practice)
    sorted_case_ids = sorted(list(unique_case_ids))

    for case_uuid in sorted_case_ids:
        #Print each unique UUID in the specified format
        print(f"> Case: {case_uuid}")

    #--- 6. Exit Success ---
    sys.exit(0) #Exit with success status

#This file is intended to be imported and run by Main.py, so no __main__ block here.