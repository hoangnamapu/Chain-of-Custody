#init.py
#Simple job: Initiate if doesn't exist genesis, or check if it's correct.

import os
import sys

try:
    #Import specific functions/classes needed for initialization
    from Data_Struct import create_genesis_block_bytes, BLOCK_HEADER_SIZE
except ImportError as e:
    #If Data_Struct cannot be imported, init cannot function.
    print(f"ERROR (in init.py): Could not import required components from Data_Struct.py: {e}", file=sys.stderr)
    print("Ensure Data_Struct.py exists and is in the same folder.", file=sys.stderr)
    sys.exit(1) #Exit immediately if dependencies are missing


def initialize_blockchain():
    #Handles the blockchain initialization logic.
    #Checks for blockchain file existence and validity based on BCHOC_FILE_PATH.
    #Creates the file with a Genesis block if it doesn't exist.
    #Verifies the Genesis block if the file does exist.
    #Prints status messages and exits with appropriate status code (0 is ok, 1 is error. Maybe change later for easier debugging via big text?). 
 
    #Get the blockchain file path from environment variable, I did ' export BCHOC_FILE_PATH="chain.bin" '. Maybe that's correct with the doc? we need to test.
    blockchain_file_path = os.environ.get('BCHOC_FILE_PATH')
    if not blockchain_file_path:
        #This check remains crucial here.
        print("CRITICAL: BCHOC_FILE_PATH environment variable not set. Cannot proceed.", file=sys.stderr)
        sys.exit(1)

    try:
        #Generate the exact byte sequence expected for the Genesis block
        expected_genesis_bytes = create_genesis_block_bytes()
        expected_genesis_size = len(expected_genesis_bytes) #Get expected size

        if not os.path.exists(blockchain_file_path):
            #--- File does not exist: Create it ---
            print(f"Blockchain file not found. Created INITIAL block.")
            try:
                with open(blockchain_file_path, 'wb') as f:
                    f.write(expected_genesis_bytes)
                #If write succeeds without error, initialization is successful
                sys.exit(0) #Success exit
            except IOError as e:
                print(f"Error: Could not create or write to blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
                #Attempt cleanup if file was partially created
                if os.path.exists(blockchain_file_path):
                    try:
                        os.remove(blockchain_file_path)
                    except OSError:
                        pass #Ignore error during cleanup attempt
                sys.exit(1) #Non-zero exit for the I/O error
            except RuntimeError as e: #Catch potential error from create_genesis_block_bytes
                 print(f"Error: Could not generate genesis block bytes: {e}", file=sys.stderr)
                 sys.exit(1)

        else:
            #--- File exists: Verify its starting content ---
            try:
                with open(blockchain_file_path, 'rb') as f:
                    #Read only the number of bytes expected for the genesis block
                    existing_start_bytes = f.read(expected_genesis_size)

                #Compare the bytes read with the expected genesis bytes
                if len(existing_start_bytes) == expected_genesis_size and existing_start_bytes == expected_genesis_bytes:
                    #The file exists, is large enough, and starts with the correct Genesis block
                    print(f"Blockchain file found with INITIAL block.")
                    sys.exit(0) #Success exit
                else:
                    #The file exists, but is either too short or doesn't match
                    print(f"Error: Blockchain file '{blockchain_file_path}' exists but has invalid content.", file=sys.stderr)
                    print("       It may be corrupted or not initialized correctly.", file=sys.stderr)
                    sys.exit(1) #Non-zero exit for invalid content error

            except IOError as e:
                print(f"Error: Could not read existing blockchain file '{blockchain_file_path}': {e}", file=sys.stderr)
                sys.exit(1) #Non-zero exit for the I/O error

    except Exception as e:
        #Catch any other unexpected errors during this process
        print(f"An unexpected error occurred during initialization process: {e}", file=sys.stderr)
        sys.exit(1) #Non-zero exit for unexpected errors
