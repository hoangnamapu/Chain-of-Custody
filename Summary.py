import os
import sys
from Data_Struct import Block, unpack_block, BLOCK_HEADER_SIZE

def handle_summary(args):

    if not hasattr(args, 'c') or not args.c:
        print("Error: case_id is required for summary command", file=sys.stderr)
        sys.exit(1)

    case_id = args.c
    file_path = os.getenv('BCHOC_FILE_PATH', 'blockchain.bin')

    if not os.path.exists(file_path):
        print("Blockchain file not found. Please initialize first", file=sys.stderr)
        sys.exit(1)
    try:
        blocks = read_blocks(file_path)
        generate_summary(case_id, blocks)
        sys.exit(0)
    except Exception as e:
        print(f"Error generating summary: {str(e)}", file=sys.stderr)

def read_blocks(file_path):
    blocks = []
    with open(file_path, 'rb') as f:
        while True:
            header = f.read(BLOCK_HEADER_SIZE)
            if not header:
                break
            
            data_length = int.from_bytes(header[140:144], byteorder='little')
            data = f.read(data_length) if data_length > 0 else b''

            block_bytes = header + data
            block_dict = unpack_block(block_bytes)
            if block_dict:
                blocks.append(block_dict)
    return blocks

def generate_summary(case_id, blocks):
    #Filter blocks for the specified case
    case_blocks = []
    for block in blocks:
        if block['state_str'] == 'INITIAL':
            continue

        #Compare case IDs (using the string representation)
        try:
            if block['encrypted_case_id'].decode('ascii', errors='ignore').startswith(case_id):
                case_blocks.append(block)
        except:
            continue

    if not case_blocks:
        print(f"No blocks found for casse ID: {case_id}", file=sys.stderr)
        sys.exit(1)

    #Tracking items
    item_states = {}
    state_counts = {
        'CHECKEDIN': 0,
        'CHECKEDOUT': 0,
        'DISPOSED': 0,
        'DESTROYED': 0,
        'RELEASED': 0,
    }

    for block in case_blocks:
        item_id = block['encrypted_evidence_id']
        state = block['state_str']

        #Track most recent state for each item
        item_states[item_id] = state

    #Count states
    for state in item_states.values():
        if state in state_counts:
            state_counts[state] += 1

    #Print summary
    print(f"Case Summary for the Case ID: {case_id}")
    print(f"Total Evidence Items: {len(item_states)}")
    print(f"Checked In: {state_counts['CHECKEDIN']}")
    print(f"Checked Out: {state_counts['CHECKEDOUT']}")
    print(f"Disposed: {state_counts['DISPOSED']}")
    print(f"Destroyed: {state_counts['DESTROYED']}")
    print(f"Releaseed: {state_counts['RELEASED']}")

