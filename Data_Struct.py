#Data_Struct.py
#Defines the block structure, constants, encryption, packing/unpacking
#for the Blockchain Chain of Custody project.
#Meant to be imported by Main.py and other modules.

import hashlib
import uuid
import struct
import time
from datetime import datetime, timezone

#--- Required External Library ---
#Needs: pip install cryptography OR apt install python3-cryptography, at least with what google says. It works on Michael's machine, should work. Remind him with
#A new requirements.txt if others need to install what he has.
#TODO: MAKE THIS LISTED IN PACKAGES FILE FOR GRADESCROPE
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.backends import default_backend
except ImportError:
    #This error should ideally be handled by the main script that imports this module
    #But print a message here for clarity during development.
    print("ERROR: The 'cryptography' library is required but not found in Data_Struct.py.")
    #Re-raise the error so the importing script knows something went wrong, and we do too.
    raise

#--- Constants based on Spec ---
#Field sizes from Data Structure table (page 5)
PREV_HASH_SIZE = 32
TIMESTAMP_SIZE = 8  #double/float (64 bits)
CASE_ID_SIZE = 32   #Encrypted UUID (Ciphertext size, 256 bits)
EVIDENCE_ID_SIZE = 32 #Encrypted 4-byte int (Ciphertext size, 256 bits)
STATE_SIZE = 12     #96 bits
CREATOR_SIZE = 12   #96 bits
OWNER_SIZE = 12     #96 bits (Derived from offsets 0x8C - 0x80 = 12 bytes)
DATA_LEN_SIZE = 4   #32 bits

#-- Project Specific Constants ---
PROJECT_AES_KEY = b"R0chLi4uLi4uLi4=" #Hardcoded 16 bytes = AES-128 (Page 8)

ALLOWED_STATES = {"INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"} #Page 5
ALLOWED_OWNERS = {"Police", "Lawyer", "Analyst", "Executive"} #Page 5

#Struct format string recommended on Page 6
BLOCK_HEADER_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_HEADER_SIZE = struct.calcsize(BLOCK_HEADER_FORMAT) #Calculate once

#--- AES Configuration ---
AES_BLOCK_SIZE_BYTES = algorithms.AES.block_size // 8 #Should be 16 for AES-128

#--- Helper Functions ---

def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    """Encrypts plaintext using AES ECB mode with PKCS7 padding."""
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes long")

    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypts ciphertext using AES ECB mode with PKCS7 unpadding."""
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    #Ensure ciphertext is valid for decryption
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE_BYTES != 0:
        raise ValueError("Ciphertext must be non-empty and a multiple of the AES block size")

    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError as e:
        #Catches padding errors, etc. Indicates bad key or corrupt data.
        raise ValueError(f"Decryption failed, likely invalid key or ciphertext: {e}") from e
    return plaintext

def funny_number():
    return 69

#--- Genesis Block Creation ---

def create_genesis_block_bytes() -> bytes:

    # I am losing it
    prev_hash = bytes(PREV_HASH_SIZE) # 32 zero bytes as per '0' in table
    timestamp = 0.0 # 8 byte float zero as per '0' in table

    # --- FIX for Genesis Case ID Literal (#001, #002, #003, #007, #008, #009 failures) ---
    case_id_bytes = b'0' * CASE_ID_SIZE # 32 bytes of ASCII '0' characters


    # --- FIX for Genesis Evidence ID Literal (#001, #002, #003, #007, #008, #009 failures) ---
    evidence_id_bytes = b'0' * EVIDENCE_ID_SIZE # 32 bytes of ASCII '0' characters


    state_bytes = b"INITIAL\0\0\0\0\0" # EXACT 12-byte literal from the table
    creator_bytes = b'\x00' * CREATOR_SIZE # 12 null bytes as per literal in table
    owner_bytes = b'\x00' * OWNER_SIZE # 12 null bytes as per literal in table

    data_length = 14 # 4 byte integer as per specified value
    data = b"Initial block\0" # 14 bytes as per specified value

    try:
        # Pack the header using the defined format and the exact byte literals
        packed_header = struct.pack(
            BLOCK_HEADER_FORMAT,
            prev_hash,
            timestamp,
            case_id_bytes, # Use the 32 ASCII '0' bytes
            evidence_id_bytes, # Use the 32 ASCII '0' bytes
            state_bytes, # Use the 12-byte literal
            creator_bytes, # Use the 12 null bytes
            owner_bytes, # Use the 12 null bytes
            data_length
        )
        # Concatenate header and data
        return packed_header + data
    except struct.error as e:
        # This failure should not happen with fixed data unless BLOCK_HEADER_FORMAT is wrong
        raise RuntimeError(f"Internal error: Failed to pack genesis block: {e}") from e

#--- Block Class (For non-Genesis blocks) ---

class Block:
    def __init__(self,
                 previous_hash: bytes | int,
                 case_id: uuid.UUID,
                 evidence_item_id: int,
                 state: str,
                 creator: str,
                 owner: str,
                 data: bytes,
                 aes_key: bytes = PROJECT_AES_KEY,
                 timestamp=None):

        self.encrypted_case_id = self._encrypt_uuid(case_id, aes_key)
        self.encrypted_case_id = self._encrypt_envidence_id(evidence_item_id, aes_key)

        # Accept integer 0 for prev_hash and store as int, else validate as bytes
        if previous_hash == 0:
            self.previous_hash = 0
        elif isinstance(previous_hash, bytes) and len(previous_hash) == PREV_HASH_SIZE:
            self.previous_hash = previous_hash
        else:
            raise ValueError(f"Block init failed: previous_hash must be {PREV_HASH_SIZE} bytes or integer 0")

        #--- Input Validation ---
        if not isinstance(case_id, uuid.UUID):
            raise TypeError("Block init failed: case_id must be a uuid.UUID object")
        if not isinstance(evidence_item_id, int) or not (0 <= evidence_item_id < 2**32):
             raise ValueError("Block init failed: evidence_item_id must be a non-negative integer representable in 4 bytes")
        if state == "INITIAL":
             raise ValueError("Block init failed: State 'INITIAL' is reserved for the Genesis block only.")
        if state not in ALLOWED_STATES:
            raise ValueError(f"Block init failed: State '{state}' is not valid. Allowed: {ALLOWED_STATES - {'INITIAL'}}")
        try:
            creator_bytes = creator.encode('utf-8')
        except UnicodeEncodeError as e:
             raise ValueError(f"Block init failed: Creator contains invalid UTF-8 characters: {e}") from e
        if len(creator_bytes) > CREATOR_SIZE:
             raise ValueError(f"Block init failed: Creator '{creator}' exceeds max length of {CREATOR_SIZE} bytes when UTF-8 encoded")

        #--- FIX for Add Command Owner (#008, #007, #009 etc. failures) ---
        try:
            owner_bytes_unpadded = owner.encode('utf-8')
        except UnicodeEncodeError as e:
             raise ValueError(f"Block init failed: Owner contains invalid UTF-8 characters: {e}") from e

        if owner == "":
            self.owner = bytes(OWNER_SIZE)
            self._original_owner = ""
        else:
            if owner not in ALLOWED_OWNERS:
                raise ValueError(f"Block init failed: Owner '{owner}' is not valid. Allowed: {ALLOWED_OWNERS}")
            if len(owner_bytes_unpadded) > OWNER_SIZE:
                raise ValueError(f"Block init failed: Owner '{owner}' exceeds max length of {OWNER_SIZE} bytes when UTF-8 encoded")
            self.owner = owner_bytes_unpadded.ljust(OWNER_SIZE, b'\0')
            self._original_owner = owner

        if not isinstance(data, bytes):
             raise TypeError("Block init failed: data must be bytes")
        if len(data) >= 2**32:
             raise ValueError("Block init failed: Data length exceeds maximum allowed (2^32 bytes)")
        if len(aes_key) not in [16, 24, 32]:
             raise ValueError(f"Block init failed: AES key must be 16, 24, or 32 bytes long (got {len(aes_key)})")

        self._original_case_id = case_id
        self._original_evidence_item_id = evidence_item_id
        self._original_state = state
        self._original_creator = creator
        self._original_owner = owner
        self._aes_key = aes_key

        self.timestamp_float = datetime.now(timezone.utc).timestamp()
        self.timestamp_iso = datetime.fromtimestamp(self.timestamp_float, timezone.utc).isoformat()

        # Store the raw 16 UUID bytes, padded to 32 bytes (no encryption for case_id)
        self.encrypted_case_id = case_id.bytes.ljust(CASE_ID_SIZE, b'\0')

        evidence_id_bytes_4 = evidence_item_id.to_bytes(4, 'big')
        encrypted_evidence_id_16 = encrypt_aes_ecb(aes_key, evidence_id_bytes_4)
        self.encrypted_evidence_id = encrypted_evidence_id_16.ljust(EVIDENCE_ID_SIZE, b'\0')

        self.state = state.encode('utf-8').ljust(STATE_SIZE, b'\0')
        self.creator = creator_bytes.ljust(CREATOR_SIZE, b'\0')
        #self.owner is already set above

        self.data_length = len(data)
        self.data = data

    def _encrypt_uuid(self, uuid_obj, aes_key):
        """Encrypt a UUID object using AES ECB"""
        cipher = cipher.AES.new(aes_key, cipher.AES.MODE_ECB)
        uuid_bytes = uuid_obj.bytes
        return cipher.encrypt(uuid_bytes)
    
    def _encrypt_evidence_id(self, item_id, aes_key):
        """Encrypt a 4-byte evidence ID using AES ECB"""
        cipher = cipher.AES.new(aes_key, cipher.AES.MODE_ECB)
        item_bytes = item_id.to_bytes(4, 'big')
        padded = item_bytes.ljust(16, b'\x00')
        return cipher.encrypt(padded)

    def pack(self) -> bytes:
        try:
            # Convert int 0 to 32 null bytes for struct.pack
            prev_hash_bytes = b'\x00' * PREV_HASH_SIZE if self.previous_hash == 0 else self.previous_hash
            packed_header = struct.pack(
                BLOCK_HEADER_FORMAT,
                prev_hash_bytes,
                self.timestamp_float,
                self.encrypted_case_id,
                self.encrypted_evidence_id,
                self.state,
                self.creator,
                self.owner,
                self.data_length
            )
            return packed_header + self.data
        except struct.error as e:
            raise RuntimeError(f"Internal error: Failed to pack block data: {e}") from e

    def calculate_hash(self) -> bytes:
        #Calculates the SHA-256 hash of the packed block data
        #Assumes pack() works if __init__ succeeded.
        packed_data = self.pack()
        return hashlib.sha256(packed_data).digest()

    #--- Accessor Methods for Original/Decoded Data ---
    #Useful for display logic in other modules without needing to unpack raw bytes again.

    def get_original_case_id(self) -> uuid.UUID: return self._original_case_id
    def get_original_evidence_id(self) -> int: return self._original_evidence_item_id
    def get_original_state(self) -> str: return self._original_state
    def get_original_creator(self) -> str: return self._original_creator
    def get_original_owner(self) -> str: return self._original_owner
    def get_timestamp_iso(self) -> str: return self.timestamp_iso
    def get_data(self) -> bytes: return self.data

    def get_state_str(self) -> str:
        #Returns the state string, decoded from stored padded bytes
        return self.state.split(b'\0', 1)[0].decode('utf-8', errors='replace')

    def get_creator_str(self) -> str:
        #Returns the creator string, decoded from stored padded bytes
        return self.creator.split(b'\0', 1)[0].decode('utf-8', errors='replace')

    def get_owner_str(self) -> str:
        #Returns the owner string, decoded from stored padded bytes
        return self.owner.split(b'\0', 1)[0].decode('utf-8', errors='replace')

    #--- Decryption Methods ---
    #These require the correct AES key. They might be called by 'show' commands
    #after password validation provides the necessary context/permission.

    def decrypt_case_id(self, key: bytes = None) -> uuid.UUID | None:
        try:
            uuid_bytes = self.encrypted_case_id[:16]
            if len(uuid_bytes) != 16:
                return None
            return uuid.UUID(bytes=uuid_bytes)
        except (ValueError, TypeError, Exception):
            return None

    def decrypt_evidence_id(self, key: bytes = None) -> int | None:
       
        use_key = key if key is not None else self._aes_key
        if not use_key: return None #Cannot decrypt without a key
        try:
            #The actual ciphertext is the first 16 bytes before padding
            decrypted_padded_bytes = decrypt_aes_ecb(use_key, self.encrypted_evidence_id[:AES_BLOCK_SIZE_BYTES])
            #Original data was 4 bytes, little-endian
            original_bytes = decrypted_padded_bytes[:4]
            if len(original_bytes) < 4:
                raise ValueError("Decrypted bytes insufficient for 4-byte integer conversion")
            return int.from_bytes(original_bytes, 'big')
        except (ValueError, TypeError, Exception): #Catch decryption/int conversion errors
            return None #Indicate failure


#--- Block Unpacking Function (Standalone) ---

def unpack_block(block_bytes: bytes) -> dict | None:
    #
    #Unpacks raw block bytes read from the file into a dictionary containing the
    #stored fields (header + data). Does NOT create a full Block object or
    #perform decryption. Essential for reading/verifying the chain.

    #Args:
    #   block_bytes: The raw bytes of a single block (header + data).

    #Returns:
    #   A dictionary containing the unpacked fields if successful. Keys include:
    #     'previous_hash', 'timestamp_float', 'encrypted_case_id',
    #     'encrypted_evidence_id', 'state' (bytes), 'creator' (bytes),
    #     'owner' (bytes), 'data_length', 'data' (bytes), 'raw_bytes' (original input),
    #     'data_valid' (bool: checks if data length matches payload size),
    #     'state_str', 'creator_str', 'owner_str', 'timestamp_iso'.
    #   Returns None if unpacking fails (e.g., insufficient bytes, format mismatch).
    #
    if not isinstance(block_bytes, bytes):
        #Ensure input is bytes
        return None
    if len(block_bytes) < BLOCK_HEADER_SIZE:
        #Not enough bytes for even the header
        return None

    try:
        header_bytes = block_bytes[:BLOCK_HEADER_SIZE]
        unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
        prev_hash_val = unpacked_header[0]
        # If prev_hash is all null bytes, treat as 0 for display
        prev_hash_display = 0 if prev_hash_val == b'\x00' * PREV_HASH_SIZE else prev_hash_val

        #Extract the variable-length data payload
        data_payload = block_bytes[BLOCK_HEADER_SIZE:]
        #Get the declared data length from the unpacked header (index 7 is 'I')
        declared_data_len = unpacked_header[7]

        #--- Data Integrity Check ---
        data_valid = (len(data_payload) == declared_data_len)
        #Note: The verification logic in verify.py MUST check this 'data_valid' flag.

        #--- Decode Strings and Format Timestamp (for convenience) ---
        #Use error='replace' to handle potential bad bytes in stored strings
        state_str = unpacked_header[4].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        creator_str = unpacked_header[5].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        owner_str = unpacked_header[6].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        #Handle genesis block timestamp (0.0) separately for ISO conversion
        timestamp_val = unpacked_header[1]
        timestamp_iso = "N/A (Genesis)" if timestamp_val == 0.0 else datetime.fromtimestamp(timestamp_val, timezone.utc).isoformat()

        #--- Construct Result Dictionary ---
        block_dict = {
            'previous_hash': prev_hash_display,
            'timestamp_float': timestamp_val,
            'encrypted_case_id': unpacked_header[2],  # This is the raw 16 UUID bytes padded to 32 now
            'encrypted_evidence_id': unpacked_header[3][:16].hex(),
            'state': unpacked_header[4],         #Raw bytes state field
            'creator': unpacked_header[5],       #Raw bytes creator field
            'owner': unpacked_header[6],         #Raw bytes owner field
            'data_length': declared_data_len,    #Declared length from header
            'data': data_payload,                #Actual data payload bytes
            'raw_bytes': block_bytes,            #The original bytes passed in (for hashing)
            #Processed/Convenience Fields
            'data_valid': data_valid,            #Result of data length check
            'state_str': state_str,              #Decoded state string
            'creator_str': creator_str,          #Decoded creator string
            'owner_str': owner_str,              #Decoded owner string
            'timestamp_iso': timestamp_iso,      #ISO 8601 formatted timestamp
        }
        return block_dict
    except (struct.error, UnicodeDecodeError, ValueError, OverflowError) as e:
        return None

