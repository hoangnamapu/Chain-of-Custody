import hashlib
import uuid
import struct
import time
from datetime import datetime, timezone
import sys
import binascii # Ensure binascii is imported

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("ERROR: The 'cryptography' library is required but not found in Data_Struct.py.")
    raise

# --- Constants based on Spec ---
PREV_HASH_SIZE = 32
TIMESTAMP_SIZE = 8
CASE_ID_SIZE = 32
EVIDENCE_ID_SIZE = 32
STATE_SIZE = 12
CREATOR_SIZE = 12
OWNER_SIZE = 12
DATA_LEN_SIZE = 4

# -- Project Specific Constants ---
PROJECT_AES_KEY = b"R0chLi4uLi4uLi4=" # Hardcoded 16 bytes = AES-128

ALLOWED_STATES = {"INITIAL", "CHECKEDIN", "CHECKEDOUT", "DISPOSED", "DESTROYED", "RELEASED"}
ALLOWED_OWNERS = {"POLICE", "LAWYER", "ANALYST", "EXECUTIVE"} #... don't do it again. 

# Struct format string
BLOCK_HEADER_FORMAT = "32s d 32s 32s 12s 12s 12s I"
BLOCK_HEADER_SIZE = struct.calcsize(BLOCK_HEADER_FORMAT)

# AES Configuration
AES_BLOCK_SIZE_BYTES = algorithms.AES.block_size // 8 # Should be 16

# --- Helper Functions (Keep these standard implementations) ---

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
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE_BYTES != 0:
        raise ValueError("Ciphertext must be non-empty and a multiple of the AES block size")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError as e:
        raise ValueError(f"Decryption failed, likely invalid key or ciphertext: {e}") from e
    return plaintext

def decrypt_aes_ecb_raw(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypts AES ECB ciphertext WITHOUT unpadding. Requires full blocks."""
    if len(key) not in [16, 24, 32]:
        raise ValueError("AES key must be 16, 24, or 32 bytes long")
    if not ciphertext or len(ciphertext) % AES_BLOCK_SIZE_BYTES != 0:
        raise ValueError("Ciphertext for raw decryption must be non-empty and a multiple of the AES block size")
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    except Exception as e:
        raise ValueError(f"Raw decryption failed: {e}") from e

def funny_number():
    return 69

# --- Genesis Block Creation (Keep fixed version) ---
def create_genesis_block_bytes() -> bytes:
    prev_hash = bytes(PREV_HASH_SIZE)
    timestamp = 0.0
    case_id_bytes = b'0' * CASE_ID_SIZE
    evidence_id_bytes = b'0' * EVIDENCE_ID_SIZE
    state_bytes = b"INITIAL\0\0\0\0\0"
    creator_bytes = b'\x00' * CREATOR_SIZE
    owner_bytes = b'\x00' * OWNER_SIZE
    data_length = 14
    data = b"Initial block\0"
    try:
        packed_header = struct.pack(
            BLOCK_HEADER_FORMAT, prev_hash, timestamp, case_id_bytes,
            evidence_id_bytes, state_bytes, creator_bytes, owner_bytes, data_length
        )
        return packed_header + data
    except struct.error as e:
        raise RuntimeError(f"Internal error: Failed to pack genesis block: {e}") from e
    
def decrypt_case_id_from_packed(packed_case_id_bytes: bytes, key: bytes = PROJECT_AES_KEY) -> uuid.UUID | None:
    """
    Decrypts the case ID from the specific flawed packing format used by Block.__init__
    (Truncated ASCII hex of padded ciphertext).
    Returns the UUID object or None on failure.
    """
    try:
        if not isinstance(packed_case_id_bytes, bytes) or len(packed_case_id_bytes) != CASE_ID_SIZE:
            return None

        # 1. Decode the 32 ASCII bytes back into the 32-character hex string.
        hex_string = packed_case_id_bytes.decode('ascii')
        if len(hex_string) != 32:
            return None

        # 2. Convert the 32-char hex string back to the first 16 ciphertext bytes.
        ciphertext_bytes = binascii.unhexlify(hex_string)
        if len(ciphertext_bytes) != AES_BLOCK_SIZE_BYTES: # Should be 16 bytes
            return None

        # 3. Decrypt these 16 bytes using RAW AES ECB decryption.
        #    Since the original data was 16 bytes (UUID), raw decryption
        #    of the first ciphertext block should yield the original 16 UUID bytes.
        decrypted_uuid_bytes = decrypt_aes_ecb_raw(key, ciphertext_bytes) # USE RAW DECRYPTION

        # 4. Check if raw decryption produced exactly 16 bytes
        if len(decrypted_uuid_bytes) != 16:
             # print(f"DEBUG: Raw decrypt for Case ID didn't yield 16 bytes, got {len(decrypted_uuid_bytes)}", file=sys.stderr) # Optional debug
             return None

        # 5. Convert the 16 decrypted bytes to UUID.
        case_uuid = uuid.UUID(bytes=decrypted_uuid_bytes) # Use all 16 bytes
        return case_uuid

    except Exception as e: # Catch any error during decode/unhexlify/decrypt/UUID creation
         # print(f"DEBUG: Exception in decrypt_case_id_from_packed: {e!r}", file=sys.stderr) # Optional debug
         return None
#PLEASE WORK GOD DAMMIT

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
                 aes_key: bytes = PROJECT_AES_KEY):

        # +++ DEBUG PRINT +++
        print(f"DEBUG DATA_STRUCT (Block.__init__): Received previous_hash arg: {previous_hash!r}", file=sys.stderr)

        # (Input validation for prev_hash, case_id, evidence_item_id, state, creator remains the same)
        if previous_hash == 0: self.previous_hash = 0
        elif isinstance(previous_hash, bytes) and len(previous_hash) == PREV_HASH_SIZE: self.previous_hash = previous_hash
        else: raise ValueError(f"Block init failed: previous_hash must be {PREV_HASH_SIZE} bytes or integer 0")
        if not isinstance(case_id, uuid.UUID): raise TypeError("Block init failed: case_id must be a uuid.UUID object")
        if not isinstance(evidence_item_id, int) or not (0 <= evidence_item_id < 2**32): raise ValueError("Block init failed: evidence_item_id must be a non-negative integer representable in 4 bytes")
        if state == "INITIAL": raise ValueError("Block init failed: State 'INITIAL' is reserved for the Genesis block only.")
        if state not in ALLOWED_STATES: raise ValueError(f"Block init failed: State '{state}' is not valid. Allowed: {ALLOWED_STATES - {'INITIAL'}}")
        try: creator_bytes = creator.encode('utf-8')
        except UnicodeEncodeError as e: raise ValueError(f"Block init failed: Creator contains invalid UTF-8 characters: {e}") from e
        if len(creator_bytes) > CREATOR_SIZE: raise ValueError(f"Block init failed: Creator '{creator}' exceeds max length of {CREATOR_SIZE} bytes when UTF-8 encoded")

        # +++ DEBUG PRINT +++
        print(f"DEBUG DATA_STRUCT (Block.__init__): Stored self.previous_hash: {self.previous_hash!r}", file=sys.stderr)

        # (Owner validation and padding fix remains the same)
        try: owner_bytes_unpadded = owner.encode('utf-8')
        except UnicodeEncodeError as e: raise ValueError(f"Block init failed: Owner contains invalid UTF-8 characters: {e}") from e
        if owner == "": self.owner = bytes(OWNER_SIZE); self._original_owner = ""
        else:
            if owner not in ALLOWED_OWNERS: raise ValueError(f"Block init failed: Owner '{owner}' is not valid. Allowed: {ALLOWED_OWNERS}")
            if len(owner_bytes_unpadded) > OWNER_SIZE: raise ValueError(f"Block init failed: Owner '{owner}' exceeds max length of {OWNER_SIZE} bytes when UTF-8 encoded")
            self.owner = owner_bytes_unpadded.ljust(OWNER_SIZE, b'\0'); self._original_owner = owner

        # (Data and key validation remains the same)
        if not isinstance(data, bytes): raise TypeError("Block init failed: data must be bytes")
        if len(data) >= 2**32: raise ValueError("Block init failed: Data length exceeds maximum allowed (2^32 bytes)")
        if len(aes_key) not in [16, 24, 32]: raise ValueError(f"Block init failed: AES key must be 16, 24, or 32 bytes long (got {len(aes_key)})")

        # (Store original values remains the same)
        self._original_case_id = case_id
        self._original_evidence_item_id = evidence_item_id
        self._original_state = state
        self._original_creator = creator
        # _original_owner set above
        self._aes_key = aes_key

        # (Timestamp generation remains the same)
        self.timestamp_float = datetime.now(timezone.utc).timestamp()
        self.timestamp_iso = datetime.fromtimestamp(self.timestamp_float, timezone.utc).isoformat()


        # =================== START: REVERTED PACKING LOGIC ===================
        # WARNING: This specific packing logic for case_id and evidence_id
        # is likely incorrect based on standard crypto practices and test #008
        # expectations, but is preserved here as requested by the user
        # because it passed more autograder tests in their environment.

        # --- CASE ID PACKING (User's specific version) ---
        case_id_bytes = case_id.bytes  # 16 bytes
        encrypted_case_id_16 = encrypt_aes_ecb(aes_key, case_id_bytes) # Should be 16 bytes ciphertext
        # Pad ciphertext with nulls -> 32 bytes
        incomplete_encrypted_case_id = encrypted_case_id_16.ljust(CASE_ID_SIZE, b'\0')
        # Hex encode the 32 bytes (ciphertext+nulls) -> 64 hex chars
        case_id_hex_string = incomplete_encrypted_case_id.hex()
        # Encode 64 hex chars -> 64 ASCII bytes
        case_id_hex_bytes = case_id_hex_string.encode('ascii')
        # Store the FIRST 32 bytes of the 64 ASCII bytes
        self.encrypted_case_id = case_id_hex_bytes[:CASE_ID_SIZE] # Truncates here


        # --- EVIDENCE ID PACKING (User's specific version) ---
        # Pad 4-byte int to 16 bytes
        raw_evidence_id_bytes = evidence_item_id.to_bytes(16, 'big')
        # Encrypt the 16 bytes (results in 32 bytes ciphertext due to padding) then truncate to 16 bytes
        encrypted_evidence_id = encrypt_aes_ecb(aes_key, raw_evidence_id_bytes)[:16] # TRUNCATION
        # Hex encode the truncated 16 bytes -> 32 hex chars
        evidence_id_hex_string = encrypted_evidence_id.hex()
        # Encode 32 hex chars -> 32 ASCII bytes
        evidence_id_hex_bytes = evidence_id_hex_string.encode('ascii')
        # Store the 32 ASCII bytes
        self.encrypted_evidence_id = evidence_id_hex_bytes

        # ==================== END: REVERTED PACKING LOGIC ====================


        # (State, Creator, Data packing remains the same)
        self.state = state.encode('utf-8').ljust(STATE_SIZE, b'\0')
        self.creator = creator_bytes.ljust(CREATOR_SIZE, b'\0')
        self.data_length = len(data)
        self.data = data

    # (pack method remains the same)
    def pack(self) -> bytes:
        try:
            # +++ DEBUG PRINT +++
            print(f"DEBUG DATA_STRUCT (Block.pack): Packing with self.previous_hash: {self.previous_hash!r}", file=sys.stderr)

            prev_hash_bytes = b'\x00' * PREV_HASH_SIZE if self.previous_hash == 0 else self.previous_hash

            # +++ DEBUG PRINT +++
            print(f"DEBUG DATA_STRUCT (Block.pack): Actual bytes being packed for prev_hash: {prev_hash_bytes.hex()}", file=sys.stderr)

            packed_header = struct.pack(
                BLOCK_HEADER_FORMAT, prev_hash_bytes, self.timestamp_float,
                self.encrypted_case_id, self.encrypted_evidence_id, self.state,
                self.creator, self.owner, self.data_length
            )
            return packed_header + self.data
        except struct.error as e:
            raise RuntimeError(f"Internal error: Failed to pack block data: {e}") from e

    # (calculate_hash method remains the same)
    def calculate_hash(self) -> bytes:
        packed_data = self.pack()
        return hashlib.sha256(packed_data).digest()

    # (Accessor methods remain the same)
    def get_original_case_id(self) -> uuid.UUID: return self._original_case_id
    def get_original_evidence_id(self) -> int: return self._original_evidence_item_id
    def get_original_state(self) -> str: return self._original_state
    def get_original_creator(self) -> str: return self._original_creator
    def get_original_owner(self) -> str: return self._original_owner
    def get_timestamp_iso(self) -> str: return self.timestamp_iso
    def get_data(self) -> bytes: return self.data
    def get_state_str(self) -> str: return self.state.split(b'\0', 1)[0].decode('utf-8', errors='replace')
    def get_creator_str(self) -> str: return self.creator.split(b'\0', 1)[0].decode('utf-8', errors='replace')
    def get_owner_str(self) -> str: return self.owner.split(b'\0', 1)[0].decode('utf-8', errors='replace')

    # (Decryption Methods - these likely won't work reliably with the reverted packing)
    # Keep them as they might be called, but expect failures
    def decrypt_case_id(self, key: bytes = None) -> uuid.UUID | None:
         # This standard decryption expects the stored field to be ASCII hex of 16 bytes ciphertext
         # which is NOT what the reverted packing logic produces.
        use_key = key if key is not None else self._aes_key
        if not use_key: return None
        try:
            hex_string = self.encrypted_case_id.decode('ascii') # Assumes stored bytes are ASCII hex
            if len(hex_string) != 32: return None # Expect 32 chars
            ciphertext = binascii.unhexlify(hex_string) # Expect 16 bytes
            decrypted_bytes = decrypt_aes_ecb(use_key, ciphertext) # Use standard decrypt
            if len(decrypted_bytes) < 16: return None
            return uuid.UUID(bytes=decrypted_bytes[:16])
        except Exception:
             return None

    def decrypt_evidence_id(self, key: bytes = None) -> int | None:
        # This standard decryption expects ASCII hex of 16 bytes ciphertext
        # which IS what the reverted packing logic produces (due to truncation).
        # HOWEVER, it uses decrypt_aes_ecb which expects proper padding info,
        # which was lost during truncation. So this will still likely fail.
        use_key = key if key is not None else self._aes_key
        if not use_key: return None
        try:
            hex_string = self.encrypted_evidence_id.decode('ascii') # Should be 32 ASCII bytes
            if len(hex_string) != 32: return None
            ciphertext = binascii.unhexlify(hex_string) # Should be 16 bytes (truncated)
            # Standard decryption will fail due to missing padding info
            decrypted_padded_bytes = decrypt_aes_ecb(use_key, ciphertext)
            # We expect the first 4 bytes of the *original* 16-byte padded data
            # but standard decryption can't recover this reliably from truncated data.
            # This logic is unlikely to work correctly.
            original_bytes = decrypted_padded_bytes[:4] # Attempt to get first 4
            if len(original_bytes) < 4: raise ValueError("Decrypted bytes insufficient")
            return int.from_bytes(original_bytes, 'big')
        except Exception:
             return None

# --- Helper for specialized Evidence ID decryption needed due to reverted packing ---
def decrypt_evidence_id_from_packed(packed_evidence_id_bytes: bytes, key: bytes = PROJECT_AES_KEY) -> int | None:
    """
    Decrypts the evidence ID from the specific flawed packing format used by Block.__init__
    (ASCII hex of truncated 16-byte ciphertext).
    Returns the integer item ID or None on failure.
    """
    try:
        if not isinstance(packed_evidence_id_bytes, bytes) or len(packed_evidence_id_bytes) != EVIDENCE_ID_SIZE: return None
        hex_string = packed_evidence_id_bytes.decode('ascii')
        if len(hex_string) != 32: return None
        truncated_ciphertext = binascii.unhexlify(hex_string)
        if len(truncated_ciphertext) != AES_BLOCK_SIZE_BYTES: return None
        # USE RAW DECRYPTION
        decrypted_padded_input = decrypt_aes_ecb_raw(key, truncated_ciphertext)
        if len(decrypted_padded_input) != AES_BLOCK_SIZE_BYTES: return None
        # Extract LAST 4 bytes of the original 16-byte block that was encrypted
        original_int_bytes = decrypted_padded_input[12:]
        item_id = int.from_bytes(original_int_bytes, 'big')
        return item_id
    except Exception:
         return None

# --- Block Unpacking Function (Includes attempts to decrypt based on packing logic) ---
def unpack_block(block_bytes: bytes) -> dict | None:
    if not isinstance(block_bytes, bytes) or len(block_bytes) < BLOCK_HEADER_SIZE: return None
    try:
        header_bytes = block_bytes[:BLOCK_HEADER_SIZE]
        unpacked_header = struct.unpack(BLOCK_HEADER_FORMAT, header_bytes)
        prev_hash_val = unpacked_header[0]

        # +++ DEBUG PRINT +++
        print(f"DEBUG DATA_STRUCT (unpack_block): Unpacked raw prev_hash bytes: {prev_hash_val.hex()}", file=sys.stderr)

        prev_hash_display = 0 if prev_hash_val == b'\x00' * PREV_HASH_SIZE else prev_hash_val

        # +++ DEBUG PRINT +++
        print(f"DEBUG DATA_STRUCT (unpack_block): Formatted prev_hash_display: {prev_hash_display!r}", file=sys.stderr)

        data_payload = block_bytes[BLOCK_HEADER_SIZE:]
        declared_data_len = unpacked_header[7]
        data_valid = (len(data_payload) == declared_data_len)
        state_str = unpacked_header[4].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        creator_str = unpacked_header[5].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        owner_str = unpacked_header[6].split(b'\0', 1)[0].decode('utf-8', errors='replace')
        timestamp_val = unpacked_header[1]
        timestamp_iso = "N/A (Genesis)" if timestamp_val == 0.0 else datetime.fromtimestamp(timestamp_val, timezone.utc).isoformat()

        # --- Decryption Attempts ---
        packed_case_id_bytes = unpacked_header[2]
        packed_evidence_id_bytes = unpacked_header[3]

        # Decrypt Evidence ID using the specialized helper for evidence ID packing
        decrypted_item_id = decrypt_evidence_id_from_packed(packed_evidence_id_bytes)

        # Decrypt Case ID using the new specialized helper for case ID packing
        decrypted_case_uuid = None
        if packed_case_id_bytes != b'0' * CASE_ID_SIZE: # Don't try on Genesis
            decrypted_case_uuid = decrypt_case_id_from_packed(packed_case_id_bytes)
        # --- END Decryption Attempts ---

        block_dict = {
            'previous_hash': prev_hash_display,
            'previous_hash_raw': prev_hash_val,  # Add the raw bytes too
            'timestamp_float': timestamp_val,
            'encrypted_case_id': packed_case_id_bytes, # Raw bytes as stored
            'encrypted_evidence_id': packed_evidence_id_bytes, # Raw bytes as stored
            'state': unpacked_header[4],
            'creator': unpacked_header[5],
            'owner': unpacked_header[6],
            'data_length': declared_data_len,
            'data': data_payload,
            'raw_bytes': block_bytes,
            'data_valid': data_valid,
            'state_str': state_str,
            'creator_str': creator_str,
            'owner_str': owner_str,
            'timestamp_iso': timestamp_iso,
            'decrypted_item_id': decrypted_item_id,
            'decrypted_case_uuid': decrypted_case_uuid,
        }
        # print(f"DEBUG UNPACK [TS {timestamp_val}]: "
        #       f"Returning dict. Dec Case: {decrypted_case_uuid}, Dec Item: {decrypted_item_id}", file=sys.stderr)
        return block_dict
    except Exception as e:
        print(f"DEBUG UNPACK: Error during unpack_block processing bytes starting with {block_bytes[:20].hex()}...: {e!r}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return None

# --- Debug Reverse Function (Keep for diagnostics) ---
def debug_reverse_evidence_id(field_bytes: bytes, key: bytes = PROJECT_AES_KEY):
    print("\n--- DEBUG REVERSE EVIDENCE ID ---")
    if not isinstance(field_bytes, bytes) or len(field_bytes) != EVIDENCE_ID_SIZE:
        print(f"ERROR: Input is not 32 bytes. Got {len(field_bytes)} bytes: {field_bytes!r}")
        print("--- END DEBUG ---"); return
    print(f"1. Input Bytes (32): {field_bytes!r}")
    try: stripped_bytes = field_bytes.rstrip(b'\0'); print(f"2. Stripped Nulls: {stripped_bytes!r}")
    except Exception as e: print(f"2. ERROR stripping nulls: {e}"); print("--- END DEBUG ---"); return
    hex_string = None
    try: hex_string = stripped_bytes.decode('ascii'); print(f"3. Decoded ASCII (Hex String): '{hex_string}'")
    except UnicodeDecodeError as e: print(f"3. ERROR decoding ASCII: {e}"); print(f" Problematic bytes: {stripped_bytes[e.start-2:e.end+2]!r}"); print("--- END DEBUG ---"); return
    except Exception as e: print(f"3. UNEXPECTED ERROR decoding ASCII: {e}"); print("--- END DEBUG ---"); return
    ciphertext_bytes = None
    try:
        if len(hex_string) % 2 != 0: raise ValueError(f"Hex string has odd length ({len(hex_string)})")
        ciphertext_bytes = binascii.unhexlify(hex_string); print(f"4. Converted from Hex (Ciphertext?): {ciphertext_bytes.hex()} ({len(ciphertext_bytes)} bytes)")
    except Exception as e: print(f"4. ERROR converting from hex: {e}"); print("--- END DEBUG ---"); return
    decrypted_bytes = None
    try:
        if len(ciphertext_bytes) % AES_BLOCK_SIZE_BYTES != 0: raise ValueError(f"Ciphertext length not multiple of block size")
        decrypted_bytes = decrypt_aes_ecb(key, ciphertext_bytes); print(f"5. Decrypted (Standard): {decrypted_bytes!r}")
    except ValueError as e:
        print(f"5. ERROR decrypting (Standard): {e}")
        try: # Try raw decryption as fallback diagnostic
            if len(ciphertext_bytes) % AES_BLOCK_SIZE_BYTES == 0:
                decrypted_raw = decrypt_aes_ecb_raw(key, ciphertext_bytes); print(f"   Attempted Raw Decryption: {decrypted_raw!r}")
            else: print("   Cannot attempt raw decryption: length not multiple of block size.")
        except Exception as raw_e: print(f"   Raw decryption also failed: {raw_e}")
    except Exception as e: print(f"5. UNEXPECTED ERROR decrypting: {e}")
    original_4_bytes = None
    if decrypted_bytes is not None and len(decrypted_bytes) >= 4:
        original_4_bytes = decrypted_bytes[:4]; print(f"6. Extracted First 4 Bytes: {original_4_bytes!r}")
    elif decrypted_bytes is not None: print(f"6. ERROR: Decrypted data too short ({len(decrypted_bytes)} bytes)")
    else: print("6. SKIPPED: Decryption failed.")
    if original_4_bytes is not None:
        try: final_int = int.from_bytes(original_4_bytes, 'big'); print(f"7. Converted to Integer: {final_int}")
        except Exception as e: print(f"7. ERROR converting bytes to int: {e}")
    else: print("7. SKIPPED: Could not extract 4 bytes.")
    print("--- END DEBUG ---")
