#Data structure

#Offset 0x00, 32 bytes Previous Hash - SHA-256 hash of parent block
#Offset 0x20, 8 bytes, Timestamp in regular unix format. Must be printed in ISO 8601 format, stored as float/double.
#Offset 0x28, 32 bytes, Case ID - UUID (encrypted with AES ECB, stored as hex)
#Offset 0x48, 32 bytes, Evidence Item ID - 4-bytes integer (encrypted with AES ECB, stored as hex)
#Offset 0x68, 12** bytes, State - Must be one of: INITIAL (for initial block ONLY), CHECKEDIN, CHECKEDOUT, DISPOSED, DESTROYED, or RELEASED
#Offset 0x74, 12 bytes, Creator - Free form text with max 12 characters
#Offset 0x80, 12 bytes, Owner - Free Form text with max 16 characters (Must be one of Police, Lawyer, Anal)
#Offset 0x8C, 4 bytes, Data Length - 4 byte integer
#Offset 0x90, 0 to (2^32) bytes (oh god this test will be fun), Data - Free form text with max 2^32 bytes

def funny_number():
    #This is just here to make sure everything is working correctly LMAO
    return 69