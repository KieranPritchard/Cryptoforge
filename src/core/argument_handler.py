import argparse

def build_parser():
    """Build and configure the command-line argument parser"""
    parser = argparse.ArgumentParser(  # Create argument parser instance
        description="Personal cryptography utility"
    )

    # Main function selector
    parser.add_argument("function", help="Primary function to execute")  # Required positional argument for algorithm/function

    # ---- Key management ----
    parser.add_argument("--save-key", type=str)           # Path or identifier to save a generated key
    parser.add_argument("--new-key-name", type=str)       # Label to assign to a newly created key
    parser.add_argument("--key-type", type=str)           # The category of key (e.g., symmetric vs asymmetric)

    parser.add_argument("--load-key", type=str)           # Name or path of the key to load from storage
    parser.add_argument("--list-keys", action="store_true") # Flag to display all keys currently in the database/folder

    parser.add_argument("--rename-key", action="store_true") # Flag to initiate a key renaming operation
    parser.add_argument("--old-name", type=str)           # The current name of the key to be changed
    parser.add_argument("--new-name", type=str)           # The target name for the key being renamed

    parser.add_argument("--delete-key", type=str)         # Name of the key to be permanently removed

    # ---- Key creation ----
    parser.add_argument("--aes-key", action="store_true")       # Flag to generate a new AES key
    parser.add_argument("--blowfish-key", action="store_true")  # Flag to generate a new Blowfish key
    parser.add_argument("--chacha20-key", action="store_true")  # Flag to generate a new ChaCha20 key
    parser.add_argument("--rsa-private-key", action="store_true") # Flag to generate an RSA private key pair
    parser.add_argument("--rsa-public-key", action="store_true")  # Flag to extract/save an RSA public key
    parser.add_argument("--ecc-private-key", action="store_true") # Flag to generate Elliptic Curve private key
    parser.add_argument("--ecc-public-key", action="store_true")  # Flag to generate Elliptic Curve public key
    parser.add_argument("--ecdsa-private-key", action="store_true") # Flag to generate keys for ECDSA signatures
    parser.add_argument("--ecdsa-public-key", action="store_true")  # Flag to handle ECDSA public key operations

    parser.add_argument("--bit-size", type=int)           # Strength of the key (e.g., 2048 for RSA, 256 for AES)
    parser.add_argument("--nonce", type=str)              # Number used once; required for stream ciphers like ChaCha20

    # ---- Operations ----
    parser.add_argument("--operation", type=str)          # Sub-action to perform (e.g., encrypt, decrypt, sign, verify)
    parser.add_argument("--input", type=str)              # Path to the input file or the raw input string
    parser.add_argument("--output", type=str)             # Path where the resulting data should be saved
    parser.add_argument("--key", type=str)                # The actual key string or path to the key file to be used
    parser.add_argument("--iv", type=str)                 # Initialization Vector for block cipher modes like CBC
    parser.add_argument("--message", type=str)            # Direct message string for quick crypto operations
    parser.add_argument("--signature", type=str)          # Path to or string of a digital signature for verification

    # ---- Hashing ----
    parser.add_argument("--hash-type", type=str)          # Algorithm to use (e.g., sha256, md5, blake2b)
    parser.add_argument(
        "--output-format",
        choices=["hex", "bytes"],
        default="hex"                                     # Format for hash display (defaulting to readable hex)
    )

    # ---- TLS / Networking ----
    parser.add_argument("--host", type=str, default="127.0.0.1") # Target IP address or hostname for TLS connections
    parser.add_argument("--port", type=int, default=4433)        # Target port number for the TLS server or client
    parser.add_argument("--cert", type=str)                      # Path to the X.509 certificate file (.pem)
    parser.add_argument("--ca-file", type=str)                   # Path to a Trusted CA file to verify remote certificates

    # ---- Flags ----
    parser.add_argument("--plaintext", action="store_true") # Flag to treat input as raw text instead of a file path
    
    # ---- File Integrity ----
    parser.add_argument("--expected-hash", type=str, help="Expected hash for verification")  # Expected hash value for file integrity verification

    return parser  # Return configured parser