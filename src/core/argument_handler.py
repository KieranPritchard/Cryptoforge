import argparse

def build_parser():
    """Build and configure the command-line argument parser"""
    parser = argparse.ArgumentParser(  # Create argument parser instance
        description="Personal cryptography utility"
    )

    # Main function selector
    parser.add_argument("function", help="Primary function to execute")  # Required positional argument for algorithm/function

    # ---- Key management ----
    parser.add_argument("--save-key", type=str)
    parser.add_argument("--new-key-name", type=str)
    parser.add_argument("--key-type", type=str)

    parser.add_argument("--load-key", type=str)
    parser.add_argument("--list-keys", action="store_true")

    parser.add_argument("--rename-key", action="store_true")
    parser.add_argument("--old-name", type=str)
    parser.add_argument("--new-name", type=str)

    parser.add_argument("--delete-key", type=str)

    # ---- Key creation ----
    parser.add_argument("--aes-key", action="store_true")
    parser.add_argument("--blowfish-key", action="store_true")
    parser.add_argument("--chacha20-key", action="store_true")
    parser.add_argument("--rsa-private-key", action="store_true")
    parser.add_argument("--rsa-public-key", action="store_true")
    parser.add_argument("--ecc-private-key", action="store_true")
    parser.add_argument("--ecc-public-key", action="store_true")
    parser.add_argument("--ecdsa-private-key", action="store_true")
    parser.add_argument("--ecdsa-public-key", action="store_true")

    parser.add_argument("--bit-size", type=int)
    parser.add_argument("--nonce", type=str)

    # ---- Operations ----
    parser.add_argument("--operation", type=str)
    parser.add_argument("--input", type=str)
    parser.add_argument("--output", type=str)
    parser.add_argument("--key", type=str)
    parser.add_argument("--iv", type=str)
    parser.add_argument("--message", type=str)
    parser.add_argument("--signature", type=str)

    # ---- Hashing ----
    parser.add_argument("--hash-type", type=str)
    parser.add_argument(
        "--output-format",
        choices=["hex", "bytes"],
        default="hex"
    )

    # ---- Flags ----
    parser.add_argument("--plaintext", action="store_true")
    
    # ---- File Integrity ----
    parser.add_argument("--expected-hash", type=str, help="Expected hash for verification")  # Expected hash value for file integrity verification

    return parser  # Return configured parser
