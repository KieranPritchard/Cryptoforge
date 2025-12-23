import json
import os

# ---- Core imports ----
from src.core.argument_handler import build_parser
from src.core.crypto_dispatcher import CryptoDispatcher, dispatch_crypto_operation

# ---- Key management ----
from src.core.key_management import KeyManager
from src.core.key_management import handle_key_management, handle_key_creation

# ---- Symmetric ciphers ----
from src.symmetric.aes_cipher import AES
from src.symmetric.blowfish_cipher import Blowfish
from src.symmetric.chacha20_cipher import ChaCha20

# ---- Asymmetric crypto ----
from src.asymmetric.rsa_cipher import RSA
from src.asymmetric.rsa_signatures import RSADigitalSignatures
from src.asymmetric.ecdsa_signatures import ECDSA

# ---- Hashing ----
from src.hashing.blake2_hash import Blake2
from src.hashing.sha2_hash import SHA2
from src.hashing.sha3_hash import SHA3

# ---- File integrity ----
from src.hashing.file_integrity import FileIntegrityChecker


# ---- Load configuration ----
with open("config.json", "r") as config_file:  # Open configuration file
    config = json.load(config_file)  # Parse JSON configuration

# ---- Ensure key directory exists ----
os.makedirs(config["key_folder"], exist_ok=True)  # Create keys directory if it doesn't exist

# ---- Initialize managers ----
key_manager = KeyManager(config["key_folder"])  # Create key manager instance with key folder path

# ---- Initialize crypto objects ----
aes_cipher = AES()  # Initialize AES cipher instance
blowfish_cipher = Blowfish()  # Initialize Blowfish cipher instance
chacha20_cipher = ChaCha20()  # Initialize ChaCha20 cipher instance
rsa_cipher = RSA()  # Initialize RSA cipher instance

rsa_signature = RSADigitalSignatures()  # Initialize RSA signature handler
ecdsa_signature = ECDSA()  # Initialize ECDSA signature handler

blake2_hash = Blake2()  # Initialize Blake2 hash instance
sha2_hash = SHA2()  # Initialize SHA2 hash instance
sha3_hash = SHA3()  # Initialize SHA3 hash instance

file_integrity = FileIntegrityChecker()  # Initialize file integrity checker instance

# ---- Defaults ----
DEFAULT_AES_MODE = config["default_aes_mode"]  # Load default AES encryption mode from config
DEFAULT_BLOWFISH_MODE = config["default_blowfish_mode"]  # Load default Blowfish encryption mode from config

# ---- Argument parsing ----
parser = build_parser()  # Build command-line argument parser
args = parser.parse_args()  # Parse command-line arguments into args object

loaded_key = None  # Initialize global variable to store loaded key (starts as None)


# ---- Main execution ----
def main():
    global loaded_key  # Allow modification of loaded_key in this function

    # Handle "key" function for key management
    if args.function.lower() == "key" or args.function.lower() == "keymgmt":  # Check if user specified key function
        # Key management operations
        if any([
            args.save_key,
            args.load_key,
            args.list_keys,
            args.rename_key,
            args.delete_key,
        ]):
            loaded_key = handle_key_management(args, loaded_key, key_manager)  # Execute key management operation
            return  # Exit after handling key management
        
        # Key generation operations
        if any([
            args.aes_key,
            args.blowfish_key,
            args.chacha20_key,
            args.rsa_private_key,
            args.rsa_public_key,
            args.ecc_private_key,
            args.ecc_public_key,
            args.ecdsa_private_key,
            args.ecdsa_public_key,
        ]):
            handle_key_creation(args, key_manager)  # Execute key generation operation
            return  # Exit after handling key generation
        
        # If key function but no operations specified
        print("Error: Key function requires key management or key generation arguments")
        print("Use --save-key, --load-key, --list-keys, --aes-key, etc.")
        return  # Exit if key function has no valid operations

    # Key management operations (legacy - can work with any function name)
    if any([
        args.save_key,
        args.load_key,
        args.list_keys,
        args.rename_key,
        args.delete_key,
    ]):
        loaded_key = handle_key_management(args, loaded_key, key_manager)  # Execute key management operation
        return  # Exit after handling key management

    # Key generation operations (legacy - can work with any function name)
    if any([
        args.aes_key,
        args.blowfish_key,
        args.chacha20_key,
        args.rsa_private_key,
        args.rsa_public_key,
        args.ecc_private_key,
        args.ecc_public_key,
        args.ecdsa_private_key,
        args.ecdsa_public_key,
    ]):
        handle_key_creation(args, key_manager)  # Execute key generation operation
        return  # Exit after handling key generation

    # Cryptographic operations
    dispatch_crypto_operation(  # Route to appropriate cryptographic operation handler
        args=args,  # Pass all parsed command-line arguments
        loaded_key=loaded_key,  # Pass any key loaded from previous operations
        defaults={  # Pass default encryption modes from config
            "aes_mode": DEFAULT_AES_MODE,
            "blowfish_mode": DEFAULT_BLOWFISH_MODE,
        },
    )


if __name__ == "__main__":  # Entry point when script is run directly
    main()  # Execute main function