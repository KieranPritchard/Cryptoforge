import json
import os

# ---- Core imports ----
from src.core.argument_handler import build_parser  # Imports the CLI argument configuration
from src.core.crypto_dispatcher import CryptoDispatcher, dispatch_crypto_operation  # Imports logic to route commands

# ---- Key management ----
from src.core.key_management import KeyManager  # Imports the class that handles file I/O for keys
from src.core.key_management import handle_key_management, handle_key_creation  # Imports the key logic handlers

# ---- Symmetric ciphers ----
from src.symmetric.aes_cipher import AES  # Imports Advanced Encryption Standard implementation
from src.symmetric.blowfish_cipher import Blowfish  # Imports Blowfish block cipher implementation
from src.symmetric.chacha20_cipher import ChaCha20  # Imports ChaCha20 stream cipher implementation

# ---- Asymmetric crypto ----
from src.asymmetric.rsa_cipher import RSA  # Imports RSA encryption/decryption logic
from src.asymmetric.rsa_signatures import RSADigitalSignatures  # Imports RSA signing logic
from src.asymmetric.ecdsa_signatures import ECDSA  # Imports Elliptic Curve signing logic

# ---- Hashing ----
from src.hashing.blake2_hash import Blake2  # Imports Blake2 family hashing
from src.hashing.sha2_hash import SHA2  # Imports SHA-2 family hashing (224, 256, etc.)
from src.hashing.sha3_hash import SHA3  # Imports SHA-3 family hashing (Keccak)

# ---- File integrity ----
from src.hashing.file_integrity import FileIntegrityChecker  # Imports utility to verify file hashes

# ---- Networking (Separate) ----
# from src.networking.tls_manager import TlsManager  # Placeholder for your separate TLS module

# ---- Load configuration ----
with open("config.json", "r") as config_file:  # Open configuration file in read mode
    config = json.load(config_file)  # Parse the JSON data into a python dictionary

# ---- Ensure key directory exists ----
os.makedirs(config["key_folder"], exist_ok=True)  # Create the folder defined in config if it is missing

# ---- Initialize managers ----
key_manager = KeyManager(config["key_folder"])  # Create key manager instance pointing to the key folder

# ---- Initialize crypto objects ----
aes_cipher = AES()  # Initialize the AES engine
blowfish_cipher = Blowfish()  # Initialize the Blowfish engine
chacha20_cipher = ChaCha20()  # Initialize the ChaCha20 engine
rsa_cipher = RSA()  # Initialize the RSA engine

rsa_signature = RSADigitalSignatures()  # Initialize the RSA digital signature handler
ecdsa_signature = ECDSA()  # Initialize the ECDSA digital signature handler

blake2_hash = Blake2()  # Initialize the Blake2 hashing engine
sha2_hash = SHA2()  # Initialize the SHA-2 hashing engine
sha3_hash = SHA3()  # Initialize the SHA-3 hashing engine

file_integrity = FileIntegrityChecker()  # Initialize the file integrity utility

# ---- Defaults ----
DEFAULT_AES_MODE = config["default_aes_mode"]  # Set default AES mode (CBC/CTR) from config
DEFAULT_BLOWFISH_MODE = config["default_blowfish_mode"]  # Set default Blowfish mode from config

# ---- Argument parsing ----
parser = build_parser()  # Generate the full CLI argument schema
args = parser.parse_args()  # Process the actual command line inputs provided by the user

loaded_key = None  # Initialize global variable to keep a key in memory during execution


# ---- Main execution ----
def main():
    global loaded_key  # Access the global loaded_key variable for updates

    # Handle "key" function for key management specifically
    if args.function.lower() in ("key", "keymgmt"):  # Checks if the user is calling key management
        # Logic for managing existing keys (load, save, list, rename, delete)
        if any([
            args.save_key,
            args.load_key,
            args.list_keys,
            args.rename_key,
            args.delete_key,
        ]):
            loaded_key = handle_key_management(args, loaded_key, key_manager)  # Run the management handler
            return  # Stop execution after completing key management
        
        # Logic for creating brand new keys (AES, RSA, ECC, etc.)
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
            handle_key_creation(args, key_manager)  # Run the creation handler
            return  # Stop execution after generating the key
        
        # Error handling if 'key' function is called without a specific action
        print("Error: Key function requires key management or key generation arguments")
        print("Use --save-key, --load-key, --list-keys, --aes-key, etc.")
        return 

    # ---- TLS / SSL Logic ----
    if args.function.lower() == "tls":  # Checks if the user wants to use TLS networking
        # This would interface with your TlsManager class
        # tls_mgr = TlsManager(cert_path=args.cert, key_path=args.key)
        # if args.operation == "server": tls_mgr.run_secure_server(args.host, args.port)
        print("TLS functionality triggered (Link to TlsManager here)")
        return

    # Secondary check for key management (allows flags to work without the 'key' keyword)
    if any([
        args.save_key,
        args.load_key,
        args.list_keys,
        args.rename_key,
        args.delete_key,
    ]):
        loaded_key = handle_key_management(args, loaded_key, key_manager)  # Process key flags
        return 

    # Secondary check for key generation (allows flags to work without the 'key' keyword)
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
        handle_key_creation(args, key_manager)  # Process generation flags
        return 

    # Main Cryptographic routing
    dispatch_crypto_operation(  # Sends the arguments to the dispatcher for encryption/hashing/signing
        args=args,  # Pass parsed CLI arguments
        loaded_key=loaded_key,  # Pass the key stored in memory (if any)
        defaults={  # Provide default algorithm modes
            "aes_mode": DEFAULT_AES_MODE,
            "blowfish_mode": DEFAULT_BLOWFISH_MODE,
        },
    )


if __name__ == "__main__":  # Standard Python entry point
    main()  # Run the main program loop