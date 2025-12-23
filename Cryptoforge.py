import argparse
from ast import arg
import json
import os
# my custom imports for the functions.
import src.aes_algorithm_functions
import src.blake2_hash_algorithm
import src.blowfish_algorithms_functions
import src.chacha20_algorithm_fuctions
import src.ecdsa_digital_signature
import src.rsa_digital_signatures
import src.key_management
import src.rsa_algorithm_fuctions
import src.sha_200_hash_functions
import src.sha_300_hash_functions

# Load configuration
with open("config.json", "r") as config_file:
    config_data = json.load(config_file)

# Create keys directory if it doesn't exist
os.makedirs(config_data["key_folder"], exist_ok=True)

# Creates the key manager object from the key management file
key_manager = src.key_management(config_data["key_folder"])

# Creates objects for the ciphers
aes_cipher = src.aes_algorithm_functions.AES()
blowfish_cipher = src.blowfish_algorithms_functions.Blowfish()
chacha20_cipher = src.chacha20_algorithm_fuctions.ChaCha20()
rsa_cipher = src.rsa_algorithm_fuctions.RSA()
# Creates objects for the hash algorithmns
blake2_hash = src.blake2_hash_algorithm.Blake2()
sha200_hash = src.sha_200_hash_functions.SHA_200()
sha300_hash = src.sha_300_hash_functions.SHA_300()
# Creates digital Signature Objects
ecdsa_digital_signature = src.ecdsa_digital_signature.ecdsa_digital_signature()
rsa_digital_signature = src.rsa_digital_signatures.RSA_digital_signatures()

# Create the argument parser for the cryptography utility
parser = argparse.ArgumentParser(
    description="My personal cryptography utility; consult the README for details."
)

# Main positional argument that selects the program function
parser.add_argument("function")

# ---- Key management: save key ----

# Save the currently loaded key to the configured key directory
parser.add_argument("--save-key", type=str, help="Save the current key to key storage.")

# Specify the name to assign to the saved key
parser.add_argument("--new-key-name", type=str, help="Name for the saved key.")

# Specify the type of key being saved
parser.add_argument("--key-type", type=str, help="Type of key to save.")

# ---- Key management: load key ----

# Load a key from the configured key directory
parser.add_argument("--load-key", type=str, help="Load a key from key storage.")

# ---- Key management: list keys ----

# List all keys stored in the key directory
parser.add_argument("--list-keys", action="store_true", help="List all stored keys.")

# ---- Key management: rename key ----

# Enable renaming of an existing key
parser.add_argument("--rename-key", action="store_true", help="Rename an existing key.")

# Specify the current name of the key to rename
parser.add_argument("--old-name", type=str, help="Current name of the key.")

# Specify the new name for the key
parser.add_argument("--new-name", type=str, help="New name for the key.")

# ---- Key management: delete key ----

# Delete a key from the key directory
parser.add_argument("--delete-key", type=str, help="Delete a key from storage.")

# ---- Key creation flags ----

# Generate a new AES key
parser.add_argument("--aes-key", action="store_true", help="Generate an AES key.")

# Generate a new Blowfish key
parser.add_argument("--blowfish-key", action="store_true", help="Generate a Blowfish key.")

# Generate a new ChaCha20 key
parser.add_argument("--chacha20-key", action="store_true", help="Generate a ChaCha20 key.")

# Generate an RSA private key
parser.add_argument("--rsa-private-key", action="store_true", help="Generate an RSA private key.")

# Generate an RSA public key
parser.add_argument("--rsa-public-key", action="store_true", help="Generate an RSA public key.")

# Generate an ECC private key
parser.add_argument("--ecc-private-key", action="store_true", help="Generate an ECC private key.")

# Generate an ECC public key
parser.add_argument("--ecc-public-key", action="store_true", help="Generate an ECC public key.")

# Generate an ECDSA private key
parser.add_argument("--ecdsa-private-key", action="store_true", help="Generate an ECDSA private key.")

# Generate an ECDSA public key
parser.add_argument("--ecdsa-public-key", action="store_true", help="Generate an ECDSA public key.")

# Specify the key size in bits
parser.add_argument("--bit-size", help="Key size in bits.")

# Specify a nonce for algorithms that require one
parser.add_argument("--nonce", help="Nonce for cryptographic operations.")

# ---- Cryptographic operation arguments ----

# Select the cryptographic operation to perform
parser.add_argument("--operation", type=str, help="Operation: encrypt, decrypt, hash, sign, verify.")

# Provide input data or a file path
parser.add_argument("--input", type=str, help="Input data or file path.")

# Specify output file path
parser.add_argument("--output", type=str, help="Output file path.")

# Specify the key to use for the operation
parser.add_argument("--key", type=str, help="Key to use for the operation.")

# Provide an initialization vector for encryption/decryption
parser.add_argument("--iv", type=str, help="Initialization vector.")

# Provide a message for signing or verification
parser.add_argument("--message", type=str, help="Message for signing or verification.")

# Provide a signature file for verification
parser.add_argument("--signature", type=str, help="Signature file path.")

# Select the hash algorithm to use
parser.add_argument("--hash-type", type=str, help="Hash algorithm to use.")

# Select output format for hash results
parser.add_argument("--output-format", choices=["hex", "bytes"], default="hex", help="Hash output format.")

# Treat input as plaintext instead of a file
parser.add_argument("--plaintext", action="store_true", help="Treat input as plaintext.")

# Parse all command-line arguments
args = parser.parse_args()

# Global variables
loaded_key = None
# gets default AES Mode
default_aes_mode = config_data["default_aes_mode"]
# gets default blowfish mode
default_blowfish_mode = config_data["default_blowfish_mode"]

# Dispatches cryptographic operations based on the selected function argument
def handle_cryptographic_operations(args, loaded_key):
    # Retrieve and normalize the requested function name
    function = args.function.lower()
    
    # Handle AES encryption/decryption operations
    if function == "aes":
        src.aes_algorithm_functions.handle_aes_operations(
            args, loaded_key, default_aes_mode
        )
    
    # Handle Blowfish encryption/decryption operations
    elif function == "blowfish":
        src.blowfish_algorithms_functions.handle_blowfish_operations(
            args, loaded_key, default_blowfish_mode
        )
    
    # Handle ChaCha20 encryption/decryption operations
    elif function == "chacha20":
        src.chacha20_algorithm_fuctions.handle_chacha20_operations(
            args, loaded_key
        )
    
    # Handle Blake2 hashing operations
    elif function == "blake2":
        src.blake2_hash_algorithm.handle_blake2_hash_operations(
            args
        )
    
    # Handle RSA encryption and key-related operations
    elif function == "rsa":
        src.rsa_algorithm_fuctions.handle_rsa_operations(
            args, loaded_key
        )
    
    # Handle SHA-200 family hashing operations
    elif function == "sha200":
        src.sha_200_hash_functions.handle_sha200_hash_operations(
            args
        )
    
    # Handle SHA-300 family hashing operations
    elif function == "sha300":
        src.sha_300_hash_functions.handle_sha300_hash_operations(
            args
        )
    
    # Handle ECDSA digital signature operations
    elif function == "ecdsa":
        src.ecdsa_digital_signature.handle_ecdsa_signature_operations(
            args, loaded_key
        )
    
    # Handle RSA digital signature operations
    elif function == "rsa_signature":
        src.rsa_digital_signatures.handle_rsa_signature_operations(
            args, loaded_key
        )
    
    # Handle invalid or unsupported function values
    else:
        print(f"Unknown function: {function}")
        print(
            "Available functions: aes, blowfish, chacha20, blake2, "
            "rsa, sha200, sha300, ecdsa, rsa_signature"
        )

# Main execution logic
if __name__ == "__main__":
    # Check for key management operations first
    if any([args.save_key, args.load_key, args.list_keys, args.rename_key, args.delete_key]):
        src.key_management.handle_key_management(args, loaded_key, key_manager)
    
    # Check for key creation operations
    elif any([args.aes_key, args.blowfish_key, args.chacha20_key, 
            args.rsa_private_key, args.rsa_public_key, 
            args.ecc_private_key, args.ecc_public_key,
            args.ecdsa_private_key, args.ecdsa_public_key]):
        src.key_management.handle_key_creation(args, key_manager)
    
    # Handle cryptographic operations
    else:
        handle_cryptographic_operations(args,loaded_key)