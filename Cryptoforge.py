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

key_manager = src.key_management.key_management(key_folder=config_data["key_folder"])

aes_cipher = src.aes_algorithm_functions.AES()
blowfish_cipher = src.blowfish_algorithms_functions.Blowfish()
chacha20_cipher = src.chacha20_algorithm_fuctions.ChaCha20()
blake2_hash = src.blake2_hash_algorithm.Blake2()
rsa_cipher = src.rsa_algorithm_fuctions.RSA()
sha200_hash = src.sha_200_hash_functions.SHA_200()
sha300_hash = src.sha_300_hash_functions.SHA_300()
ecdsa_digital_signature = src.ecdsa_digital_signature.ecdsa_digital_signature()
rsa_digital_signature = src.rsa_digital_signatures.RSA_digital_signatures()

parser = argparse.ArgumentParser(description="My personal cryptography ultility consult the readme file for more information.")
parser.add_argument("function")
# arguments for key management
# save key arguements
parser.add_argument("--save-key", type=str, help="function that saves key that is currently loaded to config defined folder.")
parser.add_argument("--new-key-name", type=str, help="specifies the name of the key that is being used.")
parser.add_argument("--key-type", type=str, help="specifies type of key to save.")
# load key arguements
parser.add_argument("--load-key", type=str, help="function that loads key from config defined folder.")
# list key arguements
parser.add_argument("--list-keys", action="store_true", help="lists keys in the key folder.")
#rename key arguements
parser.add_argument("--rename-key", action="store_true", help="flag to trigger key renaming")
parser.add_argument("--old-name", type=str, help="old name of the key to rename.")
parser.add_argument("--new-name", type=str, help="new name of the key to rename.")
# delete key arguements
parser.add_argument("--delete-key", type=str, help="specifies key to delete.")
# key creation
parser.add_argument("--aes-key", action="store_true", help="flag to create AES key")
parser.add_argument("--blowfish-key", action="store_true", help="flag to create Blowfish key")
parser.add_argument("--chacha20-key", action="store_true", help="flag to create ChaCha20 key")
parser.add_argument("--rsa-private-key", action="store_true", help="flag to create RSA private key")
parser.add_argument("--rsa-public-key", action="store_true", help="flag to create RSA public key")
parser.add_argument("--ecc-private-key", action="store_true", help="flag to create ECC private key")
parser.add_argument("--ecc-public-key", action="store_true", help="flag to create ECC public key")
parser.add_argument("--ecdsa-private-key", action="store_true", help="flag to create ECDSA private key")
parser.add_argument("--ecdsa-public-key", action="store_true", help="flag to create ECDSA public key")
parser.add_argument("--bit-size")
parser.add_argument("--nonce")

# Arguments for cryptographic operations
parser.add_argument("--operation", type=str, help="Operation to perform (encrypt, decrypt, hash, sign, verify)")
parser.add_argument("--input", type=str, help="Input data or file path")
parser.add_argument("--output", type=str, help="Output file path")
parser.add_argument("--key", type=str, help="Key for encryption/decryption")
parser.add_argument("--iv", type=str, help="Initialization vector")
parser.add_argument("--message", type=str, help="Message for signing/verification")
parser.add_argument("--signature", type=str, help="Signature file path")
parser.add_argument("--hash-type", type=str, help="Hash type (sha224, sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512, blake2s, blake2b)")
parser.add_argument("--output-format", type=str, choices=["hex", "bytes"], default="hex", help="Output format for hashes")
parser.add_argument("--plaintext", action="store_true", help="Treat --input as a plaintext string instead of a file for encryption/decryption operations.")

args = parser.parse_args()

# Global variables
loaded_key = None
default_aes_mode = config_data["default_aes_mode"]
default_blowfish_mode = config_data["default_blowfish_mode"]

# Function to handle cryptographic operations based on the main function argument
def handle_cryptographic_operations(args, loaded_key):
    function = args.function.lower()
    
    if function == "aes":
        src.aes_algorithm_functions.handle_aes_operations(args,loaded_key, default_aes_mode)
    
    elif function == "blowfish":
        src.blowfish_algorithms_functions.handle_blowfish_operations(args, loaded_key, default_blowfish_mode)
    
    elif function == "chacha20":
        src.chacha20_algorithm_fuctions.handle_chacha20_operations(args, loaded_key)
    
    elif function == "blake2":
        src.blake2_hash_algorithm.handle_blake2_hash_operations(args)
    
    elif function == "rsa":
        src.rsa_algorithm_fuctions.handle_rsa_operations(args, loaded_key)
    
    elif function == "sha200":
        src.sha_200_hash_functions.handle_sha200_hash_operations(args)
    
    elif function == "sha300":
        src.sha_300_hash_functions.handle_sha300_hash_operations(args)
    
    elif function == "ecdsa":
        src.ecdsa_digital_signature.handle_ecdsa_signature_operations(args, loaded_key)
    
    elif function == "rsa_signature":
        src.rsa_digital_signatures.handle_rsa_signature_operations(args, loaded_key)
    
    else:
        print(f"Unknown function: {function}")
        print("Available functions: aes, blowfish, chacha20, blake2, rsa, sha200, sha300, ecdsa, rsa_signature")

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