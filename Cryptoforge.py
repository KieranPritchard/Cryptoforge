import argparse
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

key_manager = src.key_management.key_management(key_folder = "")

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
parser.add_argument("--list-keys", type=str, help="lists keys in the key folder.")
#rename key arguements
parser.add_argument("--rename-key")
parser.add_argument("--old-name", type=str, help="old name of the key to rename.")
parser.add_argument("--new-name", type=str, help="new name of the key to rename.")
# delete key arguements
parser.add_argument("--delete-key", type=str, help="specifies key to delete.")
# key creation
parser.add_argument("--aes-key")
parser.add_argument("--blowfish-key")
parser.add_argument("--chacha20-key")
parser.add_argument("--rsa-private-key")
parser.add_argument("--rsa-public-key")
parser.add_argument("--ecc-private-key")
parser.add_argument("--ecc-public-key")
parser.add_argument("--ecdsa-private-key")
parser.add_argument("--ecdsa-public-key")
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

args = parser.parse_args()

# Function to handle key management operations
def handle_key_management():
    if args.save_key and args.new_key_name and args.key_type:
        # This would need the actual key data to save
        print(f"Saving key '{args.new_key_name}' of type '{args.key_type}'")
        # key_manager.save_key(args.new_key_name, key_data, args.key_type)
    
    elif args.load_key:
        print(f"Loading key: {args.load_key}")
        loaded_key = key_manager.load_key(args.load_key)
        print(f"Loaded key from: {loaded_key}")
    
    elif args.list_keys:
        print("Listing keys in key folder:")
        key_manager.list_keys()
    
    elif args.rename_key and args.old_name and args.new_name:
        print(f"Renaming key from '{args.old_name}' to '{args.new_name}'")
        key_manager.rename_key(args.old_name, args.new_name)
    
    elif args.delete_key:
        print(f"Deleting key: {args.delete_key}")
        key_manager.delete_key(args.delete_key)

# Function to handle key creation
def handle_key_creation():
    bit_size = int(args.bit_size) if args.bit_size else 256
    
    if args.aes_key:
        print(f"Creating AES key with {bit_size} bits")
        aes_key = key_manager.create_aes_key(bit_size)
        print(f"AES key created: {aes_key.hex()}")
    
    elif args.blowfish_key:
        print(f"Creating Blowfish key with {bit_size} bits")
        blowfish_key = key_manager.create_blowfish_key(bit_size)
        print(f"Blowfish key created: {blowfish_key.hex()}")
    
    elif args.chacha20_key:
        print(f"Creating ChaCha20 key with {bit_size} bits")
        chacha20_key = key_manager.create_ChaCha20_key(bit_size)
        print(f"ChaCha20 key created: {chacha20_key.hex()}")
    
    elif args.rsa_private_key:
        print("Creating RSA private key")
        rsa_private_key, rsa_private_pem = key_manager.create_rsa_private_key()
        print("RSA private key created")
    
    elif args.rsa_public_key:
        print("Creating RSA public key (requires private key)")
        # This would need the private key as input
        # rsa_public_key, rsa_public_pem = key_manager.create_rsa_public_key(private_key)
        print("RSA public key creation requires private key input")
    
    elif args.ecc_private_key:
        print("Creating ECC private key")
        ecc_private_key, ecc_private_pem = key_manager.create_ecc_private_key()
        print("ECC private key created")
    
    elif args.ecc_public_key:
        print("Creating ECC public key (requires private key)")
        # This would need the private key as input
        # ecc_public_key, ecc_public_pem = key_manager.create_ecc_public_key(private_key)
        print("ECC public key creation requires private key input")
    
    elif args.ecdsa_private_key:
        print("Creating ECDSA private key")
        ecdsa_private_key, ecdsa_private_pem = key_manager.create_ecdsa_private_key()
        print("ECDSA private key created")
    
    elif args.ecdsa_public_key:
        print("Creating ECDSA public key (requires private key)")
        # This would need the private key as input
        # ecdsa_public_key, ecdsa_public_pem = key_manager.create_ecdsa_public_key(private_key)
        print("ECDSA public key creation requires private key input")

# Function to handle AES operations
def handle_aes_operations():
    if not args.operation or not args.input:
        print("AES operations require --operation and --input arguments")
        return
    
    if args.operation == "encrypt":
        if not args.key or not args.iv:
            print("AES encryption requires --key and --iv arguments")
            return
        
        # Read input
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # Convert key and IV from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        iv = bytes.fromhex(args.iv) if len(args.iv) % 2 == 0 else args.iv.encode()
        
        # Pad data
        padded_data = src.aes_algorithm_functions.AES.padding(data)
        
        # Encrypt
        ciphertext = src.aes_algorithm_functions.AES.CBC_mode_plaintext_encryption(padded_data, key, iv)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.encrypted"
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if not args.key or not args.iv:
            print("AES decryption requires --key and --iv arguments")
            return
        
        # Read input
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # Convert key and IV from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        iv = bytes.fromhex(args.iv) if len(args.iv) % 2 == 0 else args.iv.encode()
        
        # Decrypt
        plaintext = src.aes_algorithm_functions.AES.CBC_mode_ciphertext_decryption(data, key, iv)
        
        # Unpad
        unpadded_data = src.aes_algorithm_functions.AES.unpadder(plaintext)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.decrypted"
        with open(output_file, 'w') as f:
            f.write(unpadded_data)
        print(f"Decrypted data written to {output_file}")

# Function to handle Blowfish operations
def handle_blowfish_operations():
    if not args.operation or not args.input:
        print("Blowfish operations require --operation and --input arguments")
        return
    
    if args.operation == "encrypt":
        if not args.key:
            print("Blowfish encryption requires --key argument")
            return
        
        # Read input
        with open(args.input, 'r') as f:
            data = f.read()
        
        # Convert key from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        
        # Encrypt
        ciphertext = src.blowfish_algorithms_functions.Blowfish.cbc_plaintext_encryption(key, data)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.encrypted"
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if not args.key:
            print("Blowfish decryption requires --key argument")
            return
        
        # Read input
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # Convert key from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        
        # Decrypt
        plaintext = src.blowfish_algorithms_functions.Blowfish.cbc_ciphertext_decryption(key, data)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.decrypted"
        with open(output_file, 'w') as f:
            f.write(plaintext)
        print(f"Decrypted data written to {output_file}")

# Function to handle ChaCha20 operations
def handle_chacha20_operations():
    if not args.operation or not args.input:
        print("ChaCha20 operations require --operation and --input arguments")
        return
    
    if args.operation == "encrypt":
        if not args.key or not args.nonce:
            print("ChaCha20 encryption requires --key and --nonce arguments")
            return
        
        # Read input
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # Convert key and nonce from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        nonce = bytes.fromhex(args.nonce) if len(args.nonce) % 2 == 0 else args.nonce.encode()
        
        # Encrypt
        ciphertext = src.chacha20_algorithm_fuctions.ChaCha20.ChaCha20_plaintext_encryption(key, nonce, data)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.encrypted"
        with open(output_file, 'wb') as f:
            f.write(ciphertext)
        print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if not args.key:
            print("ChaCha20 decryption requires --key argument")
            return
        
        # Read input
        with open(args.input, 'rb') as f:
            data = f.read()
        
        # Convert key from hex if needed
        key = bytes.fromhex(args.key) if len(args.key) % 2 == 0 else args.key.encode()
        
        # Extract nonce from data
        nonce = data[:16]
        ciphertext = data[16:]
        
        # Decrypt
        plaintext = src.chacha20_algorithm_fuctions.ChaCha20.ChaCha20_ciphertext_decryption(key, nonce, ciphertext)
        
        # Write output
        output_file = args.output if args.output else f"{args.input}.decrypted"
        with open(output_file, 'wb') as f:
            f.write(plaintext)
        print(f"Decrypted data written to {output_file}")

# Function to handle hash operations
def handle_hash_operations():
    if not args.input or not args.hash_type:
        print("Hash operations require --input and --hash-type arguments")
        return
    
    # Determine if input is file or text
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
        is_file = True
    except:
        data = args.input.encode()
        is_file = False
    
    hash_type = args.hash_type.lower()
    output_format = args.output_format
    
    if hash_type.startswith("sha"):
        if hash_type in ["sha224", "sha256", "sha384", "sha512"]:
            if is_file:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = src.sha_200_hash_functions.SHA_200.sha224_file_hash_hex(args.input)
                    elif hash_type == "sha256":
                        result = src.sha_200_hash_functions.SHA_200.sha256_file_hash_hex(args.input)
                    elif hash_type == "sha384":
                        result = src.sha_200_hash_functions.SHA_200.sha384_file_hash_hex(args.input)
                    elif hash_type == "sha512":
                        result = src.sha_200_hash_functions.SHA_200.sha512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha224":
                        result = src.sha_200_hash_functions.SHA_200.sha224_file_hash_bytes(args.input)
                    elif hash_type == "sha256":
                        result = src.sha_200_hash_functions.SHA_200.sha256_file_hash_bytes(args.input)
                    elif hash_type == "sha384":
                        result = src.sha_200_hash_functions.SHA_200.sha384_file_hash_bytes(args.input)
                    elif hash_type == "sha512":
                        result = src.sha_200_hash_functions.SHA_200.sha512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = src.sha_200_hash_functions.SHA_200.sha224_plaintext_hash_hex(data)
                    elif hash_type == "sha256":
                        result = src.sha_200_hash_functions.SHA_200.sha256_plaintext_hash_hex(data)
                    elif hash_type == "sha384":
                        result = src.sha_200_hash_functions.SHA_200.sha384_plaintext_hash_hex(data)
                    elif hash_type == "sha512":
                        result = src.sha_200_hash_functions.SHA_200.sha512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha224":
                        result = src.sha_200_hash_functions.SHA_200.sha224_plaintext_hash_bytes(data)
                    elif hash_type == "sha256":
                        result = src.sha_200_hash_functions.SHA_200.sha256_plaintext_hash_bytes(data)
                    elif hash_type == "sha384":
                        result = src.sha_200_hash_functions.SHA_200.sha384_plaintext_hash_bytes(data)
                    elif hash_type == "sha512":
                        result = src.sha_200_hash_functions.SHA_200.sha512_plaintext_hash_bytes(data)
        
        elif hash_type in ["sha3_224", "sha3_256", "sha3_384", "sha3_512"]:
            if is_file:
                if output_format == "hex":
                    if hash_type == "sha3_224":
                        result = src.sha_300_hash_functions.SHA_300.sha3_224_file_hash_hex(args.input)
                    elif hash_type == "sha3_256":
                        result = src.sha_300_hash_functions.SHA_300.sha3_256_file_hash_hex(args.input)
                    elif hash_type == "sha3_384":
                        result = src.sha_300_hash_functions.SHA_300.sha3_384_file_hash_hex(args.input)
                    elif hash_type == "sha3_512":
                        result = src.sha_300_hash_functions.SHA_300.sha3_512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha3_224":
                        result = src.sha_300_hash_functions.SHA_300.sha3_224_file_hash_bytes(args.input)
                    elif hash_type == "sha3_256":
                        result = src.sha_300_hash_functions.SHA_300.sha3_256_file_hash_bytes(args.input)
                    elif hash_type == "sha3_384":
                        result = src.sha_300_hash_functions.SHA_300.sha3_384_file_hash_bytes(args.input)
                    elif hash_type == "sha3_512":
                        result = src.sha_300_hash_functions.SHA_300.sha3_512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha3_224":
                        result = src.sha_300_hash_functions.SHA_300.sha3_224_plaintext_hash_hex(data)
                    elif hash_type == "sha3_256":
                        result = src.sha_300_hash_functions.SHA_300.sha3_256_plaintext_hash_hex(data)
                    elif hash_type == "sha3_384":
                        result = src.sha_300_hash_functions.SHA_300.sha3_384_plaintext_hash_hex(data)
                    elif hash_type == "sha3_512":
                        result = src.sha_300_hash_functions.SHA_300.sha3_512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha3_224":
                        result = src.sha_300_hash_functions.SHA_300.sha3_224_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_256":
                        result = src.sha_300_hash_functions.SHA_300.sha3_256_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_384":
                        result = src.sha_300_hash_functions.SHA_300.sha3_384_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_512":
                        result = src.sha_300_hash_functions.SHA_300.sha3_512_plaintext_hash_bytes(data)
    
    elif hash_type in ["blake2s", "blake2b"]:
        if is_file:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = src.blake2_hash_algorithm.Blake2.blake2s_file_hash_hex(args.input)
                else:
                    result = src.blake2_hash_algorithm.Blake2.blake2b_file_hash_hex(args.input)
            else:
                if hash_type == "blake2s":
                    result = src.blake2_hash_algorithm.Blake2.blake2s_file_hash_bytes(args.input)
                else:
                    result = src.blake2_hash_algorithm.Blake2.blake2b_file_hash_bytes(args.input)
        else:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = src.blake2_hash_algorithm.Blake2.blake2s_plaintext_hash_hex(data)
                else:
                    result = src.blake2_hash_algorithm.Blake2.blake2b_plaintext_hash_hex(data)
            else:
                if hash_type == "blake2s":
                    result = src.blake2_hash_algorithm.Blake2.blake2s_plaintext_hash_bytes(data)
                else:
                    result = src.blake2_hash_algorithm.Blake2.blake2b_plaintext_hash_bytes(data)
    
    else:
        print(f"Unsupported hash type: {hash_type}")
        return
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            if output_format == "hex":
                f.write(result)
            else:
                f.write(result.hex())
        print(f"Hash written to {args.output}")
    else:
        if output_format == "hex":
            print(f"Hash: {result}")
        else:
            print(f"Hash: {result.hex()}")

# Function to handle cryptographic operations based on the main function argument
def handle_cryptographic_operations():
    function = args.function.lower()
    
    if function == "aes":
        handle_aes_operations()
    
    elif function == "blowfish":
        handle_blowfish_operations()
    
    elif function == "chacha20":
        handle_chacha20_operations()
    
    elif function == "blake2":
        handle_hash_operations()
    
    elif function == "rsa":
        print("RSA operations available")
        # Add RSA specific operations when needed
    
    elif function == "sha200":
        handle_hash_operations()
    
    elif function == "sha300":
        handle_hash_operations()
    
    elif function == "ecdsa":
        print("ECDSA digital signature operations available")
        # Add ECDSA specific operations when needed
    
    elif function == "rsa_signature":
        print("RSA digital signature operations available")
        # Add RSA signature specific operations when needed
    
    else:
        print(f"Unknown function: {function}")
        print("Available functions: aes, blowfish, chacha20, blake2, rsa, sha200, sha300, ecdsa, rsa_signature")

# Main execution logic
if __name__ == "__main__":
    # Check for key management operations first
    if any([args.save_key, args.load_key, args.list_keys, args.rename_key, args.delete_key]):
        handle_key_management()
    
    # Check for key creation operations
    elif any([args.aes_key, args.blowfish_key, args.chacha20_key, 
              args.rsa_private_key, args.rsa_public_key, 
              args.ecc_private_key, args.ecc_public_key,
              args.ecdsa_private_key, args.ecdsa_public_key]):
        handle_key_creation()
    
    # Handle cryptographic operations
    else:
        handle_cryptographic_operations()