import argparse
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
parser.add_argument("--plaintext", action="store_true", help="Treat --input as a plaintext string instead of a file for encryption/decryption operations.")

args = parser.parse_args()

# Global variable to store loaded key
loaded_key = None

# Function to handle key management operations
def handle_key_management():
    global loaded_key
    
    if args.save_key and args.new_key_name and args.key_type:
        # This would need the actual key data to save
        print(f"Saving key '{args.new_key_name}' of type '{args.key_type}'")
        if loaded_key:
            key_manager.save_key(args.new_key_name, loaded_key, args.key_type)
        else:
            print("No key loaded to save")
    
    elif args.load_key:
        print(f"Loading key: {args.load_key}")
        loaded_key = key_manager.load_symetric_key(args.load_key)
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
        if aes_key:
            print(f"AES key created: {aes_key.hex()}")
            # Save the key
            key_manager.save_key("aes_key", aes_key.hex(), "symetric")
    
    elif args.blowfish_key:
        print(f"Creating Blowfish key with {bit_size} bits")
        blowfish_key = key_manager.create_blowfish_key(bit_size)
        if blowfish_key:
            print(f"Blowfish key created: {blowfish_key.hex()}")
            # Save the key
            key_manager.save_key("blowfish_key", blowfish_key.hex(), "symetric")
    
    elif args.chacha20_key:
        print(f"Creating ChaCha20 key with {bit_size} bits")
        chacha20_key = key_manager.create_ChaCha20_key(bit_size)
        if chacha20_key:
            print(f"ChaCha20 key created: {chacha20_key.hex()}")
            # Save the key
            key_manager.save_key("chacha20_key", chacha20_key.hex(), "symetric")
    
    elif args.rsa_private_key:
        print("Creating RSA private key")
        rsa_private_key, rsa_private_pem = key_manager.create_rsa_private_key()
        print("RSA private key created")
        # Save the private key
        key_manager.save_key("rsa_private_key", rsa_private_pem.decode(), "private")
        print("RSA private key saved to keys folder")
    
    elif args.rsa_public_key:
        print("Creating RSA public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_rsa_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    rsa_public_key, rsa_public_pem = key_manager.create_rsa_public_key(private_key)
                    print("RSA public key created successfully")
                    # Save the public key
                    key_manager.save_key("rsa_public_key", rsa_public_pem.decode(), "public")
                    print("RSA public key saved to keys folder")
                else:
                    print("Failed to load RSA private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("RSA public key creation requires --key argument with private key file path")
    
    elif args.ecc_private_key:
        print("Creating ECC private key")
        ecc_private_key, ecc_private_pem = key_manager.create_ecc_private_key()
        print("ECC private key created")
        # Save the private key
        key_manager.save_key("ecc_private_key", ecc_private_pem.decode(), "private")
        print("ECC private key saved to keys folder")
    
    elif args.ecc_public_key:
        print("Creating ECC public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_ecc_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    ecc_public_key, ecc_public_pem = key_manager.create_ecc_public_key(private_key)
                    print("ECC public key created successfully")
                    # Save the public key
                    key_manager.save_key("ecc_public_key", ecc_public_pem.decode(), "public")
                    print("ECC public key saved to keys folder")
                else:
                    print("Failed to load ECC private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("ECC public key creation requires --key argument with private key file path")
    
    elif args.ecdsa_private_key:
        print("Creating ECDSA private key")
        ecdsa_private_key, ecdsa_private_pem = key_manager.create_ecdsa_private_key()
        print("ECDSA private key created")
        # Save the private key
        key_manager.save_key("ecdsa_private_key", ecdsa_private_pem.decode(), "private")
        print("ECDSA private key saved to keys folder")
    
    elif args.ecdsa_public_key:
        print("Creating ECDSA public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_ecdsa_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    ecdsa_public_key, ecdsa_public_pem = key_manager.create_ecdsa_public_key(private_key)
                    print("ECDSA public key created successfully")
                    # Save the public key
                    key_manager.save_key("ecdsa_public_key", ecdsa_public_pem.decode(), "public")
                    print("ECDSA public key saved to keys folder")
                else:
                    print("Failed to load ECDSA private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("ECDSA public key creation requires --key argument with private key file path")

# Function to handle AES operations
def handle_aes_operations():
    global loaded_key
    if not args.operation or not args.input:
        print("AES operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key or not args.iv:
        print("AES encryption/decryption requires --key (or loaded key) and --iv arguments")
        return
    
    if args.operation == "encrypt":
        if args.plaintext:
            data = args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()
        
        # Convert key and IV from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        iv = bytes.fromhex(args.iv) if len(args.iv) % 2 == 0 else args.iv.encode()
        
        # Pad data
        padded_data = aes_cipher.padding(data)
        
        # Encrypt
        ciphertext = aes_cipher.CBC_mode_plaintext_encryption(padded_data, key_bytes, iv)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")
        else:
            output_file = args.output if args.output else f"{args.input}.encrypted"
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
            print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if args.plaintext:
            data = bytes.fromhex(args.input) if all(c in '0123456789abcdefABCDEF' for c in args.input) and len(args.input) % 2 == 0 else args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()
        
        # Convert key and IV from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        iv = bytes.fromhex(args.iv) if len(args.iv) % 2 == 0 else args.iv.encode()
        
        # Decrypt
        plaintext = aes_cipher.CBC_mode_ciphertext_decryption(data, key_bytes, iv)
        
        # Unpad
        unpadded_data = aes_cipher.unpadder(plaintext)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(unpadded_data)
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {unpadded_data}")
        else:
            output_file = args.output if args.output else f"{args.input}.decrypted"
            with open(output_file, 'w') as f:
                f.write(unpadded_data)
            print(f"Decrypted data written to {output_file}")

# Function to handle Blowfish operations
def handle_blowfish_operations():
    global loaded_key
    if not args.operation or not args.input:
        print("Blowfish operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("Blowfish encryption/decryption requires --key (or loaded key) argument")
        return
    
    if args.operation == "encrypt":
        if args.plaintext:
            data = args.input
        else:
            with open(args.input, 'r') as f:
                data = f.read()
        
        # Convert key from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        
        # Encrypt
        ciphertext = blowfish_cipher.cbc_plaintext_encryption(key_bytes, data)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")
        else:
            output_file = args.output if args.output else f"{args.input}.encrypted"
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
            print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if args.plaintext:
            data = bytes.fromhex(args.input) if all(c in '0123456789abcdefABCDEF' for c in args.input) and len(args.input) % 2 == 0 else args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()
        
        # Convert key from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        
        # Decrypt
        plaintext = blowfish_cipher.cbc_ciphertext_decryption(key_bytes, data)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(plaintext)
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {plaintext}")
        else:
            output_file = args.output if args.output else f"{args.input}.decrypted"
            with open(output_file, 'w') as f:
                f.write(plaintext)
            print(f"Decrypted data written to {output_file}")

# Function to handle ChaCha20 operations
def handle_chacha20_operations():
    global loaded_key
    if not args.operation or not args.input:
        print("ChaCha20 operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("ChaCha20 encryption/decryption requires --key (or loaded key) argument")
        return
    
    if args.operation == "encrypt":
        if not args.nonce:
            print("ChaCha20 encryption requires --nonce argument")
            return
        if args.plaintext:
            data = args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()
        
        # Convert key and nonce from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        nonce = bytes.fromhex(args.nonce) if len(args.nonce) % 2 == 0 else args.nonce.encode()
        
        # Encrypt
        ciphertext = chacha20_cipher.ChaCha20_plaintext_encryption(key_bytes, nonce, data)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")
        else:
            output_file = args.output if args.output else f"{args.input}.encrypted"
            with open(output_file, 'wb') as f:
                f.write(ciphertext)
            print(f"Encrypted data written to {output_file}")
    
    elif args.operation == "decrypt":
        if args.plaintext:
            data = bytes.fromhex(args.input) if all(c in '0123456789abcdefABCDEF' for c in args.input) and len(args.input) % 2 == 0 else args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()
        
        # Extract nonce from data
        nonce = data[:16]
        ciphertext = data[16:]
        
        # Convert key from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        
        # Decrypt
        plaintext = chacha20_cipher.ChaCha20_ciphertext_decryption(key_bytes, nonce, ciphertext)
        
        # Write output
        if args.plaintext:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(plaintext)
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {plaintext}")
        else:
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
                        result = sha200_hash.sha224_file_hash_hex(args.input)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_file_hash_hex(args.input)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_file_hash_hex(args.input)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_file_hash_bytes(args.input)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_file_hash_bytes(args.input)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_file_hash_bytes(args.input)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_plaintext_hash_hex(data)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_plaintext_hash_hex(data)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_plaintext_hash_hex(data)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_plaintext_hash_bytes(data)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_plaintext_hash_bytes(data)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_plaintext_hash_bytes(data)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_plaintext_hash_bytes(data)
        
        elif hash_type in ["sha3_224", "sha3_256", "sha3_384", "sha3_512"]:
            if is_file:
                if output_format == "hex":
                    if hash_type == "sha3_224":
                        result = sha300_hash.sha3_224_file_hash_hex(args.input)
                    elif hash_type == "sha3_256":
                        result = sha300_hash.sha3_256_file_hash_hex(args.input)
                    elif hash_type == "sha3_384":
                        result = sha300_hash.sha3_384_file_hash_hex(args.input)
                    elif hash_type == "sha3_512":
                        result = sha300_hash.sha3_512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha3_224":
                        result = sha300_hash.sha3_224_file_hash_bytes(args.input)
                    elif hash_type == "sha3_256":
                        result = sha300_hash.sha3_256_file_hash_bytes(args.input)
                    elif hash_type == "sha3_384":
                        result = sha300_hash.sha3_384_file_hash_bytes(args.input)
                    elif hash_type == "sha3_512":
                        result = sha300_hash.sha3_512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha3_224":
                        result = sha300_hash.sha3_224_plaintext_hash_hex(data)
                    elif hash_type == "sha3_256":
                        result = sha300_hash.sha3_256_plaintext_hash_hex(data)
                    elif hash_type == "sha3_384":
                        result = sha300_hash.sha3_384_plaintext_hash_hex(data)
                    elif hash_type == "sha3_512":
                        result = sha300_hash.sha3_512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha3_224":
                        result = sha300_hash.sha3_224_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_256":
                        result = sha300_hash.sha3_256_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_384":
                        result = sha300_hash.sha3_384_plaintext_hash_bytes(data)
                    elif hash_type == "sha3_512":
                        result = sha300_hash.sha3_512_plaintext_hash_bytes(data)
    
    elif hash_type in ["blake2s", "blake2b"]:
        if is_file:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_file_hash_hex(args.input)
                else:
                    result = blake2_hash.blake2b_file_hash_hex(args.input)
            else:
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_file_hash_bytes(args.input)
                else:
                    result = blake2_hash.blake2b_file_hash_bytes(args.input)
        else:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_plaintext_hash_hex(data)
                else:
                    result = blake2_hash.blake2b_plaintext_hash_hex(data)
            else:
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_plaintext_hash_bytes(data)
                else:
                    result = blake2_hash.blake2b_plaintext_hash_bytes(data)
    
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

# Function to handle ECDSA signature operations
def handle_ecdsa_signature_operations():
    global loaded_key
    if not args.operation or not args.input:
        print("ECDSA signature operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("ECDSA signing/verifying requires --key (or loaded key) argument (private/public key)")
        return
    
    if args.operation == "sign":
        # For now, we'll use a simple message
        message = args.input.encode()
        print("ECDSA signing requires private key loading from file or loaded key")
        print("Message to sign:", args.input)
        # ecdsa_digital_signature.ecdsa_sign_bytes(message, private_key)
    
    elif args.operation == "verify":
        if not args.signature:
            print("ECDSA verification requires --signature argument")
            return
        message = args.input.encode()
        print("ECDSA verification requires public key and signature loading from files or loaded key")
        print("Message to verify:", args.input)
        print("Signature file:", args.signature)
        # ecdsa_digital_signature.ecdsa_verify_message(public_key, signature, message)

# Function to handle RSA signature operations
def handle_rsa_signature_operations():
    global loaded_key
    if not args.operation or not args.input:
        print("RSA signature operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("RSA signing/verifying requires --key (or loaded key) argument (private/public key)")
        return
    
    if args.operation == "sign":
        message = args.input.encode()
        print("RSA signing requires private key loading from file or loaded key")
        print("Message to sign:", args.input)
        # signature = rsa_digital_signature.RSA_sign_hex(message, private_key)
        # print(f"Signature: {signature}")
    
    elif args.operation == "verify":
        if not args.signature:
            print("RSA verification requires --signature argument")
            return
        message = args.input.encode()
        print("RSA verification requires public key and signature loading from files or loaded key")
        print("Message to verify:", args.input)
        print("Signature file:", args.signature)
        # rsa_digital_signature.RSA_verify_message(public_key, signature, message)

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
        handle_ecdsa_signature_operations()
    
    elif function == "rsa_signature":
        handle_rsa_signature_operations()
    
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