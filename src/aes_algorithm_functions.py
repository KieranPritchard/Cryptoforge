from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

class AES:
    def __init__(self):
        pass

    def padding(self, data):
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    def unpadder(self, data):
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(data) + unpadder.finalize()
        return plaintext.decode()
    
    def CBC_mode_plaintext_encryption(self, padded_plaintext, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_encryptor = CBC_mode_cipher.encryptor()
        ciphertext = CBC_mode_encryptor.update(padded_plaintext) + CBC_mode_encryptor.finalize()
        return ciphertext
    
    def CBC_mode_ciphertext_decryption(self, ciphertext, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_decryptor = CBC_mode_cipher.decryptor()
        plaintext = CBC_mode_decryptor.update(ciphertext) + CBC_mode_decryptor.finalize()
        return plaintext
    
    def CBC_mode_file_encryption(self, file, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_encryptor = CBC_mode_cipher.encryptor()

        with open(f"{file}", "rb") as f:
            file_contents = f.read()
        encrypted_contents = CBC_mode_encryptor.update(file_contents) + CBC_mode_encryptor.finalize()
        with open(f"{file}", "wb") as f:
            f.write(encrypted_contents)

    def CBC_mode_file_decryption(self, file, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_decryptor = CBC_mode_cipher.decryptor()

        with open(f"{file}", "rb") as f:
            file_contents = f.read()
        decrypted_contents = CBC_mode_decryptor.update(file_contents) + CBC_mode_decryptor.finalize()
        with open(f"{file}", "wb") as f:
            f.write(decrypted_contents)

aes_cipher = AES()

# Function to handle AES operations
def handle_aes_operations(args):
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
        
        # Encrypts the data
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