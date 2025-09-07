from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

class Blowfish:
    def __init__(self):
        pass

    # -------------------
    # CBC mode functions
    # -------------------
    def cbc_plaintext_encryption(self, key, plaintext, iv):
        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()
        
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext
    
    def cbc_ciphertext_decryption(self, key, ciphertext, iv):
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        plaintext = plaintext_bytes.decode()

        return plaintext
    
    def cbc_file_encryption(self, key, file, iv):
        with open(file, "rb") as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize() 

        file.write(encrypted)

    def cbc_file_decryption(self, key, file, iv):
        with open(file, "rb") as f:
            data = f.read()

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_contents = decryptor.update(data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        plaintext = unpadder.update(padded_contents) + unpadder.finalize()

        file.write(plaintext)

    # -------------------
    # CFB mode functions
    # -------------------

    def cfb_plaintext_encryption(self, key, plaintext, iv):

        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + ciphertext
    
    def cfb_ciphertext_decryption(self, key, ciphertext):
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]

        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        coded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        plaintext = coded_plaintext.decode()

        return plaintext
    
    def cfb_file_encryption(self, key, file, iv):
        with open(file, "rb") as f:
            data = f.read
        
        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()

        with(file, "wb") as f:
            f.write(encrypted)

    def cfb_file_decryption(self, key, file, iv):
        with open(file, "rb") as f:
            data = f.read()

        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()

        with open(file, "wb") as  f:
            f.write(data)

blowfish_cipher = Blowfish()

# Function to handle Blowfish operations
def handle_blowfish_operations(args, loaded_key):
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