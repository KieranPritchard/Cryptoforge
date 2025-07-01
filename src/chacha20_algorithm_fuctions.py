from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend


class ChaCha20:
    def __init__(self):
        pass

    def ChaCha20_plaintext_encryption(self, key, nonce, plaintext):
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        encryptor = ChaCha20_cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        nonce_and_ciphertext = nonce+ciphertext
        return nonce_and_ciphertext
    
    def ChaCha20_ciphertext_decryption(self, key, nonce, ciphertext):
        # Always extract a 16-byte nonce
        nonce = ciphertext[:16]
        ciphertext = ciphertext[16:]
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key, nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        decryptor = ChaCha20_cipher.decryptor()
        plaintext = decryptor.update(ciphertext)
        return plaintext
    
    def ChaCha20_file_encryption(self, key, nonce, file):
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        encryptor = ChaCha20_cipher.encryptor()
        file_to_encrypt = open(file, "rb")
        file_contents = file_to_encrypt.read()
        encrypted_contents = encryptor.update(file_contents)
        file_to_encrypt.write(nonce + encrypted_contents)
        file_to_encrypt.close()

    def ChaCha20_file_decryption(self, key, nonce, file):
        file_to_decrypt = open(file, "rb")
        file_contents = file_to_decrypt.read()
        nonce = file_contents[:16]
        decrypted_contents = file_contents[16:]
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        decryptor = ChaCha20_cipher.decryptor()
        decrypted_contents = decryptor.update(decrypted_contents)
        file_to_decrypt.write(decrypted_contents)
        file_to_decrypt.close()

chacha20_cipher = ChaCha20()
# Function to handle ChaCha20 operations
def handle_chacha20_operations(args, loaded_key):
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
        
        # Convert key from hex if needed
        key_bytes = bytes.fromhex(key) if len(key) % 2 == 0 else key.encode()
        
        # Decrypt (let the method extract nonce and ciphertext)
        plaintext = chacha20_cipher.ChaCha20_ciphertext_decryption(key_bytes, None, data)
        
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