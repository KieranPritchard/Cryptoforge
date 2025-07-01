from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os
from cryptography.hazmat.primitives import serialization

class RSA:
    def __init__(self):
        pass

    def rsa_plaintext_encryption(self, public_key, plaintext):
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_ciphertext_decryption(self, private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    
    def rsa_file_encryption(self, public_key, file):
        file = open(file, "rb")
        file_contents = file.read()
        encrypted_contents = public_key.encrypt(
            file_contents,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        file = open(file, "wb")
        encrypted_file = file.write(encrypted_contents)

    def rsa_file_decryption(self, private_key, file):
        file = open(file, "rb")
        encrypted_contents = file.read()
        file.close()
        decrypted_contents = private_key.decrypt(
            encrypted_contents,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        file = open(file, "wb")
        file.write(decrypted_contents)
        file.close()

rsa_cipher = RSA()

def handle_rsa_operations(args, loaded_key):
    if not args.operation or not args.input:
        print("RSA operations require --operation and --input arguments")
        return

    key = args.key if args.key else loaded_key
    if not key:
        print("RSA encryption/decryption requires --key (or loaded key) arguments")
        return

    if args.operation == "encrypt":
        if args.plaintext:
            data = args.input.encode()
        else:
            with open(args.input, 'rb') as f:
                data = f.read()

        # Load public key from PEM file if key is a file path
        public_key = None
        if os.path.isfile(key):
            with open(key, 'rb') as key_file:
                key_data = key_file.read()
                try:
                    # Try loading as public key
                    public_key = serialization.load_pem_public_key(key_data)
                except Exception:
                    # If not public, try loading as private and get public key
                    private_key = serialization.load_pem_private_key(key_data, password=None)
                    public_key = private_key.public_key()
        else:
            public_key = key  # fallback, if already a key object

        ciphertext = rsa_cipher.rsa_plaintext_encryption(public_key, data)

        # Writes the output
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
            data = args.input
        else:
            with open(args.input, 'rb') as f:
                data = f.read()

        # Load private key from PEM file if key is a file path
        private_key = None
        if os.path.isfile(key):
            with open(key, 'rb') as key_file:
                key_data = key_file.read()
                private_key = serialization.load_pem_private_key(key_data, password=None)
        else:
            private_key = key  # fallback, if already a key object

        plaintext = rsa_cipher.rsa_ciphertext_decryption(private_key, data)

        if args.plaintext:
            if args.output:
                with open(args.output, 'w') as f:
                    # decode bytes to str for plaintext
                    f.write(plaintext.decode())
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {plaintext.decode()}")
        else:
            output_file = args.output if args.output else f"{args.input}.decrypted"
            with open(output_file, 'wb') as f:
                f.write(plaintext)
            print(f"Decrypted data written to {output_file}")