from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSA:
    def __init__(self):
        pass

    def rsa_plaintext_encryption(public_key, plaintext):
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    def rsa_ciphertext_decryption(private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext
    
    def rsa_file_encryption(public_key, file):
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

    def rsa_file_decryption(private_key,file):

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

def handle_rsa_operations(args,loaded_key):
    if not args.operation or not args.input:
        print("RSA operations require --operation and --input arguments")

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
        
        # Encrypts the data
        public_key = loaded_key or args.key
        ciphertext = rsa_cipher.rsa_plaintext_encryption(public_key,data)

        # Writes the output
        if args.plaintext:
            if args.output:
                with open(args.output, 'wb') as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")

    elif args.operation == "decrypt":
        if args.plaintext:
            data = args.input
        else:
            with open(args.input, 'rb') as f:
                data = f.read()

        # decrypts the input
        private_key = key
        plaintext = rsa_cipher.rsa_ciphertext_decryption(private_key, data)

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