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
    def cbc_plaintext_encryption(self, key, plaintext: bytes):
        iv = os.urandom(8)  # Blowfish block size = 64 bits
        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext

    def cbc_ciphertext_decryption(self, key, data: bytes):
        iv, ciphertext = data[:8], data[8:]
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    def cbc_file_encryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        ciphertext = self.cbc_plaintext_encryption(key, data)
        with open(file, "wb") as f:
            f.write(ciphertext)

    def cbc_file_decryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        plaintext = self.cbc_ciphertext_decryption(key, data)
        with open(file, "wb") as f:
            f.write(plaintext)

    # -------------------
    # CFB mode functions
    # -------------------
    def cfb_plaintext_encryption(self, key, plaintext: bytes):
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def cfb_ciphertext_decryption(self, key, data: bytes):
        iv, ciphertext = data[:8], data[8:]
        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def cfb_file_encryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        ciphertext = self.cfb_plaintext_encryption(key, data)
        with open(file, "wb") as f:
            f.write(ciphertext)

    def cfb_file_decryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        plaintext = self.cfb_ciphertext_decryption(key, data)
        with open(file, "wb") as f:
            f.write(plaintext)

    # -------------------
    # CTR mode functions
    # -------------------
    def ctr_plaintext_encryption(self, key, plaintext: bytes):
        iv = os.urandom(8)
        cipher = Cipher(algorithms.Blowfish(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def ctr_ciphertext_decryption(self, key, data: bytes):
        iv, ciphertext = data[:8], data[8:]
        cipher = Cipher(algorithms.Blowfish(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def ctr_file_encryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        ciphertext = self.ctr_plaintext_encryption(key, data)
        with open(file, "wb") as f:
            f.write(ciphertext)

    def ctr_file_decryption(self, key, file: str):
        with open(file, "rb") as f:
            data = f.read()
        plaintext = self.ctr_ciphertext_decryption(key, data)
        with open(file, "wb") as f:
            f.write(plaintext)


blowfish_cipher = Blowfish()

# -------------------
# Operation handler
# -------------------
def handle_blowfish_operations(args, loaded_key):
    if not args.operation or (not args.plaintext and not args.file):
        print("Blowfish operations require --operation and either --plaintext or --file")
        return

    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("Blowfish requires --key (or loaded key)")
        return

    # Convert key
    key_bytes = bytes.fromhex(key) if all(c in "0123456789abcdefABCDEF" for c in key) and len(key) % 2 == 0 else key.encode()

    # Plaintext mode
    if args.plaintext:
        data = args.plaintext.encode() if args.operation == "encrypt" else (
            bytes.fromhex(args.plaintext) if all(c in "0123456789abcdefABCDEF" for c in args.plaintext) and len(args.plaintext) % 2 == 0
            else args.plaintext.encode()
        )

        if args.operation == "encrypt":
            if args.mode == "cbc":
                ciphertext = blowfish_cipher.cbc_plaintext_encryption(key_bytes, data)
            elif args.mode == "cfb":
                ciphertext = blowfish_cipher.cfb_plaintext_encryption(key_bytes, data)
            elif args.mode == "ctr":
                ciphertext = blowfish_cipher.ctr_plaintext_encryption(key_bytes, data)
            else:
                ciphertext = blowfish_cipher.cbc_plaintext_encryption(key_bytes, data)

            if args.output:
                with open(args.output, "wb") as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                plaintext = blowfish_cipher.cbc_ciphertext_decryption(key_bytes, data)
            elif args.mode == "cfb":
                plaintext = blowfish_cipher.cfb_ciphertext_decryption(key_bytes, data)
            elif args.mode == "ctr":
                plaintext = blowfish_cipher.ctr_ciphertext_decryption(key_bytes, data)
            else:
                plaintext = blowfish_cipher.cbc_ciphertext_decryption(key_bytes, data)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(plaintext.decode(errors="ignore"))
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {plaintext.decode(errors='ignore')}")

    # File mode
    elif args.file:
        infile = args.file
        outfile = args.output if args.output else f"{infile}.{args.operation}ed"

        if args.operation == "encrypt":
            if args.mode == "cbc":
                blowfish_cipher.cbc_file_encryption(key_bytes, infile)
            elif args.mode == "cfb":
                blowfish_cipher.cfb_file_encryption(key_bytes, infile)
            elif args.mode == "ctr":
                blowfish_cipher.ctr_file_encryption(key_bytes, infile)
            else:
                blowfish_cipher.cbc_file_encryption(key_bytes, infile)

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                blowfish_cipher.cbc_file_decryption(key_bytes, infile)
            elif args.mode == "cfb":
                blowfish_cipher.cfb_file_decryption(key_bytes, infile)
            elif args.mode == "ctr":
                blowfish_cipher.ctr_file_decryption(key_bytes, infile)
            else:
                blowfish_cipher.cbc_file_decryption(key_bytes, infile)

        os.rename(infile, outfile)
        print(f"{args.operation.capitalize()}ed file written to {outfile}")