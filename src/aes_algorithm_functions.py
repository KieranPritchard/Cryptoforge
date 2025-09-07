from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os

class AES:
    def __init__(self):
        pass

    # -------------------
    # CBC mode functions
    # -------------------
    def CBC_mode_plaintext_encryption(self, plaintext, key):
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext

    def CBC_mode_ciphertext_decryption(self, data, key):
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()

    def CBC_mode_file_encryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv = os.urandom(16)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(iv + encrypted)

    def CBC_mode_file_decryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        with open(file, "wb") as f:
            f.write(plaintext)

    # -------------------
    # CFB mode functions
    # -------------------
    def CFB_mode_plaintext_encryption(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def CFB_mode_ciphertext_decryption(self, data, key):
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def CFB_mode_file_encryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(iv + encrypted)

    def CFB_mode_file_decryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)

    # -------------------
    # GCM mode functions
    # -------------------
    def GCM_mode_plaintext_encryption(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext + encryptor.tag

    def GCM_mode_ciphertext_decryption(self, data, key):
        iv, ciphertext, tag = data[:16], data[16:-16], data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def GCM_mode_file_encryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(iv + encrypted + encryptor.tag)

    def GCM_mode_file_decryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv, ciphertext, tag = data[:16], data[16:-16], data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)

    # -------------------
    # CTR mode functions
    # -------------------
    def CTR_mode_plaintext_encryption(self, plaintext, key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    def CTR_mode_ciphertext_decryption(self, data, key):
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def CTR_mode_file_encryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(iv + encrypted)

    def CTR_mode_file_decryption(self, file, key):
        with open(file, "rb") as f:
            data = f.read()
        iv, ciphertext = data[:16], data[16:]
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)


aes_cipher = AES()

def handle_aes_operations(args, loaded_key, default_aes_mode):
    if not args.operation or (not args.plaintext and not args.file):
        print("AES operations require --operation and either --plaintext or --file")
        return

    key = args.key if args.key else loaded_key
    if not key:
        print("AES requires --key (or loaded key)")
        return

    # Convert key
    key_bytes = bytes.fromhex(key) if all(c in "0123456789abcdefABCDEF" for c in key) and len(key) % 2 == 0 else key.encode()

    # ==============
    # Plaintext mode
    # ==============
    if args.plaintext:
        data = args.plaintext.encode() if args.operation == "encrypt" else (
            bytes.fromhex(args.plaintext) if all(c in "0123456789abcdefABCDEF" for c in args.plaintext) and len(args.plaintext) % 2 == 0
            else args.plaintext.encode()
        )

        if args.operation == "encrypt":
            if args.mode == "cbc":
                ciphertext = aes_cipher.CBC_mode_plaintext_encryption(data, key_bytes)
            elif args.mode == "cfb":
                ciphertext = aes_cipher.CFB_mode_plaintext_encryption(data, key_bytes)
            elif args.mode == "gcm":
                ciphertext = aes_cipher.GCM_mode_plaintext_encryption(data, key_bytes)
            elif args.mode == "ctr":
                ciphertext = aes_cipher.CTR_mode_plaintext_encryption(data, key_bytes)
            else:
                if default_aes_mode == "cbc":
                    ciphertext = aes_cipher.CBC_mode_plaintext_encryption(data, key_bytes)
                elif default_aes_mode == "cfb":
                    ciphertext = aes_cipher.CFB_mode_plaintext_encryption(data, key_bytes)
                elif default_aes_mode == "gcm":
                    ciphertext = aes_cipher.GCM_mode_plaintext_encryption(data, key_bytes)
                elif default_aes_mode == "ctr":
                    ciphertext = aes_cipher.CTR_mode_plaintext_encryption(data, key_bytes)

            if args.output:
                with open(args.output, "wb") as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                plaintext = aes_cipher.CBC_mode_ciphertext_decryption(data, key_bytes)
            elif args.mode == "cfb":
                plaintext = aes_cipher.CFB_mode_ciphertext_decryption(data, key_bytes)
            elif args.mode == "gcm":
                plaintext = aes_cipher.GCM_mode_ciphertext_decryption(data, key_bytes)
            elif args.mode == "ctr":
                plaintext = aes_cipher.CTR_mode_ciphertext_decryption(data, key_bytes)
            else: 
                if default_aes_mode == "cbc":
                    plaintext = aes_cipher.CBC_mode_ciphertext_decryption(data, key_bytes)
                elif default_aes_mode == "cfb":
                    plaintext = aes_cipher.CFB_mode_ciphertext_decryption(data, key_bytes)
                elif default_aes_mode == "gcm":
                    plaintext = aes_cipher.GCM_mode_ciphertext_decryption(data, key_bytes)
                elif default_aes_mode == "ctr":
                    plaintext = aes_cipher.CTR_mode_ciphertext_decryption(data, key_bytes)

            if args.output:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(plaintext.decode(errors="ignore"))
                print(f"Decrypted data written to {args.output}")
            else:
                print(f"Decrypted: {plaintext.decode(errors='ignore')}")

    # ===========
    # File mode
    # ===========
    elif args.file:
        infile = args.file
        outfile = args.output if args.output else f"{infile}.{args.operation}ed"

        if args.operation == "encrypt":
            if args.mode == "cbc":
                aes_cipher.CBC_mode_file_encryption(infile, key_bytes)
            elif args.mode == "cfb":
                aes_cipher.CFB_mode_file_encryption(infile, key_bytes)
            elif args.mode == "gcm":
                aes_cipher.GCM_mode_file_encryption(infile, key_bytes)
            elif args.mode == "ctr":
                aes_cipher.CTR_mode_file_encryption(infile, key_bytes)
            else:
                if default_aes_mode == "cbc":
                    aes_cipher.CBC_mode_file_encryption(infile, key_bytes)
                elif default_aes_mode == "cfb":
                    aes_cipher.CFB_mode_file_encryption(infile, key_bytes)
                elif default_aes_mode == "gcm":
                    aes_cipher.GCM_mode_file_encryption(infile, key_bytes)
                elif default_aes_mode == "ctr":
                    aes_cipher.CTR_mode_file_encryption(infile, key_bytes)

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                aes_cipher.CBC_mode_file_decryption(infile, key_bytes)
            elif args.mode == "cfb":
                aes_cipher.CFB_mode_file_decryption(infile, key_bytes)
            elif args.mode == "gcm":
                aes_cipher.GCM_mode_file_decryption(infile, key_bytes)
            elif args.mode == "ctr":
                aes_cipher.CTR_mode_file_decryption(infile, key_bytes)
            else: 
                if default_aes_mode == "cbc":
                    aes_cipher.CBC_mode_file_decryption(infile, key_bytes)
                elif default_aes_mode == "cfb":
                    aes_cipher.CFB_mode_file_decryption(infile, key_bytes)
                elif default_aes_mode == "gcm":
                    aes_cipher.GCM_mode_file_decryption(infile, key_bytes)
                elif default_aes_mode == "ctr":
                    aes_cipher.CTR_mode_file_decryption(infile, key_bytes)

        os.rename(infile, outfile)
        print(f"{args.operation.capitalize()}ed file written to {outfile}")