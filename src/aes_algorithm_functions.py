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
    def CBC_mode_plaintext_encryption(self, plaintext, key, iv):
        padder = sym_padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return ciphertext

    def CBC_mode_ciphertext_decryption(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        return plaintext

    def CBC_mode_file_encryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        with open(file, "wb") as f:
            f.write(encrypted)

    def CBC_mode_file_decryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(data) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        with open(file, "wb") as f:
            f.write(plaintext)

    # -------------------
    # CFB mode functions
    # -------------------
    def CFB_mode_plaintext_encryption(self, plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def CFB_mode_ciphertext_decryption(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def CFB_mode_file_encryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(encrypted)

    def CFB_mode_file_decryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)

    # -------------------
    # GCM mode functions
    # -------------------
    def GCM_mode_plaintext_encryption(self, plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag

    def GCM_mode_ciphertext_decryption(self, ciphertext, key, iv, tag):
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def GCM_mode_file_encryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        # Save ciphertext + tag together
        with open(file, "wb") as f:
            f.write(encrypted + encryptor.tag)

    def GCM_mode_file_decryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        ciphertext, tag = data[:-16], data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)

    # -------------------
    # CTR mode functions
    # -------------------
    def CTR_mode_plaintext_encryption(self, plaintext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext) + encryptor.finalize()

    def CTR_mode_ciphertext_decryption(self, ciphertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def CTR_mode_file_encryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        with open(file, "wb") as f:
            f.write(encrypted)

    def CTR_mode_file_decryption(self, file, key, iv):
        with open(file, "rb") as f:
            data = f.read()
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(data) + decryptor.finalize()
        with open(file, "wb") as f:
            f.write(decrypted)


aes_cipher = AES()

def handle_aes_operations(args, loaded_key, default_aes_mode):
    if not args.operation or (not args.plaintext and not args.file):
        print("AES operations require --operation and either --plaintext or --file")
        return

    key = args.key if args.key else loaded_key
    if not key or not args.iv:
        print("AES requires --key (or loaded key) and --iv")
        return

    # Convert key/iv
    key_bytes = bytes.fromhex(key) if all(c in "0123456789abcdefABCDEF" for c in key) and len(key) % 2 == 0 else key.encode()
    iv = bytes.fromhex(args.iv) if all(c in "0123456789abcdefABCDEF" for c in args.iv) and len(args.iv) % 2 == 0 else args.iv.encode()

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
                ciphertext = aes_cipher.CBC_mode_plaintext_encryption(data, key_bytes, iv)
            elif args.mode == "cfb":
                ciphertext = aes_cipher.CFB_mode_plaintext_encryption(data, key_bytes, iv)
            elif args.mode == "gcm":
                ciphertext, tag = aes_cipher.GCM_mode_plaintext_encryption(data, key_bytes, iv)
                ciphertext = ciphertext + tag
            elif args.mode == "ctr":
                ciphertext = aes_cipher.CTR_mode_plaintext_encryption(data, key_bytes, iv)
            else:
                if default_aes_mode == "cbc":
                    ciphertext = aes_cipher.CBC_mode_plaintext_encryption(data, key_bytes, iv)
                elif default_aes_mode == "cfb":
                    ciphertext = aes_cipher.CFB_mode_plaintext_encryption(data, key_bytes, iv)
                elif default_aes_mode == "gcm":
                    ciphertext, tag = aes_cipher.GCM_mode_plaintext_encryption(data, key_bytes, iv)
                    ciphertext = ciphertext + tag
                elif default_aes_mode == "ctr":
                    ciphertext = aes_cipher.CTR_mode_plaintext_encryption(data, key_bytes, iv)

            if args.output:
                with open(args.output, "wb") as f:
                    f.write(ciphertext)
                print(f"Encrypted data written to {args.output}")
            else:
                print(f"Encrypted (hex): {ciphertext.hex()}")

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                plaintext = aes_cipher.CBC_mode_ciphertext_decryption(data, key_bytes, iv)
            elif args.mode == "cfb":
                plaintext = aes_cipher.CFB_mode_ciphertext_decryption(data, key_bytes, iv)
            elif args.mode == "gcm":
                ciphertext, tag = data[:-16], data[-16:]
                plaintext = aes_cipher.GCM_mode_ciphertext_decryption(ciphertext, key_bytes, iv, tag)
            elif args.mode == "ctr":
                plaintext = aes_cipher.CTR_mode_ciphertext_decryption(data, key_bytes, iv)
            else: 
                if default_aes_mode == "cbc":
                    plaintext = aes_cipher.CBC_mode_ciphertext_decryption(data, key_bytes, iv)
                elif default_aes_mode == "cfb":
                    plaintext = aes_cipher.CFB_mode_ciphertext_decryption(data, key_bytes, iv)
                elif default_aes_mode == "gcm":
                    ciphertext, tag = data[:-16], data[-16:]
                    plaintext = aes_cipher.GCM_mode_ciphertext_decryption(ciphertext, key_bytes, iv, tag)
                elif default_aes_mode == "ctr":
                    plaintext = aes_cipher.CTR_mode_ciphertext_decryption(data, key_bytes, iv)

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
                aes_cipher.CBC_mode_file_encryption(infile, key_bytes, iv)
            elif args.mode == "cfb":
                aes_cipher.CFB_mode_file_encryption(infile, key_bytes, iv)
            elif args.mode == "gcm":
                aes_cipher.GCM_mode_file_encryption(infile, key_bytes, iv)
            elif args.mode == "ctr":
                aes_cipher.CTR_mode_file_encryption(infile, key_bytes, iv)
            else:
                if default_aes_mode == "cbc":
                    aes_cipher.CBC_mode_file_encryption(infile, key_bytes, iv)
                elif default_aes_mode == "cfb":
                    aes_cipher.CFB_mode_file_encryption(infile, key_bytes, iv)
                elif default_aes_mode == "gcm":
                    aes_cipher.GCM_mode_file_encryption(infile, key_bytes, iv)
                elif default_aes_mode == "ctr":
                    aes_cipher.CTR_mode_file_encryption(infile, key_bytes, iv)

        elif args.operation == "decrypt":
            if args.mode == "cbc":
                aes_cipher.CBC_mode_file_decryption(infile, key_bytes, iv)
            elif args.mode == "cfb":
                aes_cipher.CFB_mode_file_decryption(infile, key_bytes, iv)
            elif args.mode == "gcm":
                aes_cipher.GCM_mode_file_decryption(infile, key_bytes, iv)
            elif args.mode == "ctr":
                aes_cipher.CTR_mode_file_decryption(infile, key_bytes, iv)
            else: 
                if default_aes_mode == "cbc":
                    aes_cipher.CBC_mode_file_decryption(infile, key_bytes, iv)
                elif default_aes_mode == "cfb":
                    aes_cipher.CFB_mode_file_decryption(infile, key_bytes, iv)
                elif default_aes_mode == "gcm":
                    aes_cipher.GCM_mode_file_decryption(infile, key_bytes, iv)
                elif default_aes_mode == "ctr":
                    aes_cipher.CTR_mode_file_decryption(infile, key_bytes, iv)

        # Rename result
        os.rename(infile, outfile)
        print(f"{args.operation.capitalize()}ed file written to {outfile}")