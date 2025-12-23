from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# Blowfish cipher implementation supporting CBC, CFB, and CTR modes
# This class performs raw cryptographic operations only and does not
# handle CLI arguments, user input, or output formatting
class Blowfish:
    def __init__(self):
        # Blowfish does not require persistent internal state
        pass

    # =====================================================
    # CBC (Cipher Block Chaining) MODE
    # =====================================================

    # Encrypt plaintext using Blowfish CBC with PKCS7 padding
    def cbc_encrypt(self, plaintext, key):
        # Generate random 8-byte IV (Blowfish block size is 64 bits)
        iv = os.urandom(8)

        # Pad plaintext to align with block size
        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()

        # Create Blowfish CBC cipher
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())

        # Encrypt padded plaintext
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        # Return IV prepended to ciphertext
        return iv + ciphertext

    # Decrypt Blowfish CBC ciphertext and remove padding
    def cbc_decrypt(self, data, key):
        # Split IV and ciphertext
        iv, ciphertext = data[:8], data[8:]

        # Recreate cipher with extracted IV
        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())

        # Decrypt ciphertext
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove PKCS7 padding
        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

        return plaintext

    # Encrypt a file in-place using Blowfish CBC
    def cbc_encrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        encrypted = self.cbc_encrypt(data, key)
        with open(path, "wb") as f:
            f.write(encrypted)

    # Decrypt a file in-place using Blowfish CBC
    def cbc_decrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        decrypted = self.cbc_decrypt(data, key)
        with open(path, "wb") as f:
            f.write(decrypted)

    # =====================================================
    # CFB (Cipher Feedback) MODE
    # =====================================================

    # Encrypt plaintext using Blowfish CFB (no padding required)
    def cfb_encrypt(self, plaintext, key):
        iv = os.urandom(8)

        cipher = Cipher(algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + ciphertext

    # Decrypt Blowfish CFB ciphertext
    def cfb_decrypt(self, data, key):
        iv, ciphertext = data[:8], data[8:]

        cipher = Cipher( algorithms.Blowfish(key), modes.CFB(iv), backend=default_backend())

        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Encrypt a file in-place using Blowfish CFB
    def cfb_encrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(self.cfb_encrypt(data, key))

    # Decrypt a file in-place using Blowfish CFB
    def cfb_decrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(self.cfb_decrypt(data, key))

    # =====================================================
    # CTR (Counter) MODE
    # =====================================================

    # Encrypt plaintext using Blowfish CTR
    # Encryption and decryption are symmetric in CTR mode
    def ctr_encrypt(self, plaintext, key):
        iv = os.urandom(8)

        cipher = Cipher(algorithms.Blowfish(key), modes.CTR(iv),backend=default_backend())

        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return iv + ciphertext

    # Decrypt Blowfish CTR ciphertext
    def ctr_decrypt(self, data, key):
        iv, ciphertext = data[:8], data[8:]

        cipher = Cipher(algorithms.Blowfish(key),modes.CTR(iv),backend=default_backend())

        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Encrypt a file in-place using Blowfish CTR
    def ctr_encrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(self.ctr_encrypt(data, key))

    # Decrypt a file in-place using Blowfish CTR
    def ctr_decrypt_file(self, path, key):
        with open(path, "rb") as f:
            data = f.read()
        with open(path, "wb") as f:
            f.write(self.ctr_decrypt(data, key))


# Reusable Blowfish cipher instance
blowfish_cipher = Blowfish()