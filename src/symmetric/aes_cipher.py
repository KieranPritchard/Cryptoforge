from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os

# AES cipher implementation providing multiple encryption modes
# This class handles both plaintext and file-based encryption/decryption
class AES:
    def __init__(self):
        # No initialization state is required for this cipher class
        pass

    # =====================================================
    # CBC (Cipher Block Chaining) MODE METHODS
    # =====================================================

    # Encrypts plaintext using AES in CBC mode with PKCS7 padding
    # CBC requires padding because AES operates on fixed-size blocks
    def cbc_encrypt(self, plaintext, key):
        # Generate a cryptographically secure random 16-byte IV
        # The IV ensures identical plaintexts encrypt differently
        iv = os.urandom(16)

        # Create a PKCS7 padder for 128-bit blocks (AES block size)
        padder = sym_padding.PKCS7(128).padder()

        # Create the AES-CBC cipher object using the provided key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Create an encryptor context from the cipher
        encryptor = cipher.encryptor()

        # Pad the plaintext so its length is a multiple of the block size
        padded = padder.update(plaintext) + padder.finalize()

        # Encrypt the padded plaintext
        ciphertext = encryptor.update(padded) + encryptor.finalize()

        # Return IV concatenated with ciphertext for use during decryption
        return iv + ciphertext

    # Decrypts AES-CBC ciphertext and removes PKCS7 padding
    def cbc_decrypt(self, data, key):
        # Extract the IV from the first 16 bytes
        iv, ciphertext = data[:16], data[16:]

        # Recreate the AES-CBC cipher using the extracted IV
        cipher = Cipher( algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Create a decryptor context
        decryptor = cipher.decryptor()

        # Decrypt the ciphertext to obtain padded plaintext
        padded = decryptor.update(ciphertext) + decryptor.finalize()

        # Create a PKCS7 unpadder to remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()

        # Remove padding and return the original plaintext
        return unpadder.update(padded) + unpadder.finalize()

    # Encrypts a file in-place using AES-CBC
    # The original file contents are replaced with encrypted data
    def cbc_encrypt_file(self, path, key):
        # Read entire file contents as bytes
        data = open(path, "rb").read()

        # Encrypt file contents using CBC mode
        encrypted = self.cbc_encrypt(data, key)

        # Overwrite the original file with encrypted data
        open(path, "wb").write(encrypted)

    # Decrypts a file in-place using AES-CBC
    def cbc_decrypt_file(self, path, key):
        # Read encrypted file contents
        data = open(path, "rb").read()

        # Decrypt file contents using CBC mode
        decrypted = self.cbc_decrypt(data, key)

        # Overwrite the file with decrypted plaintext
        open(path, "wb").write(decrypted)

    # =====================================================
    # CFB (Cipher Feedback) MODE METHODS
    # =====================================================

    # Encrypts plaintext using AES-CFB
    # CFB mode does not require padding
    def cfb_encrypt(self, plaintext, key):
        # Generate a random IV for feedback chaining
        iv = os.urandom(16)

        # Create AES-CFB cipher
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        # Create encryptor context
        encryptor = cipher.encryptor()

        # Encrypt plaintext and prepend IV
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    # Decrypts AES-CFB ciphertext
    def cfb_decrypt(self, data, key):
        # Extract IV and ciphertext
        iv, ciphertext = data[:16], data[16:]

        # Create AES-CFB cipher with extracted IV
        cipher = Cipher( algorithms.AES(key), modes.CFB(iv), backend=default_backend())

        # Create decryptor context
        decryptor = cipher.decryptor()

        # Decrypt and return plaintext
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Encrypts a file in-place using AES-CFB
    def cfb_encrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.cfb_encrypt(data, key))

    # Decrypts a file in-place using AES-CFB
    def cfb_decrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.cfb_decrypt(data, key))

    # =====================================================
    # GCM (Galois/Counter Mode) MODE METHODS
    # =====================================================

    # Encrypts plaintext using AES-GCM
    # GCM provides confidentiality and authentication
    def gcm_encrypt(self, plaintext, key):
        # Generate random IV (nonce)
        iv = os.urandom(16)

        # Create AES-GCM cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

        # Create encryptor context
        encryptor = cipher.encryptor()

        # Encrypt plaintext
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Return IV + ciphertext + authentication tag
        return iv + ciphertext + encryptor.tag

    # Decrypts AES-GCM ciphertext and verifies authentication tag
    def gcm_decrypt(self, data, key):
        # Extract IV, ciphertext, and authentication tag
        iv, ciphertext, tag = data[:16], data[16:-16], data[-16:]

        # Create AES-GCM cipher with authentication tag
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())

        # Create decryptor context
        decryptor = cipher.decryptor()

        # Decrypt and verify integrity
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Encrypts a file in-place using AES-GCM
    def gcm_encrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.gcm_encrypt(data, key))

    # Decrypts a file in-place using AES-GCM
    def gcm_decrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.gcm_decrypt(data, key))

    # =====================================================
    # CTR (Counter) MODE METHODS
    # =====================================================

    # Encrypts plaintext using AES-CTR
    # CTR turns AES into a stream cipher
    def ctr_encrypt(self, plaintext, key):
        # Generate random counter value
        iv = os.urandom(16)

        # Create AES-CTR cipher
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv),backend=default_backend())

        # Create encryptor context
        encryptor = cipher.encryptor()

        # Encrypt plaintext and prepend counter value
        return iv + encryptor.update(plaintext) + encryptor.finalize()

    # Decrypts AES-CTR ciphertext
    # Encryption and decryption are symmetric in CTR mode
    def ctr_decrypt(self, data, key):
        iv, ciphertext = data[:16], data[16:]

        # Create AES-CTR cipher using extracted counter
        cipher = Cipher( algorithms.AES(key), modes.CTR(iv), backend=default_backend())

        # Create decryptor context
        decryptor = cipher.decryptor()

        # Decrypt and return plaintext
        return decryptor.update(ciphertext) + decryptor.finalize()

    # Encrypts a file in-place using AES-CTR
    def ctr_encrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.ctr_encrypt(data, key))

    # Decrypts a file in-place using AES-CTR
    def ctr_decrypt_file(self, path, key):
        data = open(path, "rb").read()
        open(path, "wb").write(self.ctr_decrypt(data, key))

# Reusable AES cipher instance
aes_cipher = AES()