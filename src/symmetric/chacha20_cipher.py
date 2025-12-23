from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend
import os

# ChaCha20 stream cipher implementation
# This class performs raw ChaCha20 encryption and decryption only
# and does not depend on CLI arguments, user input, or output formatting
class ChaCha20:
    def __init__(self):
        # ChaCha20 is stateless; no initialization required
        pass

    # =====================================================
    # PLAINTEXT OPERATIONS
    # =====================================================

    # Encrypt plaintext using ChaCha20
    # A 16-byte nonce is required and is prepended to the ciphertext
    def encrypt(self, plaintext, key, nonce=None):
        # Generate a random nonce if one is not supplied
        if nonce is None:
            nonce = os.urandom(16)

        # Create ChaCha20 algorithm instance
        algorithm = algorithms.ChaCha20(key, nonce)

        # Create cipher object (ChaCha20 does not use a block mode)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())

        # Encrypt plaintext
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext)

        # Return nonce + ciphertext so decryption can recover nonce
        return nonce + ciphertext

    # Decrypt ChaCha20 ciphertext
    # Expects the first 16 bytes of data to be the nonce
    def decrypt(self, data, key):
        # Extract nonce and ciphertext
        nonce = data[:16]
        ciphertext = data[16:]

        # Recreate cipher using extracted nonce
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None, backend=default_backend())

        # Decrypt ciphertext
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext)

        return plaintext

    # =====================================================
    # FILE OPERATIONS
    # =====================================================

    # Encrypt a file in-place using ChaCha20
    # The nonce is prepended to the encrypted file contents
    def encrypt_file(self, path, key, nonce=None):
        # Read file contents
        with open(path, "rb") as f:
            data = f.read()

        # Encrypt file data
        encrypted = self.encrypt(data, key, nonce)

        # Overwrite file with nonce + ciphertext
        with open(path, "wb") as f:
            f.write(encrypted)

    # Decrypt a file in-place using ChaCha20
    # Automatically extracts nonce from file contents
    def decrypt_file(self, path, key):
        # Read encrypted file contents
        with open(path, "rb") as f:
            data = f.read()

        # Decrypt file data
        decrypted = self.decrypt(data, key)

        # Overwrite file with plaintext
        with open(path, "wb") as f:
            f.write(decrypted)


# Reusable ChaCha20 cipher instance
chacha20_cipher = ChaCha20()