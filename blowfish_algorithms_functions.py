from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding
import os

class Blowfish:
    def __init__(self):
        pass

    def cbc_plaintext_encryption(key, plaintext):
        iv = os.urandom(8)

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

        return iv + ciphertext
    
    def cbc_ciphertext_decryption(key,ciphertext):
        iv = ciphertext[:8]
        ciphertext = ciphertext[8:]

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        plaintext_bytes = unpadder.update(padded_plaintext) + unpadder.finalize()
        plaintext = plaintext_bytes.decode()

        return plaintext
    
    def cbc_file_encryption(key, file):
        iv = os.urandom(8)

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        file = open(file,"rb")
        file_contents = file.read()

        padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
        padded_file = padder.update(file_contents.encode()) + padder.finalize()

        file.write(iv + padded_file)

    def cbc_file_decryption(key, file):
        file = open(file,"rb")
        file_contents = file.read()

        iv = file_contents[:8]
        encrypted_contents = file_contents[8:]

        cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_contents = decryptor.update(encrypted_contents) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
        file_bytes = unpadder.update(padded_contents) + unpadder.finalize()
        decrypted_file = file_bytes.decode()

        file.write(decrypted_file)