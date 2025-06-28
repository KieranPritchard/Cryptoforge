from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding

class AES:
    def __init__(self):
        pass

    def padding(data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data
    
    def unpadder(data):
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(data) + unpadder.finalize()
        return plaintext.decode()
    
    def CBC_mode_plaintext_encryption(padded_plaintext, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_encryptor = CBC_mode_cipher.encryptor()
        ciphertext = CBC_mode_encryptor.update(padded_plaintext) + CBC_mode_encryptor.finalize()
        return ciphertext
    
    def CBC_mode_ciphertext_decryption(ciphertext,key,iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_decryptor = CBC_mode_cipher.decryptor()
        plaintext = CBC_mode_decryptor.update(ciphertext) + CBC_mode_decryptor.finalize()
        return plaintext
    
    def CBC_mode_file_encryption(file,key,iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_encryptor = CBC_mode_cipher.encryptor()

        file = open(f"{file}","rw")
        file_contents = file.read()
        encrypted_contents = CBC_mode_encryptor.update(file_contents) + CBC_mode_encryptor.finalize()
        file.write(encrypted_contents)
        file.close()

    def CBC_mode_file_decryption(file, key, iv):
        CBC_mode_cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        CBC_mode_decryptor = CBC_mode_cipher.decryptor()

        file = open(f"{file}","rw")
        file_contents = file.read()
        decrypted_contents = CBC_mode_decryptor.update(file_contents) + CBC_mode_decryptor.finalize()
        file.write(decrypted_contents)
        file.close()