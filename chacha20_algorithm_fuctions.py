from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.backends import default_backend


class ChaCha20:
    def __init__(self):
        pass

    def ChaCha20_plaintext_encryption(key,nonce,plaintext):
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())

        encryptor = ChaCha20_cipher.encryptor()
        ciphertext = encryptor.update(plaintext)
        nonce_and_ciphertext = nonce+ciphertext

        return nonce_and_ciphertext
    
    def ChaCha20_ciphertext_decryption(key,nonce,ciphertext):
        nonce = ciphertext[:16]
        ciphertext = ciphertext[16:]

        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())

        decryptor = ChaCha20_cipher.decryptor()
        plaintext = decryptor.update(ciphertext)

        return plaintext
    
    def ChaCha20_file_encryption(key,nonce, file):
        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        encryptor = ChaCha20_cipher.encryptor()

        file_to_encrypt = open(file, "rb")
        file_contents = file_to_encrypt.read()
        encrypted_contents = encryptor.update(file_contents)
        file_to_encrypt.write(nonce + encrypted_contents)
        file_to_encrypt.close()

    def ChaCha20_file_decryption(key,nonce, file):
        file_to_decrypt = open(file, "rb")
        file_contents = file_to_decrypt.read()

        nonce = file_contents[:16]
        decrypted_contents = file_contents[16:]

        ChaCha20_cipher_algorithm = algorithms.ChaCha20(key,nonce)
        ChaCha20_cipher = Cipher(ChaCha20_cipher_algorithm, mode=None, backend=default_backend())
        decryptor = ChaCha20_cipher.decryptor()

        decrypted_contents = decryptor.update(decrypted_contents)
        file_to_decrypt.write(decrypted_contents)
        file_to_decrypt.close()