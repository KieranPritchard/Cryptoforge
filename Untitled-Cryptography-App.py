from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

class key_management:
    def __init__(self, key_folder):
        self.key_folder = key_folder

    # Create, Read, Update, and Delete Functionality
    def save_key(self, key_name, key_to_save, type_of_key):
        if type_of_key == "private":
            key_file = open(f"{key_name}.pem","w")
            key_file.write(key_to_save)
            key_file.close()
        elif type_of_key == "public":
            key_file = open(f"{key_name}.pem","w")
            key_file.write(key_to_save)
            key_file.close()
        elif type_of_key == "symetric":
            key_file = open(f"{key_name}.key","w")
            key_file.write(key_to_save)
            key_file.close()

    def load_key(self, key_to_load):
            for key in os.listdir(self.key_folder):
                if key == key_to_load:
                    key_to_load = os.path.join(self.key_folder,key_to_load)
                    return key_to_load
                else:
                    continue

    def list_keys(self):
        for key in os.listdir(self.key_folder):
            print(key)

    def rename_key(self,key_name, new_key_name):
        for key in os.listdir(self.key_folder):
            if key_name == key:
                os.rename(key,new_key_name)
            else:
                continue

    def delete_key(self, key_to_delete):
        for key in os.listdir(self.key_folder):
            if key == key_to_delete:
                os.remove(key_to_delete)

    # Key creation for the different ciphers
    def create_aes_cbc_iv():
        new_iv = os.urandom(16)
        return new_iv
    
    def create_aes_key(bit_size):
        if bit_size == 128:
            new_aes_key = os.urandom(128 // 8)
            return new_aes_key
        elif bit_size == 192:
            new_aes_key = os.urandom(192 // 8)
            return new_aes_key
        elif bit_size == 256:
            new_aes_key = os.urandom(256 //8)
            return new_aes_key
        else:
            print("Incorrect key size.")

    def create_blowfish_key(bit_size):
        if bit_size == 448:
            new_blowfish_key = os.urandom(448 // 8)
            return new_blowfish_key
        else:
            print("Unsecure key size.")

    def create_ChaCha20_nonce():
        new_ChaCha20_nonce = os.urandom(16)
        return new_ChaCha20_nonce

    def create_ChaCha20_key(bit_size):
        if bit_size == 256:
            new_ChaCha20_key = os.urandom(256 // 7)
            return new_ChaCha20_key
        else:
            print("Incorrect key length.")

    def create_rsa_private_key():
        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, 
            key_size=2048, 
            backend=default_backend()
        )

        # Serialise private key
        rsa_private_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    
        return rsa_private_key, rsa_private_pem
    
    def create_rsa_public_key(rsa_private_key):
        rsa_public_key = rsa_private_key.public_key()

        # Serialise public key
        rsa_public_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return rsa_public_key, rsa_public_pem
    
    def create_ecc_private_key():
        ecc_private_key = ec.generate_private_key(ec.SECP256R1)

        ecc_private_pem = ecc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return ecc_private_key, ecc_private_pem
    
    def create_ecc_public_key(ecc_private_key):
        ecc_public_key = ecc_private_key.public_key()

        # Serialize the public key to PEM format
        ecc_public_pem = ecc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return ecc_public_key, ecc_public_pem

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

class RSA:
    def __init__(self):
        pass

class SHA_2:
    def __init__(self):
        pass

class SHA_3:
    def __init__(self):
        pass

class Blake2:
    def __init__(self):
        pass