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
        self.key_folder

    # Create, Read, Update, and Delete Functionality
    def save_key(key_name, key_to_save, type_of_key):
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

    def list_keys(key_folder):
        for key in os.listdir(key_folder):
            print(key)

    def rename_key(key_folder,key_name, new_key_name):
        for key in os.listdir(key_folder):
            if key_name == key:
                os.rename(key,new_key_name)
            else:
                continue

    def delete_key(key_folder, key_to_delete):
        for key in os.listdir(key_folder):
            if key == key_to_delete:
                os.remove(key_to_delete)

    # Key creation for the different ciphers
    def create_iv():
        new_iv = os.urandom(16)
        return new_iv
    
    def create_aes_key(bit_size):
        if bit_size == 128:
            new_aes_key = os.urandom(128)
            return new_aes_key
        elif bit_size == 192:
            new_aes_key = os.urandom(192)
            return new_aes_key
        elif bit_size == 256:
            new_aes_key = os.urandom(256)
            return new_aes_key
        else:
            print("Incorrect key size.")

    def create_blowfish_key(bit_size):
        if bit_size == 448:
            new_blowfish_key = os.urandom(448)
            return new_blowfish_key
        else:
            print("Unsecure key size.")

    def create_ChaCha20_key(bit_size):
        if bit_size == 256:
            new_ChaCha20_key = os.urandom(256)
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

class AEScipher:
    def __init__(self):
        pass

class ChaCha20:
    def __init__(self):
        pass

class Blowfish:
    def __init__(self,mode):
        self.mode = mode

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