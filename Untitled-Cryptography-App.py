from cryptography import *
import os

class key_management:
    def __init__(self):
        pass

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
            public_exponent=65537
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

class AEScipher:
    def __init__(self,bits,mode):
        self.bits = bits
        self.mode = mode

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