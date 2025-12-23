import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization


class KeyManager:
    def __init__(self, key_folder):
        self.key_folder = key_folder  # Store key directory path
        os.makedirs(self.key_folder, exist_ok=True)  # Ensure key directory exists

    # =========================
    # KEY STORAGE OPERATIONS
    # =========================

    def save_key(self, key_name, key_data, key_type):
        # Determine file extension based on key type
        if key_type in ("private", "public"):
            extension = ".pem"
        elif key_type == "symmetric":
            extension = ".key"
        else:
            raise ValueError("Invalid key type")

        # Build full file path
        path = os.path.join(self.key_folder, key_name + extension)

        # Write key data to disk
        with open(path, "w") as f:
            f.write(key_data)

        return path  # Return saved key path

    def load_key_path(self, key_name):
        # Build full key path
        path = os.path.join(self.key_folder, key_name)

        # Verify key exists
        if os.path.isfile(path):
            return path

        return None  # Key not found

    def list_keys(self):
        # Return all keys in key directory
        return os.listdir(self.key_folder)

    def rename_key(self, old_name, new_name):
        # Build old and new paths
        old_path = os.path.join(self.key_folder, old_name)
        new_path = os.path.join(self.key_folder, new_name)

        # Rename key file
        if os.path.isfile(old_path):
            os.rename(old_path, new_path)

    def delete_key(self, key_name):
        # Build full key path
        path = os.path.join(self.key_folder, key_name)

        # Remove key file
        if os.path.isfile(path):
            os.remove(path)

    # =========================
    # PEM KEY LOADING
    # =========================

    def load_private_key_from_pem(self, pem_data):
        # Load private key object from PEM string
        return serialization.load_pem_private_key(
            pem_data.encode(),
            password=None,
            backend=default_backend()
        )

    # =========================
    # SYMMETRIC KEY CREATION
    # =========================

    def create_aes_key(self, bit_size):
        # Generate AES key of valid size
        if bit_size not in (128, 192, 256):
            raise ValueError("Invalid AES key size")

        return os.urandom(bit_size // 8)

    def create_aes_cbc_iv(self):
        # Generate random 16-byte IV for AES-CBC
        return os.urandom(16)

    def create_chacha20_key(self):
        # Generate 256-bit ChaCha20 key
        return os.urandom(32)

    def create_chacha20_nonce(self):
        # Generate 128-bit ChaCha20 nonce
        return os.urandom(16)

    # =========================
    # RSA KEY CREATION
    # =========================

    def create_rsa_private_key(self, key_size=2048):
        # Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Serialize private key to PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_key, pem

    def create_rsa_public_key(self, private_key):
        # Derive RSA public key
        public_key = private_key.public_key()

        # Serialize public key to PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key, pem

    # =========================
    # ECC / ECDSA KEY CREATION
    # =========================

    def create_ecc_private_key(self):
        # Generate ECC private key
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )

        # Serialize private key to PEM
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_key, pem

    def create_ecc_public_key(self, private_key):
        # Derive ECC public key
        public_key = private_key.public_key()

        # Serialize public key to PEM
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key, pem