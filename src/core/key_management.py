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


# =========================
# KEY MANAGEMENT HANDLERS
# =========================

def handle_key_management(args, loaded_key, key_manager):
    """Handle key management operations (save, load, list, rename, delete)"""
    if args.save_key:  # Handle save key operation
        if not args.new_key_name or not args.key_type:  # Validate required arguments
            print("Error: --save-key requires --new-key-name and --key-type")
            return loaded_key  # Return unchanged loaded_key on error
        path = key_manager.save_key(args.new_key_name, args.save_key, args.key_type)  # Save key to disk
        print(f"Key saved to: {path}")
        return loaded_key  # Return unchanged loaded_key (key is saved, not loaded)
    
    if args.load_key:  # Handle load key operation
        key_path = key_manager.load_key_path(args.load_key)  # Get path to key file
        if key_path:  # If key file exists
            with open(key_path, "r") as f:  # Open key file for reading
                key_data = f.read()  # Read key data from file
            print(f"Key loaded from: {key_path}")
            return key_data  # Return loaded key data
        else:  # Key file not found
            print(f"Error: Key '{args.load_key}' not found")
            return loaded_key  # Return unchanged loaded_key on error
    
    if args.list_keys:  # Handle list keys operation
        keys = key_manager.list_keys()  # Get list of all keys
        if keys:  # If keys exist
            print("Available keys:")
            for key in keys:  # Iterate through keys
                print(f"  - {key}")  # Print each key name
        else:  # No keys found
            print("No keys found")
        return loaded_key  # Return unchanged loaded_key
    
    if args.rename_key:  # Handle rename key operation
        if not args.old_name or not args.new_name:  # Validate required arguments
            print("Error: --rename-key requires --old-name and --new-name")
            return loaded_key  # Return unchanged loaded_key on error
        key_manager.rename_key(args.old_name, args.new_name)  # Rename key file
        print(f"Key renamed from '{args.old_name}' to '{args.new_name}'")
        return loaded_key  # Return unchanged loaded_key
    
    if args.delete_key:  # Handle delete key operation
        key_manager.delete_key(args.delete_key)  # Delete key file
        print(f"Key '{args.delete_key}' deleted")
        return loaded_key  # Return unchanged loaded_key
    
    return loaded_key  # Return unchanged loaded_key if no operation matched


def handle_key_creation(args, key_manager):
    """Handle key generation operations"""
    bit_size = args.bit_size or 256  # Default to 256 bits if not specified
    
    if args.aes_key:  # Handle AES key generation
        key = key_manager.create_aes_key(bit_size)  # Generate AES key
        key_hex = key.hex()  # Convert bytes to hexadecimal string
        print(f"AES {bit_size}-bit key (hex): {key_hex}")
        return  # Exit after generating key
    
    if args.blowfish_key:  # Handle Blowfish key generation
        # Blowfish supports 32-448 bits, but we'll use bytes
        key_bytes = (bit_size // 8)  # Convert bits to bytes
        if key_bytes < 4:  # Enforce minimum key size
            key_bytes = 4
        elif key_bytes > 56:  # Enforce maximum key size
            key_bytes = 56
        key = os.urandom(key_bytes)  # Generate random key bytes
        key_hex = key.hex()  # Convert bytes to hexadecimal string
        print(f"Blowfish {len(key)*8}-bit key (hex): {key_hex}")
        return  # Exit after generating key
    
    if args.chacha20_key:  # Handle ChaCha20 key generation
        key = key_manager.create_chacha20_key()  # Generate ChaCha20 key (always 256 bits)
        key_hex = key.hex()  # Convert bytes to hexadecimal string
        print(f"ChaCha20 256-bit key (hex): {key_hex}")
        return  # Exit after generating key
    
    if args.rsa_private_key:  # Handle RSA private key generation
        key_size = args.bit_size or 2048  # Default to 2048 bits if not specified
        private_key, pem = key_manager.create_rsa_private_key(key_size)  # Generate RSA key pair
        key_hex = pem.decode()  # Decode PEM bytes to string
        print(f"RSA {key_size}-bit private key (PEM):\n{key_hex}")
        return  # Exit after generating key
    
    if args.rsa_public_key:  # Handle RSA public key extraction
        if not args.key:  # Validate private key file is provided
            print("Error: --rsa-public-key requires --key (private key file)")
            return  # Exit if key file missing
        with open(args.key, "rb") as f:  # Open private key file
            private_key = serialization.load_pem_private_key(f.read(), password=None)  # Load private key from PEM
        public_key, pem = key_manager.create_rsa_public_key(private_key)  # Extract public key from private key
        key_hex = pem.decode()  # Decode PEM bytes to string
        print(f"RSA public key (PEM):\n{key_hex}")
        return  # Exit after generating key
    
    if args.ecc_private_key or args.ecdsa_private_key:  # Handle ECC/ECDSA private key generation
        private_key, pem = key_manager.create_ecc_private_key()  # Generate ECC key pair
        key_hex = pem.decode()  # Decode PEM bytes to string
        print(f"ECC/ECDSA private key (PEM):\n{key_hex}")
        return  # Exit after generating key
    
    if args.ecc_public_key or args.ecdsa_public_key:  # Handle ECC/ECDSA public key extraction
        if not args.key:  # Validate private key file is provided
            print("Error: --ecc-public-key/--ecdsa-public-key requires --key (private key file)")
            return  # Exit if key file missing
        with open(args.key, "rb") as f:  # Open private key file
            private_key = serialization.load_pem_private_key(f.read(), password=None)  # Load private key from PEM
        public_key, pem = key_manager.create_ecc_public_key(private_key)  # Extract public key from private key
        key_hex = pem.decode()  # Decode PEM bytes to string
        print(f"ECC/ECDSA public key (PEM):\n{key_hex}")
        return  # Exit after generating key