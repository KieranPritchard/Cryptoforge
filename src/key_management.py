from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

class key_management:
    def __init__(self, key_folder):
        self.key_folder = key_folder
        # Create key folder if it doesn't exist
        os.makedirs(self.key_folder, exist_ok=True)

    # Create, Read, Update, and Delete Functionality
    def save_key(self, key_name, key_to_save, type_of_key):
        if type_of_key == "private":
            key_file = open(os.path.join(self.key_folder, f"{key_name}.pem"), "w")
            key_file.write(key_to_save)
            key_file.close()
        elif type_of_key == "public":
            key_file = open(os.path.join(self.key_folder, f"{key_name}.pem"), "w")
            key_file.write(key_to_save)
            key_file.close()
        elif type_of_key == "symetric":
            key_file = open(os.path.join(self.key_folder, f"{key_name}.key"), "w")
            key_file.write(key_to_save)
            key_file.close()

    def load_key(self, key_to_load):
        for key in os.listdir(self.key_folder):
            if key == key_to_load:
                key_path = os.path.join(self.key_folder, key_to_load)
                return key_path
        return None

    def load_rsa_private_key_from_pem(self, pem_data):
        """Load RSA private key from PEM string"""
        try:
            private_key = serialization.load_pem_private_key(
                pem_data.encode(),
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            print(f"Error loading RSA private key: {e}")
            return None

    def load_ecc_private_key_from_pem(self, pem_data):
        """Load ECC private key from PEM string"""
        try:
            private_key = serialization.load_pem_private_key(
                pem_data.encode(),
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            print(f"Error loading ECC private key: {e}")
            return None

    def load_ecdsa_private_key_from_pem(self, pem_data):
        """Load ECDSA private key from PEM string"""
        try:
            private_key = serialization.load_pem_private_key(
                pem_data.encode(),
                password=None,
                backend=default_backend()
            )
            return private_key
        except Exception as e:
            print(f"Error loading ECDSA private key: {e}")
            return None

    def list_keys(self):
        for key in os.listdir(self.key_folder):
            print(key)

    def rename_key(self, key_name, new_key_name):
        for key in os.listdir(self.key_folder):
            if key_name == key:
                old_path = os.path.join(self.key_folder, key)
                new_path = os.path.join(self.key_folder, new_key_name)
                os.rename(old_path, new_path)
                break

    def delete_key(self, key_to_delete):
        for key in os.listdir(self.key_folder):
            if key == key_to_delete:
                key_path = os.path.join(self.key_folder, key_to_delete)
                os.remove(key_path)
                break

    # Key creation for the different ciphers
    def create_aes_cbc_iv(self):
        new_iv = os.urandom(16)
        return new_iv
    
    def create_aes_key(self, bit_size):
        if bit_size == 128:
            new_aes_key = os.urandom(128 // 8)
            return new_aes_key
        elif bit_size == 192:
            new_aes_key = os.urandom(192 // 8)
            return new_aes_key
        elif bit_size == 256:
            new_aes_key = os.urandom(256 // 8)
            return new_aes_key
        else:
            print("Incorrect key size.")
            return None

    def create_blowfish_key(self, bit_size):
        if bit_size == 448:
            new_blowfish_key = os.urandom(448 // 8)
            return new_blowfish_key
        else:
            print("Unsecure key size.")
            return None

    def create_ChaCha20_nonce(self):
        new_ChaCha20_nonce = os.urandom(16)
        return new_ChaCha20_nonce

    def create_ChaCha20_key(self, bit_size):
        if bit_size == 256:
            new_ChaCha20_key = os.urandom(256 // 8)
            return new_ChaCha20_key
        else:
            print("Incorrect key length.")
            return None

    def create_rsa_private_key(self):
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
    
    def create_rsa_public_key(self, rsa_private_key):
        rsa_public_key = rsa_private_key.public_key()

        # Serialise public key
        rsa_public_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return rsa_public_key, rsa_public_pem
    
    def create_ecc_private_key(self):
        ecc_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        ecc_private_pem = ecc_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        return ecc_private_key, ecc_private_pem
    
    def create_ecc_public_key(self, ecc_private_key):
        ecc_public_key = ecc_private_key.public_key()

        # Serialize the public key to PEM format
        ecc_public_pem = ecc_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return ecc_public_key, ecc_public_pem
    
    def create_ecdsa_private_key(self):
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_key, private_key_pem
    
    def create_ecdsa_public_key(self, private_key):
        public_key = private_key.public_key()

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return public_key, public_key_pem
    

# Function to handle key management operations
def handle_key_management(args, loaded_key, key_manager):
    
    if args.save_key and args.new_key_name and args.key_type:
        # Saves the actual made key data
        print(f"Saving key '{args.new_key_name}' of type '{args.key_type}'")
        if loaded_key:
            key_manager.save_key(args.new_key_name, loaded_key, args.key_type)
        else:
            print("No key loaded to save")
    
    elif args.load_key:
        # loads a key from
        print(f"Loading key: {args.load_key}")
        loaded_key = key_manager.load_key(args.load_key)
        print(f"Loaded key from: {loaded_key}")
    
    elif args.list_keys:
        #Lists the keys from the specified folder
        print("Listing keys in key folder:")
        key_manager.list_keys()
    
    elif args.rename_key and args.old_name and args.new_name:
        print(f"Renaming key from '{args.old_name}' to '{args.new_name}'")
        key_manager.rename_key(args.old_name, args.new_name)
    
    elif args.delete_key:
        print(f"Deleting key: {args.delete_key}")
        key_manager.delete_key(args.delete_key)

# Function to handle key creation
def handle_key_creation(args, key_manager):
    bit_size = int(args.bit_size) if args.bit_size else 256
    
    if args.aes_key:
        print(f"Creating AES key with {bit_size} bits")
        aes_key = key_manager.create_aes_key(bit_size)
        if aes_key:
            print(f"AES key created: {aes_key.hex()}")
            # Save the key
            key_manager.save_key("aes_key", aes_key.hex(), "symetric")
    
    elif args.blowfish_key:
        print(f"Creating Blowfish key with {bit_size} bits")
        blowfish_key = key_manager.create_blowfish_key(bit_size)
        if blowfish_key:
            print(f"Blowfish key created: {blowfish_key.hex()}")
            # Save the key
            key_manager.save_key("blowfish_key", blowfish_key.hex(), "symetric")
    
    elif args.chacha20_key:
        print(f"Creating ChaCha20 key with {bit_size} bits")
        chacha20_key = key_manager.create_ChaCha20_key(bit_size)
        if chacha20_key:
            print(f"ChaCha20 key created: {chacha20_key.hex()}")
            # Save the key
            key_manager.save_key("chacha20_key", chacha20_key.hex(), "symetric")
    
    elif args.rsa_private_key:
        print("Creating RSA private key")
        rsa_private_key, rsa_private_pem = key_manager.create_rsa_private_key()
        print("RSA private key created")
        # Save the private key
        key_manager.save_key("rsa_private_key", rsa_private_pem.decode(), "private")
        print("RSA private key saved to keys folder")
    
    elif args.rsa_public_key:
        print("Creating RSA public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_rsa_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    rsa_public_key, rsa_public_pem = key_manager.create_rsa_public_key(private_key)
                    print("RSA public key created successfully")
                    # Save the public key
                    key_manager.save_key("rsa_public_key", rsa_public_pem.decode(), "public")
                    print("RSA public key saved to keys folder")
                else:
                    print("Failed to load RSA private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("RSA public key creation requires --key argument with private key file path")
    
    elif args.ecc_private_key:
        print("Creating ECC private key")
        ecc_private_key, ecc_private_pem = key_manager.create_ecc_private_key()
        print("ECC private key created")
        # Save the private key
        key_manager.save_key("ecc_private_key", ecc_private_pem.decode(), "private")
        print("ECC private key saved to keys folder")
    
    elif args.ecc_public_key:
        print("Creating ECC public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_ecc_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    ecc_public_key, ecc_public_pem = key_manager.create_ecc_public_key(private_key)
                    print("ECC public key created successfully")
                    # Save the public key
                    key_manager.save_key("ecc_public_key", ecc_public_pem.decode(), "public")
                    print("ECC public key saved to keys folder")
                else:
                    print("Failed to load ECC private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("ECC public key creation requires --key argument with private key file path")
    
    elif args.ecdsa_private_key:
        print("Creating ECDSA private key")
        ecdsa_private_key, ecdsa_private_pem = key_manager.create_ecdsa_private_key()
        print("ECDSA private key created")
        # Save the private key
        key_manager.save_key("ecdsa_private_key", ecdsa_private_pem.decode(), "private")
        print("ECDSA private key saved to keys folder")
    
    elif args.ecdsa_public_key:
        print("Creating ECDSA public key")
        if args.key:  # If private key file is provided
            try:
                # Load private key from file
                with open(args.key, 'r') as f:
                    private_key_pem = f.read()
                # Load the private key object
                private_key = key_manager.load_ecdsa_private_key_from_pem(private_key_pem)
                if private_key:
                    # Create public key from private key
                    ecdsa_public_key, ecdsa_public_pem = key_manager.create_ecdsa_public_key(private_key)
                    print("ECDSA public key created successfully")
                    # Save the public key
                    key_manager.save_key("ecdsa_public_key", ecdsa_public_pem.decode(), "public")
                    print("ECDSA public key saved to keys folder")
                else:
                    print("Failed to load ECDSA private key from file")
            except FileNotFoundError:
                print(f"Private key file not found: {args.key}")
        else:
            print("ECDSA public key creation requires --key argument with private key file path")