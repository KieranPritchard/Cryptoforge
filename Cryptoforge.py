import argparse
import json
import os

# ---- Core imports ----
from src.core.argument_handler import build_parser
from src.core.crypto_dispatcher import dispatch_crypto_operation

# ---- Key management ----
from src.core.key_management import KeyManager
from src.core.key_management import handle_key_management, handle_key_creation

# ---- Symmetric ciphers ----
from src.symmetric.aes_cipher import AES
from src.symmetric.blowfish_cipher import Blowfish
from src.symmetric.chacha20_cipher import ChaCha20

# ---- Asymmetric crypto ----
from src.asymmetric.rsa_cipher import RSA
from src.asymmetric.rsa_signatures import RSASignature
from src.asymmetric.ecdsa_signatures import ECDSASignature

# ---- Hashing ----
from src.hashing.blake2_hash import Blake2
from src.hashing.sha2_hash import SHA2
from src.hashing.sha3_hash import SHA3

# ---- File integrity ----
from src.hashing.file_integrity import FileIntegrityChecker


# ---- Load configuration ----
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# ---- Ensure key directory exists ----
os.makedirs(config["key_folder"], exist_ok=True)

# ---- Initialize managers ----
key_manager = KeyManager(config["key_folder"])

# ---- Initialize crypto objects ----
aes_cipher = AES()
blowfish_cipher = Blowfish()
chacha20_cipher = ChaCha20()
rsa_cipher = RSA()

rsa_signature = RSASignature()
ecdsa_signature = ECDSASignature()

blake2_hash = Blake2()
sha2_hash = SHA2()
sha3_hash = SHA3()

file_integrity = FileIntegrityChecker()

# ---- Defaults ----
DEFAULT_AES_MODE = config["default_aes_mode"]
DEFAULT_BLOWFISH_MODE = config["default_blowfish_mode"]

# ---- Argument parsing ----
parser = build_parser()
args = parser.parse_args()

loaded_key = None


# ---- Main execution ----
def main():
    global loaded_key

    # Key management operations
    if any([
        args.save_key,
        args.load_key,
        args.list_keys,
        args.rename_key,
        args.delete_key,
    ]):
        loaded_key = handle_key_management(args, loaded_key, key_manager)
        return

    # Key generation operations
    if any([
        args.aes_key,
        args.blowfish_key,
        args.chacha20_key,
        args.rsa_private_key,
        args.rsa_public_key,
        args.ecc_private_key,
        args.ecc_public_key,
        args.ecdsa_private_key,
        args.ecdsa_public_key,
    ]):
        handle_key_creation(args, key_manager)
        return

    # Cryptographic operations
    dispatch_crypto_operation(
        args=args,
        loaded_key=loaded_key,
        defaults={
            "aes_mode": DEFAULT_AES_MODE,
            "blowfish_mode": DEFAULT_BLOWFISH_MODE,
        },
    )


if __name__ == "__main__":
    main()