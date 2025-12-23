from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import os


# ECDSA digital signature implementation using the NIST P-256 curve
# This class performs signing and verification only and does not
# handle CLI arguments, user interaction, or output formatting
class ECDSA:
    def __init__(self):
        # ECDSA does not require persistent internal state
        pass

    # =====================================================
    # KEY LOADING HELPERS
    # =====================================================

    # Load an ECDSA private key from a PEM file
    def load_private_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=None
            )

    # Load an ECDSA public key from a PEM file
    def load_public_key(self, path):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(
                f.read()
            )

    # =====================================================
    # MESSAGE SIGNING & VERIFICATION
    # =====================================================

    # Sign a message (bytes) using an ECDSA private key
    def sign(self, message, private_key):
        # Perform ECDSA signature using SHA-256
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    # Verify a message signature using an ECDSA public key
    def verify(self, message, signature, public_key):
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False

    # =====================================================
    # FILE SIGNING & VERIFICATION
    # =====================================================

    # Sign a file and write the signature to disk
    def sign_file(self, file_path, signature_path, private_key):
        # Read file contents
        with open(file_path, "rb") as f:
            data = f.read()

        # Generate signature
        signature = self.sign(data, private_key)

        # Write signature to file
        with open(signature_path, "wb") as f:
            f.write(signature)

    # Verify a file signature
    def verify_file(self, file_path, signature_path, public_key):
        # Read file contents
        with open(file_path, "rb") as f:
            data = f.read()

        # Read signature
        with open(signature_path, "rb") as f:
            signature = f.read()

        # Verify signature
        return self.verify(data, signature, public_key)


# Reusable ECDSA service instance
ecdsa = ECDSA()