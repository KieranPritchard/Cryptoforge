import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class RSADigitalSignatures:
    # Load a private key from a PEM file
    def load_private_key(self, pem_path):
        with open(pem_path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    # Load a public key from a PEM file
    def load_public_key(self, pem_path):
        with open(pem_path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    # Sign raw bytes using RSA-PSS with SHA256
    def sign_bytes(self, private_key, data):
        return private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    # Verify a signature over raw bytes
    def verify_bytes(self, public_key, data, signature):
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

    # Sign a UTF-8 message string and return signature bytes
    def sign_message(self, private_key, message):
        return self.sign_bytes(private_key, message.encode())

    # Verify a UTF-8 message string
    def verify_message(self, public_key, message, signature):
        self.verify_bytes(public_key, message.encode(), signature)

    # Sign a file and write the signature to a file
    def sign_file(self, private_key, file_path, signature_path):
        with open(file_path, "rb") as f:
            data = f.read()

        signature = self.sign_bytes(private_key, data)

        with open(signature_path, "wb") as f:
            f.write(signature)

    # Verify a file using a detached signature file
    def verify_file(self, public_key, file_path, signature_path):
        with open(file_path, "rb") as f:
            data = f.read()

        with open(signature_path, "rb") as f:
            signature = f.read()

        self.verify_bytes(public_key, data, signature)