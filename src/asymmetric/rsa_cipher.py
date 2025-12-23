import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


class RSA:
    # Encrypt raw bytes using an RSA public key (OAEP + SHA256)
    def encrypt_bytes(self, public_key, plaintext):
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Decrypt raw bytes using an RSA private key (OAEP + SHA256)
    def decrypt_bytes(self, private_key, ciphertext):
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # Encrypt a file in-place using an RSA public key
    def encrypt_file(self, public_key, file_path):
        with open(file_path, "rb") as f:
            data = f.read()

        encrypted_data = self.encrypt_bytes(public_key, data)

        with open(file_path, "wb") as f:
            f.write(encrypted_data)

    # Decrypt a file in-place using an RSA private key
    def decrypt_file(self, private_key, file_path):
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        decrypted_data = self.decrypt_bytes(private_key, encrypted_data)

        with open(file_path, "wb") as f:
            f.write(decrypted_data)

    # Load a public key from a PEM file or derive it from a private key
    def load_public_key(self, pem_path):
        with open(pem_path, "rb") as f:
            pem_data = f.read()

        try:
            return serialization.load_pem_public_key(pem_data)
        except ValueError:
            private_key = serialization.load_pem_private_key(pem_data, password=None)
            return private_key.public_key()

    # Load a private key from a PEM file
    def load_private_key(self, pem_path):
        with open(pem_path, "rb") as f:
            pem_data = f.read()

        return serialization.load_pem_private_key(pem_data, password=None)