from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

def ecdsa_sign_file(file_path, signature_path, private_key):
        with open(file_path, "rb") as f:
            data = f.read()

        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))

        with open(signature_path, "wb") as f:
            f.write(signature)

def ecdsa_verify_file(file_path, signature_path, public_key):
        with open(file_path, "rb") as f:
            data = f.read()

        with open(signature_path, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            print("✅ Signature is valid.")
        except InvalidSignature:
            print("❌ Signature is INVALID.")