from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSA_digital_signatures:
    def __init__(self):
        pass

    def RSA_sign_bytes(message, private_key):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256
        )

        signature_in_bytes = signature.bytes()

        return signature_in_bytes
    
    def RSA_sign_hex(message, private_key):
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256
        )

        signature_in_hex = signature.hex()

        return signature_in_hex
    
    def RSA_verify_message(public_key, signature, message):
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid")
        except Exception as e:
            print("Signature is invalid", e)
    
    def RSA_sign_file(file_path, private_key):
        with open(file_path, "rb") as f:
            file_data = f.read()
        
        signature = private_key.sign(
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open("signature.sig", "wb") as sig_file:
            sig_file.write(signature)

    def RSA_verify_file(file_path, public_key):
        with open(file_path, "rb") as f:
            file_data = f.read()

        with open("signature.sig", "rb") as sig_file:
            signature = sig_file.read()

        try:
            public_key.verify(
                signature,
                file_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid.")
        except Exception as e:
            print("Signature is invalid:", e)