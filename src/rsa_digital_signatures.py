from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

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
            hashes.SHA256()
        )

        signature_in_bytes = signature.bytes()

        return signature_in_bytes
    
    def RSA_sign_hex(self, message, private_key):
        # If private_key is a file path, load the key
        if isinstance(private_key, str) and os.path.isfile(private_key):
            with open(private_key, 'rb') as key_file:
                key_data = key_file.read()
                private_key_obj = serialization.load_pem_private_key(key_data, password=None)
        else:
            private_key_obj = private_key
        signature = private_key_obj.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def RSA_verify_message(self, public_key, signature_file, message):
        # If public_key is a file path, load the key
        if isinstance(public_key, str) and os.path.isfile(public_key):
            with open(public_key, 'rb') as key_file:
                key_data = key_file.read()
                private_key_obj = serialization.load_pem_private_key(key_data, password=None)
                public_key_obj = private_key_obj.public_key()
        else:
            public_key_obj = public_key
        # Load signature from file
        with open(signature_file, 'rb') as f:
            signature = f.read()
        try:
            public_key_obj.verify(
                signature,
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature is valid.")
        except Exception as e:
            print(f"Signature verification failed: {e}")
    
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

rsa_digital_signature = RSA_digital_signatures()

# Function to handle RSA signature operations
def handle_rsa_signature_operations(args, loaded_key):
    if not args.operation or not args.input:
        print("RSA signature operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("RSA signing/verifying requires --key (or loaded key) argument (private/public key)")
        return
    
    if args.operation == "sign":
        message = args.input.encode()
        print("RSA signing requires private key loading from file or loaded key")
        print("Message to sign:", args.input)
        signature = rsa_digital_signature.RSA_sign_hex(args.input, args.key)
        if hasattr(args, 'output') and args.output:
            with open(args.output, 'wb') as f:
                f.write(signature)
            print(f"Signature written to {args.output}")
    
    elif args.operation == "verify":
        if not args.signature:
            print("RSA verification requires --signature argument")
            return
        message = args.input.encode()
        print("RSA verification requires public key and signature loading from files or loaded key")
        print("Message to verify:", args.input)
        print("Signature file:", args.signature)
        rsa_digital_signature.RSA_verify_message(args.key, args.signature, args.input)