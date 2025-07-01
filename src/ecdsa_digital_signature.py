from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
import os

class ecdsa_digital_signature:
    def ecdsa_sign_bytes(message, private_key):
        # If private_key is a file path, load the key
        if isinstance(private_key, str) and os.path.isfile(private_key):
            with open(private_key, 'rb') as key_file:
                key_data = key_file.read()
                private_key_obj = serialization.load_pem_private_key(key_data, password=None)
        else:
            private_key_obj = private_key
        signature = private_key_obj.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )

        print("Signature:", signature.hex())
        return signature

    def ecdsa_verify_message(self, public_key, signature_file, message):
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
                ec.ECDSA(hashes.SHA256())
            )
            print("Signature is valid.")
        except Exception as e:
            print(f"Signature verification failed: {e}")

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
                print("Signature is valid.")
            except InvalidSignature:
                print("Signature is INVALID.")

# At the top of the file, after the class definition
ecdsa_digital_signature_instance = ecdsa_digital_signature()

# Function to handle ECDSA signature operations
def handle_ecdsa_signature_operations(args, loaded_key):
    if not args.operation or not args.input:
        print("ECDSA signature operations require --operation and --input arguments")
        return
    key = args.key if args.key else loaded_key
    if not key:
        print("ECDSA signing/verifying requires --key (or loaded key) argument (private/public key)")
        return
    if args.operation == "sign":
        message = args.input.encode()
        print("ECDSA signing requires private key loading from file or loaded key")
        print("Message to sign:", args.input)
        signature = ecdsa_digital_signature_instance.ecdsa_sign_bytes(args.input, args.key)
        if hasattr(args, 'output') and args.output:
            with open(args.output, 'wb') as f:
                f.write(signature)
            print(f"Signature written to {args.output}")
    elif args.operation == "verify":
        print("ECDSA verification requires public key and signature loading from files or loaded key")
        print("Message to verify:", args.input)
        print("Signature file:", args.signature)
        ecdsa_digital_signature_instance.ecdsa_verify_message(key, args.signature, args.input)