from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

class ecdsa_digital_signature:
    def ecdsa_sign_bytes(message, private_key):
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        print("Signature:", signature.hex())

    def ecdsa_sign_bytes(message, private_key):
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )

        print("Signature:", signature.bytes())

    def ecdsa_verify_message(public_key, signature, message):
        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            print("✅ Signature is valid.")
        except InvalidSignature:
            print("❌ Signature is INVALID.")


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


# Function to handle ECDSA signature operations
def handle_ecdsa_signature_operations(args, loaded_key):
    if not args.operation or not args.input:
        print("ECDSA signature operations require --operation and --input arguments")
        return
    
    # Use args.key if provided, else fallback to loaded_key
    key = args.key if args.key else loaded_key
    if not key:
        print("ECDSA signing/verifying requires --key (or loaded key) argument (private/public key)")
        return
    
    if args.operation == "sign":
        # For now, we'll use a simple message
        message = args.input.encode()
        print("ECDSA signing requires private key loading from file or loaded key")
        print("Message to sign:", args.input)
        ecdsa_digital_signature.ecdsa_sign_bytes(args.input, args.key)
    
    elif args.operation == "verify":
        if not args.signature:
            print("ECDSA verification requires --signature argument")
            return
        message = args.input.encode()
        print("ECDSA verification requires public key and signature loading from files or loaded key")
        print("Message to verify:", args.input)
        print("Signature file:", args.signature)
        ecdsa_digital_signature.ecdsa_verify_message(args.key, args.signature, args.input)