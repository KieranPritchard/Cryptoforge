import hashlib

class SHA_200:
    def __init__(self):
        pass

    def sha224_plaintext_hash_bytes(self, plaintext):
        sha224_object = hashlib.sha224()
        sha224_object.update(plaintext)
        byte_digest = sha224_object.digest()
        return byte_digest
    
    def sha224_plaintext_hash_hex(self, plaintext):
        sha224_object = hashlib.sha224()
        sha224_object.update(plaintext)
        hex_digest = sha224_object.hexdigest()
        return hex_digest
    
    def sha224_file_hash_bytes(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha224(data).digest()
        return hash_result_bytes
    
    def sha224_file_hash_hex(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha224(data).hexdigest()
        return hash_result_hex
    
    def sha256_plaintext_hash_bytes(self, plaintext):
        sha256_object = hashlib.sha256()
        sha256_object.update(plaintext)
        byte_digest = sha256_object.digest()
        return byte_digest
    
    def sha256_plaintext_hash_hex(self, plaintext):
        sha256_object = hashlib.sha256()
        sha256_object.update(plaintext)
        hex_digest = sha256_object.hexdigest()
        return hex_digest
    
    def sha256_file_hash_bytes(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha256(data).digest()
        return hash_result_bytes
    
    def sha256_file_hash_hex(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha256(data).hexdigest()
        return hash_result_hex

    def sha384_plaintext_hash_bytes(self, plaintext):
        sha384_object = hashlib.sha384()
        sha384_object.update(plaintext)
        byte_digest = sha384_object.digest()
        return byte_digest
    
    def sha384_plaintext_hash_hex(self, plaintext):
        sha384_object = hashlib.sha384()
        sha384_object.update(plaintext)
        hex_digest = sha384_object.hexdigest()
        return hex_digest
    
    def sha384_file_hash_bytes(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha384(data).digest()
        return hash_result_bytes
    
    def sha384_file_hash_hex(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha384(data).hexdigest()
        return hash_result_hex
    
    def sha512_plaintext_hash_bytes(self, plaintext):
        sha512_object = hashlib.sha512()
        sha512_object.update(plaintext)
        hash_bytes = sha512_object.digest()
        return hash_bytes
    
    def sha512_plaintext_hash_hex(self, plaintext):
        sha512_object = hashlib.sha512()
        sha512_object.update(plaintext)
        hash_hex = sha512_object.hexdigest()
        return hash_hex
    
    def sha512_file_hash_bytes(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha512(data).digest()
        return hash_result_bytes
    
    def sha512_file_hash_hex(self, file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex = hashlib.sha512(data).hexdigest()
        return hash_result_hex

sha200_hash = SHA_200()

def handle_sha200_hash_operations(args):
    if not args.input or not args.hash_type:
        print("Hash operations require --input and --hash-type arguments")
        return
    
    # Finds out if the input is a file or text
    try:
        with open(args.input, 'rb') as f:
            data = f.read()
        is_file = True
    except:
        data = args.input.encode()
        is_file = False

    hash_type = args.hash_type.lower()
    output_format = args.output_format

    if hash_type.startswith("sha"):
        if hash_type in ["sha224", "sha256", "sha384", "sha512"]:
            if is_file:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_file_hash_hex(args.input)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_file_hash_hex(args.input)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_file_hash_hex(args.input)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_file_hash_bytes(args.input)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_file_hash_bytes(args.input)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_file_hash_bytes(args.input)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_plaintext_hash_hex(data)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_plaintext_hash_hex(data)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_plaintext_hash_hex(data)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha224":
                        result = sha200_hash.sha224_plaintext_hash_bytes(data)
                    elif hash_type == "sha256":
                        result = sha200_hash.sha256_plaintext_hash_bytes(data)
                    elif hash_type == "sha384":
                        result = sha200_hash.sha384_plaintext_hash_bytes(data)
                    elif hash_type == "sha512":
                        result = sha200_hash.sha512_plaintext_hash_bytes(data)
        else:
            print(f"Unsupported hash type: {hash_type}")
            return
    
    # Output result
    if args.output:
        if output_format == "hex":
            with open(args.output, 'w') as f:
                f.write(result)
        else:
            with open(args.output, 'wb') as f:
                f.write(result)
        print(f"Hash written to {args.output}")
    else:
        if output_format == "hex":
            print(f"Hash: {result}")
        else:
            print(f"Hash: {result.hex()}")