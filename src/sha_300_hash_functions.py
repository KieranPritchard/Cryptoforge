import hashlib

class SHA_300:
    def __init__(self):
        pass

    def sha3_224_plaintext_hash_bytes(plaintext):
        sha3_224_object = hashlib.sha3_224()
        sha3_224_object.update(plaintext)
        byte_digest = sha3_224_object.digest()
        return byte_digest
    
    def sha3_224_plaintext_hash_hex(plaintext):
        sha3_224_object = hashlib.sha3_224()
        sha3_224_object.update(plaintext)
        hex_digest = sha3_224_object.hexdigest()
        return hex_digest
    
    def sha3_224_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha3_224(data).digest()
        return hash_result_bytes
    
    def sha3_224_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha3_224(data).hexdigest()
        return hash_result_hex
    
    def sha3_256_plaintext_hash_bytes(plaintext):
        sha3_256_object = hashlib.sha3_256()
        sha3_256_object.update(plaintext)
        byte_digest = sha3_256_object.digest()
        return byte_digest
    
    def sha3_256_plaintext_hash_hex(plaintext):
        sha3_256_object = hashlib.sha3_256()
        sha3_256_object.update(plaintext)
        hex_digest = sha3_256_object.hexdigest()
        return hex_digest
    
    def sha3_256_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha3_256(data).digest()
        return hash_result_bytes
    
    def sha3_256_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha3_256(data).hexdigest()
        return hash_result_hex

    def sha3_384_plaintext_hash_bytes(plaintext):
        sha3_384_object = hashlib.sha3_384()
        sha3_384_object.update(plaintext)
        byte_digest = sha3_384_object.digest()
        return byte_digest
    
    def sha3_384_plaintext_hash_hex(plaintext):
        sha3_384_object = hashlib.sha3_384()
        sha3_384_object.update(plaintext)
        hex_digest = sha3_384_object.hexdigest()
        return hex_digest
    
    def sha3_384_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha3_384(data).digest()
        return hash_result_bytes
    
    def sha3_384_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex= hashlib.sha3_384(data).hexdigest()
        return hash_result_hex
    
    def sha3_512_plaintext_hash_bytes(plaintext):
        sha3_512_object = hashlib.sha3_512()
        sha3_512_object.update(plaintext)
        hash_bytes = sha3_512_object.digest()
        return hash_bytes
    
    def sha3_512_plaintext_hash_hex(plaintext):
        sha3_512_object = hashlib.sha3_512()
        sha3_512_object.update(plaintext)
        hash_hex = sha3_512_object.hexdigest()
        return hash_hex
    
    def sha3_512_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.sha3_512(data).digest()
        return hash_result_bytes
    
    def sha3_512_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex = hashlib.sha3_512(data).hexdigest()
        return hash_result_hex

sha300_hash = SHA_300()

def handle_sha300_hash_operations(args):
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
        if hash_type in ["sha3_224", "sha3_256", "sha3_384", "sha3_512"]:
            if is_file:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = sha300_hash.sha3_224_file_hash_hex(args.input)
                    elif hash_type == "sha256":
                        result = sha300_hash.sha3_256_file_hash_hex(args.input)
                    elif hash_type == "sha384":
                        result = sha300_hash.sha3_384_file_hash_hex(args.input)
                    elif hash_type == "sha512":
                        result = sha300_hash.sha3_512_file_hash_hex(args.input)
                else:
                    if hash_type == "sha224":
                        result = sha300_hash.sha3_224_file_hash_bytes(args.input)
                    elif hash_type == "sha256":
                        result = sha300_hash.sha3_256_file_hash_bytes(args.input)
                    elif hash_type == "sha384":
                        result = sha300_hash.sha3_384_file_hash_bytes(args.input)
                    elif hash_type == "sha512":
                        result = sha300_hash.sha3_512_file_hash_bytes(args.input)
            else:
                if output_format == "hex":
                    if hash_type == "sha224":
                        result = sha300_hash.sha224_plaintext_hash_hex(data)
                    elif hash_type == "sha256":
                        result = sha300_hash.sha256_plaintext_hash_hex(data)
                    elif hash_type == "sha384":
                        result = sha300_hash.sha384_plaintext_hash_hex(data)
                    elif hash_type == "sha512":
                        result = sha300_hash.sha512_plaintext_hash_hex(data)
                else:
                    if hash_type == "sha224":
                        result = sha300_hash.sha224_plaintext_hash_bytes(data)
                    elif hash_type == "sha256":
                        result = sha300_hash.sha256_plaintext_hash_bytes(data)
                    elif hash_type == "sha384":
                        result = sha300_hash.sha384_plaintext_hash_bytes(data)
                    elif hash_type == "sha512":
                        result = sha300_hash.sha512_plaintext_hash_bytes(data)
        else:
            print(f"Unsupported hash type: {hash_type}")
            return
    
    # Output result
    if args.output:
        with open(args.output, 'w') as f:
            if output_format == "hex":
                f.write(result)
            else:
                f.write(result.hex())
        print(f"Hash written to {args.output}")
    else:
        if output_format == "hex":
            print(f"Hash: {result}")
        else:
            print(f"Hash: {result.hex()}")