import hashlib

class Blake2:
    def __init__(self):
        pass

    def blake2s_plaintext_hash_bytes(plaintext):
        blake2s_object = hashlib.blake2s()
        blake2s_object.update(plaintext)
        byte_digest = blake2s_object.digest()
        return byte_digest
    
    def blake2s_plaintext_hash_hex(plaintext):
        blake2s_object = hashlib.blake2s()
        blake2s_object.update(plaintext)
        hex_digest = blake2s_object.hexdigest()
        return hex_digest
    
    def blake2s_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.blake2s(data).digest()
        return hash_result_bytes
    
    def blake2s_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex = hashlib.blake2s(data).hexdigest()
        return hash_result_hex
    
    def blake2b_plaintext_hash_bytes(plaintext):
        blake2b_object = hashlib.blake2b()
        blake2b_object.update(plaintext)
        byte_digest = blake2b_object.digest()
        return byte_digest
    
    def blake2b_plaintext_hash_hex(plaintext):
        blake2b_object = hashlib.blake2b()
        blake2b_object.update(plaintext)
        hex_digest = blake2b_object.hexdigest()
        return hex_digest
    
    def blake2b_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_bytes = hashlib.blake2b(data).digest()
        return hash_result_bytes
    
    def blake2b_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()
        hash_result_hex = hashlib.blake2b(data).hexdigest()
        return hash_result_hex

blake2_hash = Blake2()

def handle_blake2_hash_operations(args):
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

    if hash_type in ["blake2s", "blake2b"]:
        if is_file:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_file_hash_hex(args.input)
                else:
                    result = blake2_hash.blake2b_file_hash_hex(args.input)
            else:
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_file_hash_bytes(args.input)
                else:
                    result = blake2_hash.blake2b_file_hash_bytes(args.input)
        else:
            if output_format == "hex":
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_plaintext_hash_hex(data)
                else:
                    result = blake2_hash.blake2b_plaintext_hash_hex(data)
            else:
                if hash_type == "blake2s":
                    result = blake2_hash.blake2s_plaintext_hash_bytes(data)
                else:
                    result = blake2_hash.blake2b_plaintext_hash_bytes(data)
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