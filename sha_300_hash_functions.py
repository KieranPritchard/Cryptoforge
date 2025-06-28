import hashlib

class SHA_300:
    def __init__(self):
        pass

    def sha3_224_plaintext_hash_bytes(plaintext):
        sha3_224_object = hashlib.sha3_224()

        byte_updates = sha3_224_object.update(plaintext)
        byte_digest = sha3_224_object.digest(byte_updates)

        return byte_digest
    
    def sha3_224_plaintext_hash_hex(plaintext):
        sha3_224_object = hashlib.sha3_224()

        byte_updates = sha3_224_object.update(plaintext)
        hex_digest = sha3_224_object.hexdigest(byte_updates)

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
        sha3_256_object = hashlib.sha3_224()

        byte_updates = sha3_256_object.update(plaintext)
        byte_digest = sha3_256_object.digest(byte_updates)

        return byte_digest
    
    def sha3_256_plaintext_hash_hex(plaintext):
        sha3_224_object = hashlib.sha3_256()

        byte_updates = sha3_224_object.update(plaintext)
        hex_digest = sha3_224_object.hexdigest(byte_updates)

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

        byte_updates = sha3_384_object.update(plaintext)
        byte_digest = sha3_384_object.digest(byte_updates)

        return byte_digest
    
    def sha3_384_plaintext_hash_hex(plaintext):
        sha3_384_object = hashlib.sha384()

        byte_updates = sha3_384_object.update(plaintext)
        hex_digest = sha3_384_object.hexdigest(byte_updates)

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

        byte_updates = sha3_512_object.update(plaintext)
        hash_bytes = sha3_512_object.digest(byte_updates)

        return hash_bytes
    
    def sha3_512_plaintext_hash_hex(plaintext):
        sha3_512_object = hashlib.sha3_512()

        byte_updates = sha3_512_object.update(plaintext)
        hash_hex = sha3_512_object.hexdigest(byte_updates)

        return hash_hex
    
    def sha3_512_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_bytes = hashlib.sha3_512(data).digest()

        return hash_result_bytes
    
    def sha3_512_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_hex = hashlib.sha3_512(data).hexdigest()

        return hash_result_hex
