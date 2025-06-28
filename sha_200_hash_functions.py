import hashlib

class SHA_200:
    def __init__(self):
        pass

    def sha224_plaintext_hash_bytes(plaintext):
        sha224_object = hashlib.sha224()

        byte_updates = sha224_object.update(plaintext)
        byte_digest = sha224_object.digest(byte_updates)

        return byte_digest
    
    def sha224_plaintext_hash_hex(plaintext):
        sha224_object = hashlib.sha224()

        byte_updates = sha224_object.update(plaintext)
        hex_digest = sha224_object.hexdigest(byte_updates)

        return hex_digest
    
    def sha224_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_bytes = hashlib.sha224(data).digest()
        return hash_result_bytes
    
    def sha224_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_hex= hashlib.sha224(data).hexdigest()
        return hash_result_hex
    
    def sha256_plaintext_hash_bytes(plaintext):
        sha256_object = hashlib.sha256()

        byte_updates = sha256_object.update(plaintext)
        byte_digest = sha256_object.digest(byte_updates)

        return byte_digest
    
    def sha256_plaintext_hash_hex(plaintext):
        sha224_object = hashlib.sha256()

        byte_updates = sha224_object.update(plaintext)
        hex_digest = sha224_object.hexdigest(byte_updates)

        return hex_digest
    
    def sha256_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_bytes = hashlib.sha256(data).digest()
        return hash_result_bytes
    
    def sha256_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_hex= hashlib.sha256(data).hexdigest()
        return hash_result_hex

    def sha384_plaintext_hash_bytes(plaintext):
        sha384_object = hashlib.sha384()

        byte_updates = sha384_object.update(plaintext)
        byte_digest = sha384_object.digest(byte_updates)

        return byte_digest
    
    def sha384_plaintext_hash_hex(plaintext):
        sha384_object = hashlib.sha384()

        byte_updates = sha384_object.update(plaintext)
        hex_digest = sha384_object.hexdigest(byte_updates)

        return hex_digest
    
    def sha384_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_bytes = hashlib.sha384(data).digest()
        return hash_result_bytes
    
    def sha384_file_hash_hex(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_hex= hashlib.sha384(data).hexdigest()
        return hash_result_hex
    
    def sha512_plaintext_hash_bytes(plaintext):
        sha512_object = hashlib.sha512()

        byte_updates = sha512_object.update(plaintext)
        hash_bytes = sha512_object.digest(byte_updates)

        return hash_bytes
    
    def sha512_plaintext_hash_hex(plaintext):
        sha512_object = hashlib.sha512()

        byte_updates = sha512_object.update(plaintext)
        hash_hex = sha512_object.hexdigest(byte_updates)

        return hash_hex
    
    def sha512_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_bytes = hashlib.sha512(data).digest()

        return hash_result_bytes
    
    def sha512_file_hash_bytes(file):
        file_to_hash = open(file, "rb")
        data = file_to_hash.read()
        file_to_hash.close()

        hash_result_hex = hashlib.sha512(data).hexdigest()

        return hash_result_hex