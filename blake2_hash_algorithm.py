import hashlib

class Blake2:
    def __init__(self):
        pass

    def blake2s_plaintext_hash_bytes(plaintext):
        blake2s_object = hashlib.blake2s()

        byte_updates = blake2s_object.update(plaintext)
        byte_digest = blake2s_object.digest(byte_updates)

        return byte_digest
    
    def blake2s_plaintext_hash_hex(plaintext):
        blake2s_object = hashlib.blake2s()

        byte_updates = blake2s_object.update(plaintext)
        hex_digest = blake2s_object.hexdigest(byte_updates)

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
    
    def blake2s_plaintext_hash_bytes(plaintext):
        blake2s_object = hashlib.blake2s()

        byte_updates = blake2s_object.update(plaintext)
        byte_digest = blake2s_object.digest(byte_updates)

        return byte_digest
    
    def blake2s_plaintext_hash_hex(plaintext):
        blake2s_object = hashlib.blake2s()

        byte_updates = blake2s_object.update(plaintext)
        hex_digest = blake2s_object.hexdigest(byte_updates)

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

        byte_updates = blake2b_object.update(plaintext)
        byte_digest = blake2b_object.digest(byte_updates)

        return byte_digest
    
    def blake2b_plaintext_hash_hex(plaintext):
        blake2b_object = hashlib.blake2b()

        byte_updates = blake2b_object.update(plaintext)
        hex_digest = blake2b_object.hexdigest(byte_updates)

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
    
    def blake2b_plaintext_hash_bytes(plaintext):
        blake2s_object = hashlib.blake2b()

        byte_updates = blake2s_object.update(plaintext)
        byte_digest = blake2s_object.digest(byte_updates)

        return byte_digest
    
    def blake2b_plaintext_hash_hex(plaintext):
        blake2s_object = hashlib.blake2b()

        byte_updates = blake2s_object.update(plaintext)
        hex_digest = blake2s_object.hexdigest(byte_updates)

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