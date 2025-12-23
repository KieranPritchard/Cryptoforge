import hashlib


# Blake2 hashing implementation supporting blake2s and blake2b
# This class performs hashing only and does not handle CLI arguments,
# input detection, or output formatting
class Blake2:
    def __init__(self):
        # Blake2 does not require internal state
        pass

    # =====================================================
    # BLAKE2s HASHING (optimized for 32-bit platforms)
    # =====================================================

    # Hash plaintext bytes using blake2s and return raw bytes
    def blake2s_hash_bytes(self, data):
        hasher = hashlib.blake2s()
        hasher.update(data)
        return hasher.digest()

    # Hash plaintext bytes using blake2s and return hexadecimal string
    def blake2s_hash_hex(self, data):
        hasher = hashlib.blake2s()
        hasher.update(data)
        return hasher.hexdigest()

    # Hash a file using blake2s and return raw bytes
    def blake2s_file_hash_bytes(self, path):
        with open(path, "rb") as f:
            data = f.read()
        return hashlib.blake2s(data).digest()

    # Hash a file using blake2s and return hexadecimal string
    def blake2s_file_hash_hex(self, path):
        with open(path, "rb") as f:
            data = f.read()
        return hashlib.blake2s(data).hexdigest()

    # =====================================================
    # BLAKE2b HASHING (optimized for 64-bit platforms)
    # =====================================================

    # Hash plaintext bytes using blake2b and return raw bytes
    def blake2b_hash_bytes(self, data):
        hasher = hashlib.blake2b()
        hasher.update(data)
        return hasher.digest()

    # Hash plaintext bytes using blake2b and return hexadecimal string
    def blake2b_hash_hex(self, data):
        hasher = hashlib.blake2b()
        hasher.update(data)
        return hasher.hexdigest()

    # Hash a file using blake2b and return raw bytes
    def blake2b_file_hash_bytes(self, path):
        with open(path, "rb") as f:
            data = f.read()
        return hashlib.blake2b(data).digest()

    # Hash a file using blake2b and return hexadecimal string
    def blake2b_file_hash_hex(self, path):
        with open(path, "rb") as f:
            data = f.read()
        return hashlib.blake2b(data).hexdigest()


# Reusable Blake2 hashing instance
blake2_hash = Blake2()