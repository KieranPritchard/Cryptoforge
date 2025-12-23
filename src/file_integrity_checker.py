import hashlib
import os


class FileIntegrityChecker:
    def __init__(self):
        pass

    def select_algorithm(self, algorithm):
        algorithms = {
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
            "sha3_224": hashlib.sha3_224,
            "sha3_256": hashlib.sha3_256,
            "sha3_384": hashlib.sha3_384,
            "sha3_512": hashlib.sha3_512,
            "blake2b": hashlib.blake2b,
            "blake2s": hashlib.blake2s,
        }

        if algorithm not in algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        return algorithms[algorithm]()

    def hash_file(self, file_path, algorithm):
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        hash_object = self.select_algorithm(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_object.update(chunk)

        return hash_object.hexdigest()

    def verify_file(self, file_path, expected_hash, algorithm):
        calculated_hash = self.hash_file(file_path, algorithm)
        return calculated_hash.lower() == expected_hash.lower()