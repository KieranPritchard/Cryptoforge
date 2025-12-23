import hashlib
import os

class FileIntegrityChecker:
    # Return a hash object for the selected algorithm
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

        # Reject unsupported algorithms
        if algorithm not in algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        return algorithms[algorithm]()  # Create hash object

    # Compute file hash using streaming reads
    def hash_file(self, file_path, algorithm):
        # Verify file exists
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        hash_object = self.select_algorithm(algorithm)  # Initialize hash

        # Read file in chunks to support large files
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_object.update(chunk)

        return hash_object.hexdigest()  # Return hex digest

    # Verify file integrity against expected hash
    def verify_file(self, file_path, expected_hash, algorithm):
        calculated_hash = self.hash_file(file_path, algorithm)
        return calculated_hash.lower() == expected_hash.lower()