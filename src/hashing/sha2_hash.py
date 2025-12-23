import hashlib
import os


class SHA2:
    def __init__(self):
        self.algorithms = {
            "sha224": hashlib.sha224,
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
        }

    # Internal helper to create a hash object
    def _get_hasher(self, algorithm):
        algorithm = algorithm.lower()
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return self.algorithms[algorithm]()

    # Hash raw bytes → bytes
    def hash_bytes(self, data: bytes, algorithm: str) -> bytes:
        hasher = self._get_hasher(algorithm)
        hasher.update(data)
        return hasher.digest()

    # Hash raw bytes → hex string
    def hash_bytes_hex(self, data: bytes, algorithm: str) -> str:
        hasher = self._get_hasher(algorithm)
        hasher.update(data)
        return hasher.hexdigest()

    # Hash a file → bytes (streamed, safe for large files)
    def hash_file(self, file_path: str, algorithm: str) -> bytes:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        hasher = self._get_hasher(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.digest()

    # Hash a file → hex string
    def hash_file_hex(self, file_path: str, algorithm: str) -> str:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        hasher = self._get_hasher(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.hexdigest()