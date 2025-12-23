import hashlib
import os


class SHA3:
    def __init__(self):
        self.algorithms = {
            "sha3_224": hashlib.sha3_224,
            "sha3_256": hashlib.sha3_256,
            "sha3_384": hashlib.sha3_384,
            "sha3_512": hashlib.sha3_512,
        }

    # Internal helper
    def _get_hasher(self, algorithm: str):
        algorithm = algorithm.lower()
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        return self.algorithms[algorithm]()

    # Hash raw bytes → bytes
    def hash_bytes(self, data: bytes, algorithm: str) -> bytes:
        hasher = self._get_hasher(algorithm)
        hasher.update(data)
        return hasher.digest()

    # Hash raw bytes → hex
    def hash_bytes_hex(self, data: bytes, algorithm: str) -> str:
        hasher = self._get_hasher(algorithm)
        hasher.update(data)
        return hasher.hexdigest()

    # Hash file → bytes (streamed)
    def hash_file(self, file_path: str, algorithm: str) -> bytes:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        hasher = self._get_hasher(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.digest()

    # Hash file → hex (streamed)
    def hash_file_hex(self, file_path: str, algorithm: str) -> str:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(file_path)

        hasher = self._get_hasher(algorithm)

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)

        return hasher.hexdigest()