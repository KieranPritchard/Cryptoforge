import hashlib
import os

class file_integrity_checker:
    def __init__(self):
        pass

    def select_algorithm(algorithm):
        if algorithm == "sha224":
            return hashlib.sha224()
        elif algorithm == "sha256":
            return hashlib.sha256()
        elif algorithm == "sha384":
            return hashlib.sha384()
        elif algorithm == "sha512":
            return hashlib.sha512()
        elif algorithm == "sha3_224":
            return hashlib.sha3_224()
        elif algorithm == "sha3_256":
            return hashlib.sha3_256()
        elif algorithm == "sha3_384":
            return hashlib.sha3_384()
        elif algorithm == "sha3_512":
            return hashlib.sha3_512()
        elif algorithm == "blake2b":
            return hashlib.blake2b()
        elif algorithm == "blake2s":
            return hashlib.blake2s()