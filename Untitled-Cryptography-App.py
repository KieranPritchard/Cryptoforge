import cryptography

class AEScipher:
    def __init__(self,bits,mode):
        self.bits = bits
        self.mode = mode