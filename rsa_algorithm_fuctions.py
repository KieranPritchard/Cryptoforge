from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class RSA:
    def __init__(self):
        pass

    def rsa_plaintext_encryption(public_key, plaintext):
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return ciphertext

    def rsa_ciphertext_decryption(private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return plaintext
    
    def rsa_file_encryption(public_key, file):
        file = open(file, "rb")
        file_contents = file.read()

        encrypted_contents = public_key.encrypt(
            file_contents,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        file = open(file, "wb")
        encrypted_file = file.write(encrypted_contents)

    def rsa_file_decryption(private_key,file):

        file = open(file, "rb")
        encrypted_contents = file.read()
        file.close()

        decrypted_contents = private_key.decrypt(
            encrypted_contents,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        file = open(file, "wb")
        file.write(decrypted_contents)
        file.close()