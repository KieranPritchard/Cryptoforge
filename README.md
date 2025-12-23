# Cryptoforge

## Project Description

This project is a comprehensive cryptography command line utility designed to provide a suite of cryptographic algorithms and tools for secure data processing and management. The utility includes implementations of various encryption, decryption, hashing, and digital signature algorithms, making it a versatile toolkit for beginners.

**Note:** In addition to being a CLI tool, Cryptoforge also functions as a Python library. All cryptographic classes and functions can be imported and used directly in Python scripts, making it easy to integrate cryptographic operations into your own applications.

### Objective

To create a simple to use cryptography tool; Which I can then use to encrypt, hash, and use digital signatures and learn about how cryptography works and is used. I made this to provide a simpler way of using cryptography with simpler commands compared to OpenSSL, by working on this project the aim is to learn about cryptography further and also slowly build a tool which myself and others can use in place of OpenSSL.

### Technology and Tools Used
- Python 3
- cryptography library
- argparse

## How to Use the Project

### Key Management Commands

Use the `key` or `keymgmt` function for all key-related operations:

1. **Save Key:** `python cryptoforge.py key --save-key <key_data> --new-key-name <name> --key-type <type>`
2. **Load Key:** `python cryptoforge.py key --load-key <key_name>`
3. **List Keys:** `python cryptoforge.py key --list-keys`
4. **Rename Key:** `python cryptoforge.py key --rename-key --old-name <old_name> --new-name <new_name>`
5. **Delete Key:** `python cryptoforge.py key --delete-key <key_name>`

### Key Creation Commands

Use the `key` or `keymgmt` function for key generation:

1. **Create AES Key:** `python cryptoforge.py key --aes-key [--bit-size <size>]`
2. **Create Blowfish Key:** `python cryptoforge.py key --blowfish-key [--bit-size <size>]`
3. **Create ChaCha20 Key:** `python cryptoforge.py key --chacha20-key`
4. **Create RSA Private Key:** `python cryptoforge.py key --rsa-private-key [--bit-size <size>]`
5. **Create RSA Public Key:** `python cryptoforge.py key --rsa-public-key --key <private_key_file>`
6. **Create ECC Private Key:** `python cryptoforge.py key --ecc-private-key`
7. **Create ECC Public Key:** `python cryptoforge.py key --ecc-public-key --key <private_key_file>`
8. **Create ECDSA Private Key:** `python cryptoforge.py key --ecdsa-private-key`
9. **Create ECDSA Public Key:** `python cryptoforge.py key --ecdsa-public-key --key <private_key_file>`

**Note:** Key management and generation commands can also work with any function name (legacy support), but using `key` or `keymgmt` is recommended for clarity.

### Cryptographic Operation Commands

#### AES Operations
1. **AES Encrypt:** `python cryptoforge.py aes --operation encrypt --input <file> --key <key> --iv <iv> [--output <file>]`
2. **AES Decrypt:** `python cryptoforge.py aes --operation decrypt --input <file> --key <key> --iv <iv> [--output <file>]`
3. **AES Encrypt Plaintext:** `python cryptoforge.py aes --operation encrypt --plaintext --input <string> --key <key> --iv <iv> [--output <file>]`
4. **AES Decrypt Plaintext:** `python cryptoforge.py aes --operation decrypt --plaintext --input <hex_string> --key <key> --iv <iv> [--output <file>]`

#### Blowfish Operations
1. **Blowfish Encrypt:** `python cryptoforge.py blowfish --operation encrypt --input <file> --key <key> [--output <file>]`
2. **Blowfish Decrypt:** `python cryptoforge.py blowfish --operation decrypt --input <file> --key <key> [--output <file>]`
3. **Blowfish Encrypt Plaintext:** `python cryptoforge.py blowfish --operation encrypt --plaintext --input <string> --key <key> [--output <file>]`
4. **Blowfish Decrypt Plaintext:** `python cryptoforge.py blowfish --operation decrypt --plaintext --input <hex_string> --key <key> [--output <file>]`

#### ChaCha20 Operations
1. **ChaCha20 Encrypt:** `python cryptoforge.py chacha20 --operation encrypt --input <file> --key <key> --nonce <nonce> [--output <file>]`
2. **ChaCha20 Decrypt:** `python cryptoforge.py chacha20 --operation decrypt --input <file> --key <key> [--output <file>]`
3. **ChaCha20 Encrypt Plaintext:** `python cryptoforge.py chacha20 --operation encrypt --plaintext --input <string> --key <key> --nonce <nonce> [--output <file>]`
4. **ChaCha20 Decrypt Plaintext:** `python cryptoforge.py chacha20 --operation decrypt --plaintext --input <hex_string> --key <key> [--output <file>]`

#### Hash Operations (SHA-2, SHA-3, Blake2)
1. **SHA-2 Hash:** `python cryptoforge.py sha200 --input <file_or_text> --hash-type <sha224|sha256|sha384|sha512> [--output <file>] [--output-format <hex|bytes>]`
2. **SHA-3 Hash:** `python cryptoforge.py sha300 --input <file_or_text> --hash-type <sha3_224|sha3_256|sha3_384|sha3_512> [--output <file>] [--output-format <hex|bytes>]`
3. **Blake2 Hash:** `python cryptoforge.py blake2 --input <file_or_text> --hash-type <blake2s|blake2b> [--output <file>] [--output-format <hex|bytes>]`

#### File Integrity Operations
1. **Compute File Hash:** `python cryptoforge.py file_integrity --input <file> --hash-type <algorithm> [--output <file>]`
   - Supported algorithms: `sha224`, `sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`, `sha3_384`, `sha3_512`, `blake2b`, `blake2s`
2. **Verify File Integrity:** `python cryptoforge.py integrity --input <file> --hash-type <algorithm> --expected-hash <hash_value>`
   - Compares the computed hash of the file against the expected hash value

#### Digital Signature Operations
1. **ECDSA Sign:** `python cryptoforge.py ecdsa --operation sign --input <message> --key <private_key> --output <signature_file>`
2. **ECDSA Verify:** `python cryptoforge.py ecdsa --operation verify --input <message> --key <public_key_or_private_key> --signature <signature_file>`
3. **RSA Sign:** `python cryptoforge.py rsa_signature --operation sign --input <message> --key <private_key> --output <signature_file>`
4. **RSA Verify:** `python cryptoforge.py rsa_signature --operation verify --input <message> --key <public_key_or_private_key> --signature <signature_file>`

**Note:** For verification, you can provide either a public key or a private key PEM file (the public key will be derived automatically if a private key is provided).

### Main Function Categories
- `key` / `keymgmt` - Key management and generation operations
- `aes` - AES encryption/decryption
- `blowfish` - Blowfish encryption/decryption
- `chacha20` - ChaCha20 encryption/decryption
- `blake2` - Blake2 hashing
- `rsa` - RSA operations
- `sha200` - SHA-2 hashing
- `sha300` - SHA-3 hashing
- `ecdsa` - ECDSA digital signatures
- `rsa_signature` - RSA digital signatures
- `file_integrity` / `integrity` - File integrity checking (hash computation and verification)

### Common Arguments
- `--operation`: encrypt, decrypt, hash, sign, verify
- `--input`: Input data or file path
- `--output`: Output file path
- `--key`: Key for encryption/decryption/signing (can be a string or file path)
- `--iv`: Initialization vector (for AES)
- `--nonce`: Nonce (for ChaCha20)
- `--signature`: Signature file path
- `--hash-type`: Hash algorithm type
- `--output-format`: hex or bytes (for hashes)
- `--bit-size`: Key size in bits (default: 256)
- `--plaintext`: Treat `--input` as a plaintext string instead of a file for encryption/decryption operations. When set, the program will encrypt/decrypt the string directly and print the result (or save to `--output` if specified). Use this for direct string encryption/decryption.
- `--expected-hash`: Expected hash value for file integrity verification (used with `file_integrity`/`integrity` function)

## Key Usage Behavior

For all cryptographic operations (encryption, decryption, signing, verification, etc.), you can provide a key using the `--key` argument. **If you do not provide the `--key` argument, the program will automatically use the key that was most recently loaded with the `--load-key` option during this execution.**

- If neither `--key` nor a loaded key is available, the operation will fail with an error message.
- This makes it easier to perform multiple operations after loading a key, without needing to specify `--key` each time.
- For digital signatures, the `--key` argument can be a PEM file path (private or public key). The program will automatically load and use the correct key object.

### Example Usage

1. **List all saved keys:**
   ```sh
   python cryptoforge.py key --list-keys
   ```

2. **Generate and save an AES key:**
   ```sh
   python cryptoforge.py key --aes-key --bit-size 256
   ```

3. **Load a key:**
   ```sh
   python cryptoforge.py key --load-key my_aes_key.key
   ```

4. **Encrypt a file using the loaded key (no --key needed):**
   ```sh
   python cryptoforge.py aes --operation encrypt --input plaintext.txt --iv <iv-hex>
   ```

5. **Or, specify a key directly:**
   ```sh
   python cryptoforge.py aes --operation encrypt --input plaintext.txt --key <key-hex> --iv <iv-hex>
   ```

6. **Sign a file and output the signature:**
   ```sh
   python cryptoforge.py rsa_signature --operation sign --input message.txt --key my_rsa_private.pem --output message.sig
   ```

7. **Verify a signature:**
   ```sh
   python cryptoforge.py rsa_signature --operation verify --input message.txt --key my_rsa_private.pem --signature message.sig
   ```

8. **Compute file hash:**
   ```sh
   python cryptoforge.py file_integrity --input file.txt --hash-type sha256
   ```

9. **Verify file integrity:**
   ```sh
   python cryptoforge.py integrity --input file.txt --hash-type sha256 --expected-hash <expected_hash_value>
   ```

**Note:** The fallback to the loaded key applies to all supported cryptographic functions, including AES, Blowfish, ChaCha20, ECDSA, and RSA operations.

## Using as a Python Library

Cryptoforge can be imported and used as a library in your Python projects. All cryptographic classes are designed to be stateless and reusable.

### Example Library Usage

```python
from src.symmetric.aes_cipher import AES
from src.hashing.sha2_hash import SHA2
from src.core.key_management import KeyManager

# Initialize crypto instances
aes = AES()
sha2 = SHA2()
key_manager = KeyManager("./keys")

# Generate a key
key = key_manager.create_aes_key(256)

# Encrypt data
plaintext = b"Hello, World!"
ciphertext = aes.cbc_encrypt(plaintext, key)

# Decrypt data
decrypted = aes.cbc_decrypt(ciphertext, key)

# Hash data
hash_value = sha2.hash_bytes_hex(plaintext, "sha256")
print(f"SHA256: {hash_value}")

# Hash a file
file_hash = sha2.hash_file_hex("document.txt", "sha256")
print(f"File SHA256: {file_hash}")
```

### Available Classes for Import

**Symmetric Ciphers:**
- `src.symmetric.aes_cipher.AES`
- `src.symmetric.blowfish_cipher.Blowfish`
- `src.symmetric.chacha20_cipher.ChaCha20`

**Hashing:**
- `src.hashing.sha2_hash.SHA2`
- `src.hashing.sha3_hash.SHA3`
- `src.hashing.blake2_hash.Blake2`
- `src.hashing.file_integrity.FileIntegrityChecker`

**Asymmetric Crypto:**
- `src.asymmetric.rsa_cipher.RSA`
- `src.asymmetric.rsa_signatures.RSADigitalSignatures`
- `src.asymmetric.ecdsa_signatures.ECDSA`

**Key Management:**
- `src.core.key_management.KeyManager`
- `src.core.key_management.handle_key_management`
- `src.core.key_management.handle_key_creation`

All classes follow a consistent interface pattern and can be instantiated and used independently without the CLI.

## Troubleshooting

- **TypeError: ... takes 1 positional argument but 2 were given**
  - Ensure all class methods use `self` as the first parameter.
- **AttributeError: 'str' object has no attribute 'sign' or 'verify'**
  - Make sure you are passing a loaded key object, not a file path string. The program now automatically loads PEM keys if a file path is provided.
- **UnboundLocalError: cannot access local variable 'result'**
  - This is fixed in the latest version; all hash handlers now set `result` or print an error.
- **ValueError: nonce must be 128-bits (16 bytes)**
  - Ensure the nonce for ChaCha20 is exactly 16 bytes (32 hex characters).
