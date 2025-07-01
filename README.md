# Crytoforge

## Project Description

This project is a comprehensive cryptography command line utility designed to provide a suite of cryptographic algorithms and tools for secure data processing and management. The utility includes implementations of various encryption, decryption, hashing, and digital signature algorithms, making it a versatile toolkit for beggineers.

### Objective

To create a simple to use cryptography tool; Which I can then use to in encryption, hash, and use digital signatures and learn about how cryptography works and is used. I made this to provide a simpler way of using cryptography with simpler commands compared to OpenSSL, it was also made to automate part of the process Openssl makes you perform. By working on this project the aim is to learn about cryptography further and also slowly build a tool which myself and possibly others can use in place of OpenSSL.

### Technology and Tools Used
- Python 3
- cryptography library
- argparse

## How to Use the Project

### Key Management Commands

1. **Save Key:** `keymgmt --save-key <key_data> --new-key-name <name> --key-type <type>`
2. **Load Key:** `keymgmt --load-key <key_name>`
3. **List Keys:** `keymgmt --list-keys`
4. **Rename Key:** `keymgmt --rename-key --old-name <old_name> --new-name <new_name>`
5. **Delete Key:** `keymgmt --delete-key <key_name>`

### Key Creation Commands
1. **Create AES Key:** `--aes-key [--bit-size <size>]`
2. **Create Blowfish Key:** `--blowfish-key [--bit-size <size>]`
3. **Create ChaCha20 Key:** `--chacha20-key [--bit-size <size>]`
4. **Create RSA Private Key:** `--rsa-private-key`
5. **Create RSA Public Key:** `--rsa-public-key --key <private_key_file>`
6. **Create ECC Private Key:** `--ecc-private-key`
7. **Create ECC Public Key:** `--ecc-public-key --key <private_key_file>`
8. **Create ECDSA Private Key:** `--ecdsa-private-key`
9. **Create ECDSA Public Key:** `--ecdsa-public-key --key <private_key_file>`

### Cryptographic Operation Commands

#### AES Operations
1. **AES Encrypt:** `aes --operation encrypt --input <file> --key <key> --iv <iv> [--output <file>]`
2. **AES Decrypt:** `aes --operation decrypt --input <file> --key <key> --iv <iv> [--output <file>]`
3. **AES Encrypt Plaintext:** `aes --operation encrypt --plaintext --input <string> --key <key> --iv <iv> [--output <file>]`
4. **AES Decrypt Plaintext:** `aes --operation decrypt --plaintext --input <hex_string> --key <key> --iv <iv> [--output <file>]`

#### Blowfish Operations
1. **Blowfish Encrypt:** `blowfish --operation encrypt --input <file> --key <key> [--output <file>]`
2. **Blowfish Decrypt:** `blowfish --operation decrypt --input <file> --key <key> [--output <file>]`
3. **Blowfish Encrypt Plaintext:** `blowfish --operation encrypt --plaintext --input <string> --key <key> [--output <file>]`
4. **Blowfish Decrypt Plaintext:** `blowfish --operation decrypt --plaintext --input <hex_string> --key <key> [--output <file>]`

#### ChaCha20 Operations
1. **ChaCha20 Encrypt:** `chacha20 --operation encrypt --input <file> --key <key> --nonce <nonce> [--output <file>]`
2. **ChaCha20 Decrypt:** `chacha20 --operation decrypt --input <file> --key <key> [--output <file>]`
3. **ChaCha20 Encrypt Plaintext:** `chacha20 --operation encrypt --plaintext --input <string> --key <key> --nonce <nonce> [--output <file>]`
4. **ChaCha20 Decrypt Plaintext:** `chacha20 --operation decrypt --plaintext --input <hex_string> --key <key> [--output <file>]`

#### Hash Operations (SHA-2, SHA-3, Blake2)
1. **SHA-2 Hash:** `sha200 --input <file_or_text> --hash-type <sha224|sha256|sha384|sha512> [--output <file>] [--output-format <hex|bytes>]`
2. **SHA-3 Hash:** `sha300 --input <file_or_text> --hash-type <sha3_224|sha3_256|sha3_384|sha3_512> [--output <file>] [--output-format <hex|bytes>]`
3. **Blake2 Hash:** `blake2 --input <file_or_text> --hash-type <blake2s|blake2b> [--output <file>] [--output-format <hex|bytes>]`

#### Digital Signature Operations
1. **ECDSA Sign:** `ecdsa --operation sign --input <message> --key <private_key> --output <signature_file>`
2. **ECDSA Verify:** `ecdsa --operation verify --input <message> --key <public_key_or_private_key> --signature <signature_file>`
3. **RSA Sign:** `rsa_signature --operation sign --input <message> --key <private_key> --output <signature_file>`
4. **RSA Verify:** `rsa_signature --operation verify --input <message> --key <public_key_or_private_key> --signature <signature_file>`

**Note:** For verification, you can provide either a public key or a private key PEM file (the public key will be derived automatically if a private key is provided).

### Main Function Categories
- `aes` - AES encryption/decryption
- `blowfish` - Blowfish encryption/decryption
- `chacha20` - ChaCha20 encryption/decryption
- `blake2` - Blake2 hashing
- `rsa` - RSA operations
- `sha200` - SHA-2 hashing
- `sha300` - SHA-3 hashing
- `ecdsa` - ECDSA digital signatures
- `rsa_signature` - RSA digital signatures

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

## Key Usage Behavior

For all cryptographic operations (encryption, decryption, signing, verification, etc.), you can provide a key using the `--key` argument. **If you do not provide the `--key` argument, the program will automatically use the key that was most recently loaded with the `--load-key` option during this execution.**

- If neither `--key` nor a loaded key is available, the operation will fail with an error message.
- This makes it easier to perform multiple operations after loading a key, without needing to specify `--key` each time.
- For digital signatures, the `--key` argument can be a PEM file path (private or public key). The program will automatically load and use the correct key object.

### Example Usage

1. **Load a key:**
   ```sh
   python Cryptoforge.py aes keymgmt --load-key my_aes_key.key
   ```
2. **Encrypt a file using the loaded key (no --key needed):**
   ```sh
   python Cryptoforge.py aes --operation encrypt --input plaintext.txt --iv <iv-hex>
   ```
3. **Or, specify a key directly:**
   ```sh
   python Cryptoforge.py aes --operation encrypt --input plaintext.txt --key <key-hex> --iv <iv-hex>
   ```
4. **Sign a file and output the signature:**
   ```sh
   python Cryptoforge.py rsa_signature --operation sign --input message.txt --key my_rsa_private.pem --output message.sig
   ```
5. **Verify a signature:**
   ```sh
   python Cryptoforge.py rsa_signature --operation verify --input message.txt --key my_rsa_private.pem --signature message.sig
   ```

**Note:** The fallback to the loaded key applies to all supported cryptographic functions, including AES, Blowfish, ChaCha20, ECDSA, and RSA operations.

## Troubleshooting

- **TypeError: ... takes 1 positional argument but 2 were given**
  - Ensure all class methods use `self` as the first parameter.
- **AttributeError: 'str' object has no attribute 'sign' or 'verify'**
  - Make sure you are passing a loaded key object, not a file path string. The program now automatically loads PEM keys if a file path is provided.
- **UnboundLocalError: cannot access local variable 'result'**
  - This is fixed in the latest version; all hash handlers now set `result` or print an error.
- **ValueError: nonce must be 128-bits (16 bytes)**
  - Ensure the nonce for ChaCha20 is exactly 16 bytes (32 hex characters).

## Licenses

