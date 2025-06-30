# Crytoforge

## Project Description

### Objective

### Technology and Tools Used

## How to Use the Project

### Key Management Commands

1. **Save Key:** `--save-key <key_name> --new-key-name <name> --key-type <type>`
2. **Load Key:** `--load-key <key_name>`
3. **List Keys:** `--list-keys`
4. **Rename Key:** `--rename-key --old-name <old_name> --new-name <new_name>`
5. **Delete Key:** `--delete-key <key_name>`

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

#### Blowfish Operations
1. **Blowfish Encrypt:** `blowfish --operation encrypt --input <file> --key <key> [--output <file>]`
2. **Blowfish Decrypt:** `blowfish --operation decrypt --input <file> --key <key> [--output <file>]`

#### ChaCha20 Operations
1. **ChaCha20 Encrypt:** `chacha20 --operation encrypt --input <file> --key <key> --nonce <nonce> [--output <file>]`
2. **ChaCha20 Decrypt:** `chacha20 --operation decrypt --input <file> --key <key> [--output <file>]`

#### Hash Operations (SHA-2, SHA-3, Blake2)
1. **SHA-2 Hash:** `sha200 --input <file_or_text> --hash-type <sha224|sha256|sha384|sha512> [--output <file>] [--output-format <hex|bytes>]`
2. **SHA-3 Hash:** `sha300 --input <file_or_text> --hash-type <sha3_224|sha3_256|sha3_384|sha3_512> [--output <file>] [--output-format <hex|bytes>]`
3. **Blake2 Hash:** `blake2 --input <file_or_text> --hash-type <blake2s|blake2b> [--output <file>] [--output-format <hex|bytes>]`

#### Digital Signature Operations
1. **ECDSA Sign:** `ecdsa --operation sign --input <message> --key <private_key>`
2. **ECDSA Verify:** `ecdsa --operation verify --input <message> --key <public_key> --signature <signature_file>`
3. **RSA Sign:** `rsa_signature --operation sign --input <message> --key <private_key>`
4. **RSA Verify:** `rsa_signature --operation verify --input <message> --key <public_key> --signature <signature_file>`

### Main Function Categories
- `aes` - AES encryption/decryption
- `blowfish` - Blowfish encryption/decryption
- `chacha20` - ChaCha20 encryption/decryption
- `blake2` - Blake2 hashing
- `rsa` - RSA operations (placeholder)
- `sha200` - SHA-2 hashing
- `sha300` - SHA-3 hashing
- `ecdsa` - ECDSA digital signatures
- `rsa_signature` - RSA digital signatures

### Common Arguments
- `--operation`: encrypt, decrypt, hash, sign, verify
- `--input`: Input data or file path
- `--output`: Output file path
- `--key`: Key for encryption/decryption/signing
- `--iv`: Initialization vector (for AES)
- `--nonce`: Nonce (for ChaCha20)
- `--signature`: Signature file path
- `--hash-type`: Hash algorithm type
- `--output-format`: hex or bytes (for hashes)
- `--bit-size`: Key size in bits (default: 256)

## Licenses