# =========================
# Algorithm Imports
# =========================

# Symmetric encryption algorithms
from src.symmetric.aes_cipher import AES              # AES block cipher (CBC/CFB/CTR)
from src.symmetric.blowfish_cipher import Blowfish    # Blowfish block cipher
from src.symmetric.chacha20_cipher import ChaCha20    # ChaCha20 stream cipher

# Hashing algorithms
from src.hashing.blake2_hash import Blake2            # Blake2 hashing
from src.hashing.sha2_hash import SHA2                # SHA-2 family hashing
from src.hashing.sha3_hash import SHA3                # SHA-3 family hashing

# Asymmetric cryptography
from src.asymmetric.rsa_cipher import RSA              # RSA encryption/decryption
from src.asymmetric.ecdsa_signatures import ECDSA      # ECDSA digital signatures
from src.asymmetric.rsa_signatures import RSADigitalSignatures  # RSA signatures

# File integrity utilities
from src.hashing.file_integrity import FileIntegrityChecker  # Hash-based file verification

# Standard library imports
import os                                             # File system utilities

# Cryptography library helpers
from cryptography.hazmat.primitives import serialization  # Key serialization utilities
from cryptography.exceptions import InvalidSignature      # Signature verification error


# =========================
# Crypto Dispatcher
# =========================

class CryptoDispatcher:
    """Maps function names to crypto classes and instantiates them"""

    def __init__(self, defaults):
        self.defaults = defaults  # Store default crypto modes/settings

        # Registry mapping CLI function names → implementation classes
        self._registry = {
            "aes": AES,
            "blowfish": Blowfish,
            "chacha20": ChaCha20,
            "blake2": Blake2,
            "sha200": SHA2,
            "sha300": SHA3,
            "rsa": RSA,
            "ecdsa": ECDSA,
            "rsa_signature": RSADigitalSignatures,
            "file_integrity": FileIntegrityChecker,
            "integrity": FileIntegrityChecker,  # Alias for convenience
        }

    def dispatch(self, function):
        """Return a new crypto object based on function name"""
        function = function.lower()  # Normalize input

        # Checks if the function is in the registry
        if function not in self._registry:
            # Raises error if it does not exist
            raise ValueError(
                f"Unknown function '{function}'. "
                f"Available: {', '.join(self._registry.keys())}"
            )
        return self._registry[function]()  # Instantiate requested crypto class


# =========================
# Key Parsing Helpers
# =========================

def _parse_key(key_arg, loaded_key):
    """Resolve key from CLI argument, loaded key, or key file"""
    if key_arg:  # Checks key passed directly via CLI
        if os.path.isfile(key_arg):  # Treat argument as file path
            # Opens the file
            with open(key_arg, "r") as f:
                # Extracts the key data
                key_data = f.read().strip()
            # Try hex-decoding
            try:
                # Returns an encoded key
                return bytes.fromhex(key_data)  
            except ValueError:
                # Fall back to raw string
                return key_data.encode()       
        else:  # Key provided inline
            try:
                # Returns the bytes from the hexadecimal key
                return bytes.fromhex(key_arg)
            except ValueError:
                # Returns an encoded key
                return key_arg.encode()

    elif loaded_key:  # Use previously loaded key
        try:
            # Returns the bytes from the hexadecimal key
            return bytes.fromhex(loaded_key)
        except (ValueError, AttributeError):
            # Encode string to bytes or return as is if already bytes
            return loaded_key.encode() if isinstance(loaded_key, str) else loaded_key

    return None  # No usable key found


def _parse_hex_bytes(hex_string, byte_length=None):
    """Convert hex string to bytes and optionally validate length"""
    # Checks if there is not a hex string
    if not hex_string:
        return None

    # Tries to parse the hex string
    try:
        # Converts the hex string into bytes
        data = bytes.fromhex(hex_string)
        # Checks for if the byte and length data do not match the bit length
        if byte_length and len(data) != byte_length:
            # Raises an error message
            raise ValueError(f"Expected {byte_length} bytes, got {len(data)}")
        # Returns the data
        return data
    # Catches a value error
    except ValueError as e:
        # Raises value error
        raise ValueError(f"Invalid hex string: {e}")


# =========================
# Input / Output Helpers
# =========================

def _read_input(args):
    """Read input either as plaintext or from a file"""

    # Checks if the arguments contain plaintext
    if args.plaintext:  # Treat input as literal text
        # Returns the input as encoded if there is a args input
        return args.input.encode('utf-8') if args.input else None
    else: # Treat input as file path
        # Checks if the input is not doesn't exist
        if not args.input or not os.path.isfile(args.input):
            # Raises an error
            raise FileNotFoundError(f"Input file not found: {args.input}")
        # Opens the inputted file
        with open(args.input, "rb") as f:
            return f.read()  # Always read files as raw bytes


def _write_output(data, output_path, is_text=False):
    """Write output to file or print to console"""

    # Checks if there is an output path and saves it to a file
    if output_path: 
        # Decides which mode to use on the file (text vs binary)
        mode = "w" if is_text else "wb"
        # Opens the output file
        with open(output_path, mode) as f:
            # Writes data to it
            f.write(data)
        # Tells the user the output path
        print(f"Output written to: {output_path}")
    else:  # No output file → print result
        if isinstance(data, bytes):
            print(data.hex())  # Print bytes as hex for visibility
        else:
            print(data) # Print text directly


# =========================
# File Integrity Dispatcher
# =========================

def dispatch_file_integrity(args, integrity_checker):
    """Handle file hash computation and verification"""

    # Checks if there is an argument for input
    if not args.input:
        # Outputs an error message
        print("Error: --input required for file integrity operations")
        return

    # Checks if there isn't a hash type specified
    if not args.hash_type:
        # Outputs an error message
        print("Error: --hash-type required for file integrity operations")
        return

    # Compute file hash if no expected hash is provided
    if not args.expected_hash:
        try:
            # Generates hash of the specified file
            file_hash = integrity_checker.hash_file(args.input, args.hash_type)
            # If output path exists, save it to file
            if args.output:
                with open(args.output, "w") as f:
                    f.write(file_hash)
                print(f"Hash saved to {args.output}")
            else:
                # Otherwise, print the hash to console
                print(f"{args.hash_type.upper()}: {file_hash}")
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")

    # Verify file hash if an expected hash is provided
    else:
        try:
            # Compares actual file hash against the provided expected hash
            is_valid = integrity_checker.verify_file(
                args.input, args.expected_hash, args.hash_type
            )

            # Re-calculate hash for display purposes in case of failure
            calculated = integrity_checker.hash_file(args.input, args.hash_type)

            if is_valid:
                print(f"✓ File integrity verified: {args.input}")
            else:
                print(f"✗ File integrity check FAILED: {args.input}")

            # Show comparison results
            print(f"  Expected:   {args.expected_hash}")
            print(f"  Calculated: {calculated}")

        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}")


# =========================
# Main Crypto Dispatcher
# =========================

def dispatch_crypto_operation(args, loaded_key, defaults):
    """Route CLI requests to the correct crypto operation"""

    # Initialize the dispatcher with default settings
    dispatcher = CryptoDispatcher(defaults)

    # Safely extract the function name from CLI arguments
    function_name = args.function.lower() if getattr(args, 'function', None) else None
    if not function_name:
        print("Error: No function specified")
        return

    # Route specifically to file integrity logic if requested
    if function_name in ("file_integrity", "integrity"):
        dispatch_file_integrity(args, FileIntegrityChecker())
        return

    # Instantiate the algorithm class (AES, RSA, etc.) via the dispatcher
    try:
        crypto_instance = dispatcher.dispatch(function_name)
    except ValueError as e:
        print(f"Error: {e}")
        return

    # Ensure an operation (encrypt/decrypt/sign/verify) is specified
    operation = getattr(args, 'operation', None)
    if not operation:
        print("Error: --operation required")
        return

    operation = operation.lower()

    try:
        # =========================
        # Symmetric Encryption (AES, Blowfish, ChaCha20)
        # =========================
        if function_name in ("aes", "blowfish", "chacha20"):
            # Attempt to resolve the key from args or memory
            key = _parse_key(getattr(args, 'key', None), loaded_key)
            if not key:
                print("Error: --key required")
                return

            # ---------- ENCRYPT ----------
            if operation == "encrypt":
                # Read the data to be encrypted
                input_data = _read_input(args)
                if not input_data:
                    print("Error: --input required")
                    return

                # Route to AES encryption based on selected block mode
                if function_name == "aes":
                    mode = getattr(args, 'mode', defaults.get('aes_mode', 'cbc')).lower()
                    result = getattr(crypto_instance, f"{mode}_encrypt")(input_data, key)

                # Route to Blowfish encryption
                elif function_name == "blowfish":
                    mode = getattr(args, 'mode', defaults.get('blowfish_mode', 'cbc')).lower()
                    result = getattr(crypto_instance, f"{mode}_encrypt")(input_data, key)

                # Route to ChaCha20 (requires a nonce/IV)
                else:  # ChaCha20
                    nonce = _parse_hex_bytes(args.nonce, 16) if getattr(args, 'nonce', None) else None
                    result = crypto_instance.encrypt(input_data, key, nonce)

                # Save or print the ciphertext
                _write_output(result, getattr(args, 'output', None))

            # ---------- DECRYPT ----------
            elif operation == "decrypt":
                # If plaintext flag is set, treat input string as hex-encoded ciphertext
                if args.plaintext:
                    input_data = bytes.fromhex(args.input)
                else:
                    # Otherwise, read from file or direct input
                    input_data = _read_input(args)

                # Route to AES decryption
                if function_name == "aes":
                    mode = getattr(args, 'mode', defaults.get('aes_mode', 'cbc')).lower()
                    result = getattr(crypto_instance, f"{mode}_decrypt")(input_data, key)

                # Route to Blowfish decryption
                elif function_name == "blowfish":
                    mode = getattr(args, 'mode', defaults.get('blowfish_mode', 'cbc')).lower()
                    result = getattr(crypto_instance, f"{mode}_decrypt")(input_data, key)

                # Route to ChaCha20 decryption
                else:  # ChaCha20
                    result = crypto_instance.decrypt(input_data, key)

                # Handle output: decode to UTF-8 if user expected plaintext
                if args.plaintext:
                    _write_output(result.decode('utf-8', errors='replace'),
                                getattr(args, 'output', None), is_text=True)
                else:
                    _write_output(result, getattr(args, 'output', None))

            else:
                print(f"Error: Unsupported operation '{operation}'")

        # =========================
        # Hashing (SHA2, SHA3, Blake2)
        # =========================
        elif function_name in ("sha200", "sha300", "blake2"):
            if operation != "hash":
                print("Error: Only 'hash' operation supported")
                return

            # Read raw data to hash
            input_data = _read_input(args)
            output_format = getattr(args, 'output_format', 'hex')

            # Handle Blake2 (has s and b variants)
            if function_name == "blake2":
                result = (crypto_instance.blake2s_hash_hex(input_data)
                        if args.hash_type == "blake2s"
                        else crypto_instance.blake2b_hash_hex(input_data))
            # Handle SHA families
            else:
                result = crypto_instance.hash_bytes_hex(input_data, args.hash_type)

            # Output the hash string
            _write_output(result, getattr(args, 'output', None), is_text=True)

        # =========================
        # RSA Encryption
        # =========================
        elif function_name == "rsa":
            key_path = args.key
            input_data = _read_input(args)

            if operation == "encrypt":
                # Load public key from path and encrypt
                public_key = crypto_instance.load_public_key(key_path)
                result = crypto_instance.encrypt_bytes(public_key, input_data)
            else:
                # Load private key from path and decrypt
                private_key = crypto_instance.load_private_key(key_path)
                result = crypto_instance.decrypt_bytes(private_key, input_data)

            # Output resulting bytes
            _write_output(result, getattr(args, 'output', None))

        # =========================
        # Digital Signatures (RSA/ECDSA)
        # =========================
        elif function_name in ("rsa_signature", "ecdsa"):
            if operation == "sign":
                # Load private key to create a signature for a file
                private_key = crypto_instance.load_private_key(args.key)
                crypto_instance.sign_file(private_key, args.input, args.output)
                print(f"Signature saved to: {args.output}")

            elif operation == "verify":
                # Load public key to verify an existing signature against a file
                public_key = crypto_instance.load_public_key(args.key)
                crypto_instance.verify_file(public_key, args.input, args.signature)
                print("✓ Signature verified")

    # Catch-all for cryptographic or file system exceptions
    except Exception as e:
        print(f"Error: {e}")