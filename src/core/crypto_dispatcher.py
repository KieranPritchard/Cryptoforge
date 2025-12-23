# Symmetric
from src.symmetric.aes_cipher import AES
from src.symmetric.blowfish_cipher import Blowfish
from src.symmetric.chacha20_cipher import ChaCha20

# Hashing
from src.hashing.blake2_hash import Blake2
from src.hashing.sha2_hash import SHA2
from src.hashing.sha3_hash import SHA3

# Asymmetric
from src.asymmetric.rsa_cipher import RSA
from src.asymmetric.ecdsa_signatures import ECDSA
from src.asymmetric.rsa_signatures import RSADigitalSignatures

# File Integrity
from src.hashing.file_integrity import FileIntegrityChecker

import os
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


class CryptoDispatcher:
    def __init__(self, defaults):
        self.defaults = defaults  # Store default encryption modes

        # Algorithm registry
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
        function = function.lower()  # Normalize function name to lowercase

        if function not in self._registry:  # Check if function exists in registry
            raise ValueError(
                f"Unknown function '{function}'. "
                f"Available: {', '.join(self._registry.keys())}"
            )

        return self._registry[function]()  # Return new instance of the requested crypto class


def _parse_key(key_arg, loaded_key):
    """Parse key from argument, loaded_key, or file"""
    if key_arg:  # If key argument provided
        if os.path.isfile(key_arg):  # If it's a file path, read it
            with open(key_arg, "r") as f:
                key_data = f.read().strip()
            try:
                return bytes.fromhex(key_data)  # Try to parse as hex
            except ValueError:
                return key_data.encode()  # Otherwise treat as raw string
        else:  # It's a hex string or raw string
            try:
                return bytes.fromhex(key_arg)  # Try to parse as hex
            except ValueError:
                return key_arg.encode()  # Otherwise treat as raw string
    elif loaded_key:  # Use loaded key if available
        try:
            return bytes.fromhex(loaded_key)  # Try to parse as hex
        except (ValueError, AttributeError):
            return loaded_key.encode() if isinstance(loaded_key, str) else loaded_key
    return None  # No key available


def _parse_hex_bytes(hex_string, byte_length=None):
    """Parse hex string to bytes, optionally validate length"""
    if not hex_string:
        return None
    try:
        data = bytes.fromhex(hex_string)
        if byte_length and len(data) != byte_length:
            raise ValueError(f"Expected {byte_length} bytes, got {len(data)}")
        return data
    except ValueError as e:
        raise ValueError(f"Invalid hex string: {e}")


def _read_input(args):
    """Read input from file or plaintext string"""
    if args.plaintext:  # Treat input as plaintext string
        return args.input.encode('utf-8') if args.input else None
    else:  # Treat input as file path
        if not args.input or not os.path.isfile(args.input):
            raise FileNotFoundError(f"Input file not found: {args.input}")
        with open(args.input, "rb") as f:
            return f.read()


def _write_output(data, output_path, is_text=False):
    """Write output to file or print to console"""
    if output_path:  # Write to file
        mode = "w" if is_text else "wb"
        with open(output_path, mode) as f:
            f.write(data)
        print(f"Output written to: {output_path}")
    else:  # Print to console
        if isinstance(data, bytes):
            print(data.hex())  # Print hex for bytes
        else:
            print(data)  # Print string directly


def dispatch_file_integrity(args, integrity_checker):
    """Handle file integrity operations"""
    if not args.input:  # Validate input file is provided
        print("Error: --input required for file integrity operations")
        return  # Exit if input is missing
    
    if not args.hash_type:  # Validate hash algorithm is specified
        print("Error: --hash-type required for file integrity operations")
        return  # Exit if hash type is missing
    
    # Hash operation (compute hash)
    if not args.expected_hash:  # If no expected hash, compute and display hash
        try:
            file_hash = integrity_checker.hash_file(args.input, args.hash_type)  # Calculate file hash
            if args.output:  # If output file specified, save hash to file
                with open(args.output, "w") as f:
                    f.write(file_hash)
                print(f"Hash saved to {args.output}")
            else:  # Otherwise, print hash to console
                print(f"{args.hash_type.upper()}: {file_hash}")
        except FileNotFoundError as e:
            print(f"Error: {e}")  # Handle file not found error
        except ValueError as e:
            print(f"Error: {e}")  # Handle invalid hash algorithm error
    
    # Verify operation
    else:  # If expected hash provided, verify file integrity
        try:
            is_valid = integrity_checker.verify_file(args.input, args.expected_hash, args.hash_type)  # Verify file hash matches expected
            if is_valid:  # Hash matches - file is valid
                print(f"✓ File integrity verified: {args.input}")
                print(f"  Expected: {args.expected_hash}")
                print(f"  Calculated: {integrity_checker.hash_file(args.input, args.hash_type)}")
            else:  # Hash doesn't match - file may be corrupted
                calculated = integrity_checker.hash_file(args.input, args.hash_type)
                print(f"✗ File integrity check FAILED: {args.input}")
                print(f"  Expected: {args.expected_hash}")
                print(f"  Calculated: {calculated}")
        except FileNotFoundError as e:
            print(f"Error: {e}")  # Handle file not found error
        except ValueError as e:
            print(f"Error: {e}")  # Handle invalid hash algorithm error


def dispatch_crypto_operation(args, loaded_key, defaults):
    """Dispatch cryptographic operations based on function name in args"""
    dispatcher = CryptoDispatcher(defaults)  # Create dispatcher with default modes
    
    # Get the function name from args
    function_name = args.function.lower() if hasattr(args, 'function') and args.function else None  # Extract and normalize function name
    
    if not function_name:  # Validate function name exists
        print("Error: No function specified")
        return  # Exit if no function specified
    
    # Handle file integrity separately
    if function_name in ("file_integrity", "integrity"):  # Special handling for file integrity operations
        integrity_checker = FileIntegrityChecker()  # Create file integrity checker instance
        dispatch_file_integrity(args, integrity_checker)  # Route to file integrity handler
        return  # Exit after handling file integrity
    
    # Get the crypto class instance
    try:
        crypto_instance = dispatcher.dispatch(function_name)  # Get appropriate crypto class instance from registry
    except ValueError as e:  # Handle unknown function error
        print(f"Error: {e}")
        return  # Exit if function not found in registry
    
    # Get operation type
    operation = getattr(args, 'operation', None)
    if not operation:
        print("Error: --operation required")
        return
    
    operation = operation.lower()
    
    try:
        # Handle symmetric ciphers (AES, Blowfish, ChaCha20)
        if function_name in ("aes", "blowfish", "chacha20"):
            key = _parse_key(getattr(args, 'key', None), loaded_key)  # Parse key from args or loaded_key
            if not key:
                print("Error: --key required (or use --load-key first)")
                return
            
            if operation == "encrypt":
                input_data = _read_input(args)  # Read input data
                if not input_data:
                    print("Error: --input required")
                    return
                
                if function_name == "aes":  # AES encryption
                    mode = getattr(args, 'mode', defaults.get('aes_mode', 'cbc')).lower()  # Get mode from args or defaults
                    if mode == "cbc":
                        result = crypto_instance.cbc_encrypt(input_data, key)
                    elif mode == "cfb":
                        result = crypto_instance.cfb_encrypt(input_data, key)
                    elif mode == "ctr":
                        result = crypto_instance.ctr_encrypt(input_data, key)
                    else:
                        print(f"Error: Unsupported AES mode: {mode}")
                        return
                
                elif function_name == "blowfish":  # Blowfish encryption
                    mode = getattr(args, 'mode', defaults.get('blowfish_mode', 'cbc')).lower()
                    if mode == "cbc":
                        result = crypto_instance.cbc_encrypt(input_data, key)
                    elif mode == "cfb":
                        result = crypto_instance.cfb_encrypt(input_data, key)
                    elif mode == "ctr":
                        result = crypto_instance.ctr_encrypt(input_data, key)
                    else:
                        print(f"Error: Unsupported Blowfish mode: {mode}")
                        return
                
                else:  # ChaCha20 encryption
                    nonce = None
                    if getattr(args, 'nonce', None):  # Use provided nonce
                        nonce = _parse_hex_bytes(args.nonce, 16)
                    result = crypto_instance.encrypt(input_data, key, nonce)
                
                _write_output(result, getattr(args, 'output', None))  # Write output
                
            elif operation == "decrypt":
                # For plaintext decryption, input is hex string that needs parsing
                if args.plaintext:  # If plaintext mode, input is hex string
                    try:
                        input_data = bytes.fromhex(args.input) if args.input else None
                    except ValueError:
                        print("Error: Invalid hex string for plaintext decryption")
                        return
                else:  # File mode, read file
                    input_data = _read_input(args)
                if not input_data:
                    print("Error: --input required")
                    return
                
                if function_name == "aes":  # AES decryption
                    mode = getattr(args, 'mode', defaults.get('aes_mode', 'cbc')).lower()
                    if mode == "cbc":
                        result = crypto_instance.cbc_decrypt(input_data, key)
                    elif mode == "cfb":
                        result = crypto_instance.cfb_decrypt(input_data, key)
                    elif mode == "ctr":
                        result = crypto_instance.ctr_decrypt(input_data, key)
                    else:
                        print(f"Error: Unsupported AES mode: {mode}")
                        return
                
                elif function_name == "blowfish":  # Blowfish decryption
                    mode = getattr(args, 'mode', defaults.get('blowfish_mode', 'cbc')).lower()
                    if mode == "cbc":
                        result = crypto_instance.cbc_decrypt(input_data, key)
                    elif mode == "cfb":
                        result = crypto_instance.cfb_decrypt(input_data, key)
                    elif mode == "ctr":
                        result = crypto_instance.ctr_decrypt(input_data, key)
                    else:
                        print(f"Error: Unsupported Blowfish mode: {mode}")
                        return
                
                else:  # ChaCha20 decryption
                    result = crypto_instance.decrypt(input_data, key)
                
                if args.plaintext:  # If plaintext mode, decode to string
                    _write_output(result.decode('utf-8', errors='replace'), getattr(args, 'output', None), is_text=True)
                else:  # Otherwise output as bytes (hex or binary)
                    _write_output(result, getattr(args, 'output', None))
            
            else:
                print(f"Error: Unsupported operation '{operation}' for {function_name}")
        
        # Handle hashing (SHA2, SHA3, Blake2)
        elif function_name in ("sha200", "sha300", "blake2"):
            if operation != "hash":
                print(f"Error: Only 'hash' operation supported for {function_name}")
                return
            
            hash_type = getattr(args, 'hash_type', None)
            if not hash_type:
                print("Error: --hash-type required for hashing operations")
                return
            
            input_data = _read_input(args)  # Read input data
            if not input_data:
                print("Error: --input required")
                return
            
            output_format = getattr(args, 'output_format', 'hex')  # Get output format
            
            if function_name == "sha200":  # SHA2 hashing
                if output_format == "hex":
                    result = crypto_instance.hash_bytes_hex(input_data, hash_type)
                else:
                    result = crypto_instance.hash_bytes(input_data, hash_type)
            
            elif function_name == "sha300":  # SHA3 hashing
                if output_format == "hex":
                    result = crypto_instance.hash_bytes_hex(input_data, hash_type)
                else:
                    result = crypto_instance.hash_bytes(input_data, hash_type)
            
            else:  # Blake2 hashing
                if hash_type == "blake2s":
                    if output_format == "hex":
                        result = crypto_instance.blake2s_hash_hex(input_data)
                    else:
                        result = crypto_instance.blake2s_hash_bytes(input_data)
                elif hash_type == "blake2b":
                    if output_format == "hex":
                        result = crypto_instance.blake2b_hash_hex(input_data)
                    else:
                        result = crypto_instance.blake2b_hash_bytes(input_data)
                else:
                    print(f"Error: Unsupported Blake2 hash type: {hash_type}")
                    return
            
            if output_format == "hex":
                _write_output(result, getattr(args, 'output', None), is_text=True)
            else:
                _write_output(result, getattr(args, 'output', None))
        
        # Handle RSA encryption/decryption
        elif function_name == "rsa":
            key_path = getattr(args, 'key', None)  # Get key file path
            if not key_path:
                print("Error: --key required (PEM file path)")
                return
            
            if operation == "encrypt":
                input_data = _read_input(args)  # Read input data
                if not input_data:
                    print("Error: --input required")
                    return
                
                public_key = crypto_instance.load_public_key(key_path)  # Load public key
                result = crypto_instance.encrypt_bytes(public_key, input_data)  # Encrypt
                _write_output(result, getattr(args, 'output', None))  # Write output
            
            elif operation == "decrypt":
                input_data = _read_input(args)  # Read input data
                if not input_data:
                    print("Error: --input required")
                    return
                
                private_key = crypto_instance.load_private_key(key_path)  # Load private key
                result = crypto_instance.decrypt_bytes(private_key, input_data)  # Decrypt
                _write_output(result, getattr(args, 'output', None))  # Write output
            
            else:
                print(f"Error: Unsupported operation '{operation}' for RSA")
        
        # Handle digital signatures (RSA, ECDSA)
        elif function_name in ("rsa_signature", "ecdsa"):
            key_path = getattr(args, 'key', None)  # Get key file path
            if not key_path:
                print("Error: --key required (PEM file path)")
                return
            
            if operation == "sign":
                input_path = getattr(args, 'input', None)  # Get input file
                if not input_path:
                    print("Error: --input required")
                    return
                
                output_path = getattr(args, 'output', None)  # Get signature output path
                if not output_path:
                    print("Error: --output required for signing")
                    return
                
                private_key = crypto_instance.load_private_key(key_path)  # Load private key
                
                if function_name == "rsa_signature":
                    crypto_instance.sign_file(private_key, input_path, output_path)  # Sign file
                else:  # ECDSA
                    crypto_instance.sign_file(input_path, output_path, private_key)  # Sign file (different parameter order)
                
                print(f"Signature saved to: {output_path}")
            
            elif operation == "verify":
                input_path = getattr(args, 'input', None)  # Get input file
                if not input_path:
                    print("Error: --input required")
                    return
                
                signature_path = getattr(args, 'signature', None)  # Get signature file
                if not signature_path:
                    print("Error: --signature required for verification")
                    return
                
                # Load key (can be public or private - derive public if needed)
                try:
                    public_key = crypto_instance.load_public_key(key_path)  # Try to load as public key
                except ValueError:
                    # If that fails, try loading as private key and derive public
                    private_key = crypto_instance.load_private_key(key_path)
                    public_key = private_key.public_key()
                
                if function_name == "rsa_signature":
                    try:
                        crypto_instance.verify_file(public_key, input_path, signature_path)  # Verify signature
                        print("✓ Signature verified successfully")
                    except InvalidSignature:
                        print("✗ Signature verification failed")
                else:  # ECDSA
                    is_valid = crypto_instance.verify_file(input_path, signature_path, public_key)  # Verify signature
                    if is_valid:
                        print("✓ Signature verified successfully")
                    else:
                        print("✗ Signature verification failed")
            
            else:
                print(f"Error: Unsupported operation '{operation}' for {function_name}")
        
        else:
            print(f"Error: Operation handling not implemented for {function_name}")
    
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except ValueError as e:
        print(f"Error: {e}")
    except InvalidSignature:
        print("Error: Invalid signature")
    except Exception as e:
        print(f"Error: {e}")