# Symmetric
import src.symmetric.aes_cipher
import src.symmetric.blowfish_cipher
import src.symmetric.chacha20_cipher

# Hashing
import src.hashing.blake2_hash
import src.hashing.sha2_hash
import src.hashing.sha3_hash

# Asymmetric
import src.asymmetric.rsa_cipher
import src.asymmetric.ecdsa_signatures
import src.asymmetric.rsa_signatures


def dispatch_crypto_operation(args, loaded_key, defaults):
    function = args.function.lower()

    # ---- Symmetric encryption ----
    if function == "aes":
        src.symmetric.aes_cipher.handle_aes_operations(
            args,
            loaded_key,
            defaults["aes_mode"]
        )

    elif function == "blowfish":
        src.symmetric.blowfish_cipher.handle_blowfish_operations(
            args,
            loaded_key,
            defaults["blowfish_mode"]
        )

    elif function == "chacha20":
        src.symmetric.chacha20_cipher.handle_chacha20_operations(
            args,
            loaded_key
        )

    # ---- Hashing ----
    elif function == "blake2":
        src.hashing.blake2_hash.handle_blake2_hash_operations(args)

    elif function == "sha200":
        src.hashing.sha2_hash.handle_sha200_hash_operations(args)

    elif function == "sha300":
        src.hashing.sha3_hash.handle_sha300_hash_operations(args)

    # ---- Asymmetric crypto ----
    elif function == "rsa":
        src.asymmetric.rsa_cipher.handle_rsa_operations(
            args,
            loaded_key
        )

    elif function == "ecdsa":
        src.asymmetric.ecdsa_signatures.handle_ecdsa_signature_operations(
            args,
            loaded_key
        )

    elif function == "rsa_signature":
        src.asymmetric.rsa_signatures.handle_rsa_signature_operations(
            args,
            loaded_key
        )

    else:
        print(f"Unknown function: {function}")
        print(
            "Available functions: "
            "aes, blowfish, chacha20, "
            "blake2, sha200, sha300, "
            "rsa, ecdsa, rsa_signature"
        )
