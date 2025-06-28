import argparse
# my custom imports for the functions.
import src.aes_algorithm_functions
import src.blake2_hash_algorithm
import src.blowfish_algorithms_functions
import src.chacha20_algorithm_fuctions
import src.ecdsa_digital_signature
import src.key_management
import src.ecdsa_digital_signature
import src.rsa_algorithm_fuctions
import src.sha_200_hash_functions
import src.sha_300_hash_functions

parser = argparse.ArgumentParser(description="My personal cryptography ultility consult the readme file for more information.")
parser.add_argument("function")
# arguments for key management
# save key arguements
parser.add_argument("--save-key", type=str, help="function that saves key that is currently loaded to config defined folder.")
parser.add_argument("--new-key-name", type=str, help="specifies the name of the key that is being used.")
parser.add_argument("--key-type", type=str, help="specifies type of key to save.")
# load key arguements
parser.add_argument("--load-key", type=str, help="function that loads key from config defined folder.")
# list key arguements
parser.add_argument("--list-keys", type=str, help="lists keys in the key folder.")
#rename key arguements
parser.add_argument("--old-name", type=str, help="old name of the key to rename.")
parser.add_argument("--new-name", type=str, help="new name of the key to rename.")
# delete key arguements
parser.add_argument("--delete-key", type=str, help="specifies key to delete.")
# key creation
parser.add_argument("--aes-key")
parser.add_argument("--blowfish-key")
parser.add_argument("--chacha20-key")
parser.add_argument("--rsa-private-key")
parser.add_argument("--rsa-public-key")
parser.add_argument("--ecc-private-key")
parser.add_argument("--ecc-public-key")
parser.add_argument("--ecdsa-private-key")
parser.add_argument("--ecdsa-public-key")
parser.add_argument("--bit-size")
parser.add_argument("--nonce")
args = parser.parse_args()