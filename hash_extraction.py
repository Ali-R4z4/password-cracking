import hashlib
import re

def identify_hash_algorithm(hash_string):
    
    if '$' in hash_string:  
        salt, hash_value = hash_string.split('$', 1)  

        return f"Salted Hash (Salt: {salt} | Hash: {hash_value} | Algorithm: {identify_hash_algorithm(hash_value)})"
    
    
    if len(hash_string) == 32 and re.match(r'^[a-f0-9]{32}$', hash_string):
        return "MD5"
    elif len(hash_string) == 40 and re.match(r'^[a-f0-9]{40}$', hash_string):
        return "SHA1"
    
    elif len(hash_string) == 64 and re.match(r'^[a-f0-9]{64}$', hash_string):
        return "SHA256"
    
    elif len(hash_string) == 128 and re.match(r'^[a-f0-9]{128}$', hash_string):
        return "SHA512"
    else:
        return "Unknown Algorithm"

def extract_hashes(file_path):
    try:
        with open(file_path, 'r') as file:
            hashes = file.readlines()

        if not hashes:
            print("No hashes found in the file.")
            return

        print("Hashes and Their Algorithms:")
        for hash_str in hashes:
            hash_str = hash_str.strip()
            if hash_str:  
                algorithm = identify_hash_algorithm(hash_str)
                
                if "Unknown Algorithm" not in algorithm:
                    print(f"Hash: {hash_str} | Algorithm: {algorithm}")
    
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.")


