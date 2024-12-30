import hashlib
import itertools
import string

# Function to hash a password using the specified algorithm
def hash_password(password, algorithm):
    """
    Hash the given password using the specified algorithm.
    
    Args:
    password (str): The password to hash.
    algorithm (str): The hashing algorithm (e.g., MD5, SHA1, SHA256, SHA512).
    
    Returns:
    str: The hashed password.
    
    Raises:
    ValueError: If an unsupported algorithm is provided.
    """
    algorithm = algorithm.upper()  
    if algorithm == "MD5":
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == "SHA1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == "SHA256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == "SHA512":
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def brute_force_crack(target_hash, algorithm, min_length=4, max_length=4, charset=string.ascii_letters + string.digits + string.punctuation):
    """
    Try brute-forcing a password given a hash, algorithm, and character set.
    
    Args:
    target_hash (str): The hashed password to crack.
    algorithm (str): The hashing algorithm used (e.g., 'MD5', 'SHA256').
    min_length (int): Minimum length of the password to try.
    max_length (int): Maximum length of the password to try.
    charset (str): Character set to use for generating passwords.
    
    Returns:
    str: The cracked password if found, otherwise a failure message.
    """
    algorithm = algorithm.upper()  
    try:
        print(f"Attempting to crack hash: {target_hash} using {algorithm} with password length of {min_length} to {max_length}...")
        
        for length in range(min_length, max_length + 1):
            print(f"Trying passwords of length {length}...")
            total_combinations = len(charset) ** length
            print(f"Total combinations for length {length}: {total_combinations}")
            
            for password_tuple in itertools.product(charset, repeat=length):
                password = ''.join(password_tuple)
                hashed_password = hash_password(password, algorithm)
                if hashed_password == target_hash:
                    return f"Password cracked: {password}"
        
        return "Password not found within the given length limit."
    except ValueError as e:
        return f"An error occurred: {e}"
