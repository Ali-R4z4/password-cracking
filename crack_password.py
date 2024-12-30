import hashlib
import os


def get_hash_function(algorithm):
    hash_functions = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
    }
    hash_func = hash_functions.get(algorithm)
    if not hash_func:
        print(f"Error: Unsupported hash algorithm '{algorithm}'. Supported algorithms are: md5, sha1, sha256, sha512.")
    return hash_func


def check_wordlist(wordlist):
    if not os.path.isfile(wordlist):
        print(f"Error: The wordlist file '{wordlist}' does not exist.")
        return False
    return True


def read_wordlist(wordlist):
    if not os.path.isfile(wordlist):
        print(f"Error: The wordlist file '{wordlist}' does not exist.")
        return []
    with open(wordlist, 'r', encoding='latin-1') as file:
        words = [line.strip() for line in file if line.strip()]
        if not words:
            print(f"Error: The wordlist file '{wordlist}' is empty.")
        return words


def crack_password(hashed_password, wordlist, algorithm):
    hash_func = get_hash_function(algorithm)

    if not hash_func:
        return None

   
    words = read_wordlist(wordlist)
    if not words:  
        
        print(f"Error: Wordlist '{wordlist}' is empty or unreadable.")
        return None

    for word in words:
        hashed_word = hash_func(word.encode()).hexdigest()
        if hashed_word == hashed_password:
            return word
    return None


def display_supported_algorithms():
    print("Supported Hash Algorithms:")
    print("1. MD5")
    print("2. SHA1")
    print("3. SHA256")
    print("4. SHA512")



def get_user_input():
    
    
    hashed_password = input("Enter the hashed password to crack: ").strip()
    if not hashed_password:
        print("Error: Hashed password cannot be empty.")
        return None, None, None


    wordlist = "rockyou.txt"  
    
    if not check_wordlist(wordlist):
        return None, None, None



    display_supported_algorithms()
    algorithm_choice = input("Choose the hashing algorithm (md5, sha1, sha256, sha512): ").strip().lower()

    return hashed_password, wordlist, algorithm_choice



def main():
    print("Password Cracking Tool")


    hashed_password, wordlist, algorithm_choice = get_user_input()
    if not hashed_password or not wordlist or not algorithm_choice:
        return

    
    cracked_password = crack_password(hashed_password, wordlist, algorithm_choice)

    if cracked_password:
        print(f"Password found: {cracked_password}")
    else:
        print("Password not found.")

if __name__ == "__main__":
    main()
