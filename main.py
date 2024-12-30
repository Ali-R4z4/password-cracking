import sys
from crack_password import crack_password
from hash_extraction import extract_hashes
from brute_force_crack import brute_force_crack  

def main():
    while True:  
        print("\nChoose an option:")
        print("1. Crack password using dictionary (crack_password.py)")
        print("2. Extract hash from file (hash_extraction.py)")
        print("3. Crack password using brute force (brute_force_crack.py)")  
        print("4. Exit")  

        choice = input("Enter choice (1/2/3/4): ")

        if choice == '1':  
            try:
                target_hash = input("Enter the hash to crack: ").strip()
                if not target_hash:
                    print("Error: Hash cannot be empty.")
                    continue

                algorithm = input("Enter the hashing algorithm (md5, sha1, sha256, sha512): ").strip().lower()
                if not algorithm:
                    print("Error: Hashing algorithm cannot be empty.")
                    continue

                wordlist_file = "rockyou.txt"  
                cracked_password = crack_password(target_hash, wordlist_file, algorithm)
                
                if cracked_password:
                    print(f"Password cracked: {cracked_password}")
                else:
                    print("Password could not be cracked using the provided dictionary.")
            except Exception as e:
                print(f"An error occurred: {e}")
        
        elif choice == '2':  
            try:
                file_path = input("Enter the path to the file containing the hash strings: ").strip()
                if not file_path:
                    print("Error: File path cannot be empty.")
                    continue

                extract_hashes(file_path)
                print("Hashes extracted successfully.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '3':  
            try:
                target_hash = input("Enter the hash to crack: ").strip()
                if not target_hash:
                    print("Error: Hash cannot be empty.")
                    continue

                algorithm = input("Enter the hashing algorithm (md5, sha1, sha256, sha512): ").strip().lower()
                if not algorithm:
                    print("Error: Hashing algorithm cannot be empty.")
                    continue

                result = brute_force_crack(target_hash, algorithm)
                if result:
                    print(f"Password cracked: {result}")
                else:
                    print("Password could not be cracked using brute force.")
            except Exception as e:
                print(f"An error occurred: {e}")

        elif choice == '4':  
            print("Exiting the program. Goodbye!")
            break  

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
