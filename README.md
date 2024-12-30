# password-cracking
A Python-based project for ethical hacking that includes hash extraction, dictionary attacks, and brute force techniques. The main.py file serves as the central access point to all functionalities. Includes testing files like rocky.txt (wordlist) and hash.txt (hash storage). Designed for educational purposes.


Password Cracking using Hash and Hash Extraction Technique

This project demonstrates ethical hacking techniques for password cracking and hash extraction. It includes Python scripts for hash extraction, dictionary-based attacks, and brute force methods. The project is designed for educational purposes only.

Project Overview

This project includes the following components:

main.py: Central script to access all available functionalities (hash extraction, password cracking, brute force).

hash_extraction.py: Extracts password hashes from files or databases for further analysis.

crack_password.py: Cracks hashes using a wordlist (rocky.txt) and a dictionary attack.

brute_force.py: Attempts to crack passwords through brute force by trying all possible combinations.

Included Files

rocky.txt: A wordlist used for password cracking.

hash.txt: A file that stores extracted hashes for analysis.

How to Use Install Dependencies

Ensure you have Python installed on your system. If required, you can install dependencies using pip:

pip install -r requirements.txt

Running the Project

To use the main functionality, run the main.py script, which gives access to other options (hash extraction, password cracking, brute force):

python main.py

Follow the prompts to either extract hashes or crack passwords.

Understanding the Scripts

hash_extraction.py: Use this script to extract password hashes from a given source.

crack_password.py: This script will attempt to crack password hashes using the wordlist rocky.txt.

brute_force.py: If the dictionary attack fails, use this script to brute force the password.
