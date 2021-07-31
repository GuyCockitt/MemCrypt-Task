# MemCrypt-Task
Task for MemCrypt to verify suitability for employment.

Task Description from MemCrypt:
# 1. Introduction

A core innovation of MemCrypt is the ability to detect cryptographic keys in-memory. We can use this technology to recover data which has been encrypted by malicious software such as Ransomware.
The tasks we have defined here are modelled against scenarios one may face as part of their day-to-day work with MemCrypt. 

# 2. Task Details
The tasks are as follows:

1. Perform analysis against a simulated memory dump file (see `data/memory_dump.bin`) and filter out incremental values (which are considered benign).
In the context of this scenario, benign data found in the memory dump file is any data which is of no interest to us. Incremental values are just one example of such benign data found in-memory.
Any remaining data in the memory dump is deemed to be candidate cryptographic keys and IVs (values which may be used to decrypt encrypted data). There will be a _number_ of 16-byte candidate values found if the analysis and filtering is done correctly.

2. Once candidate values are found, test each candidate cryptographic value and determine the correct set which will allow one to unlock an encrypted file.
An encrypted file has been provided (see `data/encrypted_file`) to test the cryptographic values recovered during memory analysis.


# 2. Setup

To run `memcrypt_analysis.py`, please ensure Python 3.x is installed and the requirements defined in `requirements.txt` are met. No additional configuration should be necessary.
Please see comments provided in the script for instructions on which functions need completing. One may also choose to implement the entire solution in a different programming language if they wish to do so.

# 3. A Note on Candidate Keys and IVs

The candidate values in this scenario relate specifically to cryptographic keys and initialisation vectors (IVs) used by the **AES-128 CBC algorithm**.
In short, in order to encrypt or decrypt using AES-128 CBC mode, we require a 16-byte (128 bit) cryptographic key and a 16-byte IV (thus the reason we operate at 16-byte offset against the memory dump in this scenario).
The same key and IV may be used for both encryption and decryption. Only one set of cryptographic key and IV will allow you to successfully decrypt the encrypted file in this task.

# 4. Output

Once the task is complete, please upload your solution to a public GitHub repository which is accessible to MemCrypt.
