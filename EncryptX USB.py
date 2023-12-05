import os
import sys
import psutil
import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def is_windows():
    return "win32" == sys.platform # Checks if the users OS is Windows

def is_system_drive(drive_letter):
    try:
        partitions = psutil.disk_partitions(all=True) # Gets all of the partitions
        for partition in partitions:
            if partition.device.startswith(drive_letter.upper()): # If the partition is equal to the one inputed
                return os.path.splitdrive(partition.device)[0] == os.getenv("SystemDrive") # Returns if the partition is the system drive
    except Exception as e:
        print(f"Error: {e}")

def is_encrypted_file(file_path):
    return file_path.endswith('.benc') # Checks if the file is already encrypted and returns either true or false

def aes_encrypt_file(input_file_path, key):
    if is_encrypted_file(input_file_path): # If the file is already encrypted it will not encrypt it again
        print(f"File Already Encrypted >> {input_file_path}")
        return None

    iv = os.urandom(16) # Generates the initialization vector

    with open(input_file_path, 'rb') as file: # Stores all the bytes from the file
        plaintext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()) # Initializes the cipher
    encryptor = cipher.encryptor() # Uses the encryptor module 

    ciphertext = encryptor.update(plaintext) + encryptor.finalize() # Encrypts the bytes

    with open(input_file_path, 'wb') as file: # Writes back to the file
        file.write(iv + ciphertext)

    os.rename(input_file_path, (input_file_path + '.benc')) #'Renames the file to inclue .benc

    return input_file_path + '.benc' # Returns the path of the encrypted file

def aes_decrypt_file(input_file_path, key):
    if not is_encrypted_file(input_file_path): # If the file is not encrypted it will not continue
        print(f"File Not Encrypted >> {input_file_path}")
        return None

    with open(input_file_path, 'rb') as file: # Stores all the bytes from the file
        data = file.read()

    iv = data[:16] # Extracts iv from data

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()) # Initializes the cipher
    decryptor = cipher.decryptor() # Uses the decryptor module 

    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize() # Decrypts the bytes

    with open(input_file_path, 'wb') as file: # Writes back to the file
        file.write(decrypted_data)

    os.rename(input_file_path, input_file_path.rstrip('.benc')) # Renames the file to not inclue .benc

    return input_file_path.rstrip('.benc') # Returns the path of the decrypted file

def generate_key(password, iterations=1000): # This function takes in the password and turns it into a key (bytes) usign an algorithm

    salt = b'\xb8_h\xa5W,4\xd9\x87\x0e"\x1b\'kx\xaa'

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )

    key = kdf.derive(password.encode('utf-8'))

    return key

def get_files_in_directory(directory): # This function gets all the files in a certain directory and any sub directories
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_paths.append(file_path)
    return file_paths

if __name__ == "__main__": # Main Code
    if not is_windows():
        print("This tool mainly supports Windows I cannot guarantee it will work on another OS!")
        opt = input("Are you sure you want to continue? y/n >> ") # Makes sure the user wants to continue even if the OS is not Windows
        opt = opt.lower() # Converts the option to a lower case character
        match opt:
            case "y": # If opt == "y"
                pass
            case "n": # If opt == "n"
                print("Aborting...")
                sys.exit()
            case _: # If not equal to any above
                print("Invalid Option! Aborting...")
                sys.exit()

    version = "Ver 1.0"
    os.system("cls")

    password = getpass.getpass("Password (Used To Encrypt/Decrypt) >>  ")  # Gets the password

    os.system(f"title EncryptX USB - {version}") # Changes the title of the command prompt

    key = generate_key(password) # Uses the generate_key function to generate the key from the password
    folder_path = input("Folder/Directory To Encrypt >> ") # The directory the user wants to encrpyt/decrypt

    if "/" in folder_path: # This replaces any / to a \ to prevent an error
        folder_path = folder_path.replace("/", "\\")

    result = is_system_drive(folder_path[0]) # Grabs the first letter of the inputed directory and checks if it is a system drive
    if result: # If result is true
        print(f"{folder_path.upper()} is a system drive.")
        opt = input("Are you sure you want to continue? y/n >> ") # Makes sure the user wants to continue even if the directory is in the system drive
        opt = opt.lower() # Converts the option to a lower case character
        match opt:
            case "y": # If opt == "y"
                pass
            case "n": # If opt == "n"
                print("Aborting...")
                sys.exit()
            case _: # If not equal to any above
                print("Invalid Option! Aborting...")
                sys.exit()

    try: # Attempts to get all the files and stores them in a list
        all_files = get_files_in_directory(folder_path)
        for files in all_files: # If this file is found it will remove it as we dont want it to encrypt its self
            if files == os.path.realpath(__file__):
                all_files.remove(os.path.realpath(__file__))
    except Exception as e:
        print("Error! " + str(e))
        sys.exit()

    os.system("cls")
    print("""
1 >> Encrypt All Files
2 >> Decrypt All Files
    """)

    opt = input("EncryptX >> ")
    os.system("cls")

    done = 0
    total = len(all_files) # Gets the total files found

    match opt:
        case "1":
            for file in all_files:
                encrypted_file_path = aes_encrypt_file(file, key) # Encrypts the file
                done += 1 
                percent = round(((done / total)*100), 1) # Calculates the percent complete
                os.system(f"title EncryptX USB - Ver 1.0 - {percent}%") # Updates the command prompts title
                if encrypted_file_path != None: # If the function does not return none it will print that is has encrypted a file
                    print(f"Encrypted {done}/{total} >> {encrypted_file_path}")
        case "2":
            for file in all_files:
                decrypted_file_path = aes_decrypt_file(file, key) # Decrypts the file
                done += 1
                percent = round(((done / total)*100), 1) # Calculates the percent complete
                os.system(f"title EncryptX USB - Ver 1.0 - {percent}%") # Updates the command prompts title
                if decrypted_file_path != None: # If the function does not return none it will print that is has decrypted a file
                    print(f"Decrypted {done}/{total} >> {decrypted_file_path}")
        case _:
            pass

    input("\nPress Enter To Exit...")