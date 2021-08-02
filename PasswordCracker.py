import hashlib
from os import path
from termcolor import colored


def crack(type_of_hash, file_path, hash_to_decrypt):
    print(colored(text="Currently cracking " + hash_to_decrypt + " with " + type_of_hash, color='green'))
    with open(file_path, 'r') as file:
        found = False
        for line in file.readlines():
            if type_of_hash.lower() == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt.lower():
                    return print(colored('Found MD5 Password: ' + line.strip(), 'green')), True

            if type_of_hash == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt.lower():
                    return print(colored('Found Sha1 Password: ' + line.strip(), 'green')), True

            if type_of_hash == 'sha256':
                hash_object = hashlib.sha256(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt.lower():
                    return print(colored('Found Sha-256 Password: ' + line.strip(), 'green')), True

        if not found:
            return print(colored('Password Not In File.', 'red')), False


if __name__ == "__main__":
    try:
        hash_to_decrypt = str(input('[+] Enter hash to decrypt or hashes using ",": '))
        fr, thr = False, False

        while not thr:
            type_of_hash = str(input('Choose a Hash to decrypt:\n [1] SHA-1  [2]MD-5  [3]SHA-256')).strip(' ')
            if type_of_hash == "1" or type_of_hash == "2" or type_of_hash == "3":
                thr = True
                if type_of_hash == "1":
                    type_of_hash = "sha1"
                elif type_of_hash == "2":
                    type_of_hash = "md5"
                else:
                    type_of_hash = "sha256"
            else:
                pass

        while not fr:  # if file is not right
            file_path = str(input('Enter path to the file to bruteforce with: '))
            if not path.isfile(file_path):
                print('File not found\nTry again')
            else:
                fr = True

    except:
        print("0_o Error")
    else:
        for hash in hash_to_decrypt.split(','):
            crack(type_of_hash, file_path, hash)
