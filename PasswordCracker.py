import hashlib
from os import path


def crack(type_of_hash, file_path, hash_to_decrypt):
    print("Currently cracking " + hash_to_decrypt + " with " + type_of_hash)
    with open(file_path, 'r') as file:
        for line in file.readlines():
            if type_of_hash.lower() == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt.lower():
                    return 1
                    # print('Found MD5 Password: ' + line.strip())
                    # exit(0)

            if type_of_hash == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt.lower():
                    return 2
                    # print('Found Sha1 Password: ' + line.strip())
                    # exit(0)

        print('Password Not In File.')


if __name__ == "__main__":
    try:
        hash_to_decrypt = str(input('[+] Enter hash to decrypt or hashes using ",": '))
        fr, thr = False, False

        while not thr:
            type_of_hash = str(input('Choose a Hash to decrypt:\n [1] SHA-1  [2]MD-5 ')).strip(' ')
            if type_of_hash == "1" or type_of_hash == "2":
                thr = True
                if type_of_hash == "1":
                    type_of_hash = "sha1"
                else:
                    type_of_hash = "md5"
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
