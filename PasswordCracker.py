import hashlib


def crack(type_of_hash, file_path, hash_to_decrypt):
    print("Currently cracking "+hash_to_decrypt+" with "+type_of_hash)
    with open(file_path, 'r') as file:
        for line in file.readlines():
            if type_of_hash.lower() == 'md5':
                hash_object = hashlib.md5(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found MD5 Password: ' + line.strip())
                    exit(0)

            if type_of_hash == 'sha1':
                hash_object = hashlib.sha1(line.strip().encode())
                hashed_word = hash_object.hexdigest()
                if hashed_word == hash_to_decrypt:
                    print('Found SHA1 Password: ' + line.strip())
                    exit(0)

        print('Password Not In File.')
