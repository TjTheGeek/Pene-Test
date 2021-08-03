lol=['SSH-2.0-OpenSSH_8.1']
with open('/Users/tijesuolalekan/Documents/Software_Project2/passwords.txt', 'r') as file:
    for line in file.readlines():
        if line.strip() in lol:
            print(lol)