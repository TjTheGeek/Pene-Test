import socket
from os import path
from termcolor import colored

from portScanner import check_ip, get_banner


def noneType(listOfElements):  # removes every appearance of none
    noneElement = True
    while noneElement:
        if None in listOfElements:
            listOfElements.remove(None)
        else:
            noneElement = False
    return listOfElements


resultsOfScan = []


def scan1(target, portsArray, time):
    try:
        converted_ip = check_ip(target)
    except:
        pass
    else:
        print('\n' + '[-_0 Scanning Target] ' + str(target))
        print(portsArray)
        for port in portsArray:
            resultsOfScan.append(scan_port(converted_ip, port, time))

    return noneType(resultsOfScan)


def scan(target, rangeLB=79, rangeUP=84, time=2):
    try:
        converted_ip = check_ip(target)[0]
        print('\n' + '[-_0 Scanning Target] ' + str(target) + "2")
        for port in range(rangeLB, rangeUP):
            resultsOfScan.append(scan_port(converted_ip, port, time))
    except:
        pass

    return noneType(resultsOfScan)


open_ports, banners = [], []


def scan_port(ipaddress, port, timeout):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ipaddress, port))
        # try  decode the banner and add it to the array, if not do nothing
        try:
            banner = get_banner(sock).decode().strip('\n').strip('\r').lower()
        except:
            pass
        else:  # if it get the banner, return the banner and the corresponding port
            return banner, port
        finally:
            sock.close()
    except:
        pass


if __name__ == "__main__":
    try:
        right_choice = [False, False, False, False]
        port_is_range = bool()
        banner_array = []
        port_array = []
        while not right_choice[0]:
            targets = str(input('\n[+] Enter Target/s To Scan(split multiple targets with ,): ')).strip(' ')
            for ip_add in targets.split(','):
                if not check_ip(ip_add)[1]:
                    right_choice[0] = False
                    print(colored(ip_add, on_color='on_red', attrs=['underline']) +
                          colored(' not an ipaddress', color='red'))
                    break
                else:
                    right_choice[0] = True

        while not right_choice[1]:
            ports = input(
                '\n[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ').strip(' ')
            if '-' not in ports:  # if it not a range i.e specific port(s)
                port_is_range = False
                for port in ports.split(','):
                    if port.isdigit():  # check if each port theyve entered is an whole number
                        port_array.append(int(port))  # add it it to the array
                        right_choice[1] = True
                    else:  # if a input isn't a number, ask the the question again
                        right_choice[1] = False
                        print(colored(port, on_color='on_red', attrs=['underline'])
                              + colored(' not a valid port number', color='red'))
                        break
            else:  # if its a range
                port_is_range = True
                for port in ports.split('-'):
                    if port.isdigit():  # check if each ports they've entered is an whole number
                        port_array.append(int(port))
                        right_choice[1] = True
                    else:
                        right_choice[1] = False
                        print(colored(port, color='grey', attrs=['underline']) +
                              colored(' not a valid port number', color='red'))
                        break

        # makes sure the range is in order
        # in case they input higher port first
        port_array.sort()
        while not right_choice[2]:
            timer = input('\n[+] Enter timeout time in seconds ').strip(' ')
            if timer.isdigit():
                right_choice[2] = True
            else:
                right_choice[2] = False

        while not right_choice[3]:
            vul_File = input('\n[+] Input file with banners to search for')
            if not path.isfile(vul_File):
                print(colored('File Not Found !', color='red'))
            else:
                right_choice[3] = True

        for ip_add in targets.split(','):
            if port_is_range:
                banner_port = scan(ip_add, port_array[0], port_array[1], int(timer))
                if None in banner_port:
                    pass
                else:
                    banner_array.append(banner_port[0].lower())
                    port_array.append(banner_port[1])
            else:
                banner_port = scan1(ip_add, port_array, int(timer))
                if None in banner_port:
                    pass
                else:
                    banner_array.append(banner_port[0])
                    port_array.append(banner_port[1])

        if len(banner_array) > 0:
            with open(vul_File, 'r') as file:
                once = count = 0
                for line in file.readlines():
                    if line.lower() in banner_array:
                        once = 1
                        print(
                            colored('[!!] VULNERABLE BANNER: ', 'green') +
                            colored(line, 'cyan', attrs=['bold', 'underline', 'reverse']) +
                            colored('" ON PORT: ', 'green') +
                            colored(str(open_ports[banner_array.index(line.lower())]), color='cyan',
                                    attrs=['bold', 'underline', 'reverse'])
                        )

            view_all = input(colored('Would you like it see all banners found ?', 'yellow')).strip()
            if 'y' in view_all:
                for x in range(len(banner_array)):
                    print(colored('Banner: ', on_color='on_green') +
                          colored(banner_array[x], 'yellow', attrs=['underline', 'bold']) +
                          colored('on Port: ', on_color='on_green') +
                          colored(port_array[x], 'yellow', attrs=['underline', 'bold']))
            else:
                exit(0)
    except KeyboardInterrupt:
        print('bye.')
        exit(0)
