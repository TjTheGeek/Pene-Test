import socket
from os import path
from termcolor import colored
from portScanner import checkIP, getBanner


def noneType(listOfElements):  # removes every appearance of none
    noneElement = True
    while noneElement:
        if None in listOfElements:
            listOfElements.remove(None)
        else:
            noneElement = False
    return listOfElements


open_ports, banners, resultsOfScan = [], [], []


# Scans one target at specific port/s i.e. ports 1,7,20,80,100
def scan1(target, portsArray, time):
    try:
        converted_ip = checkIP(target)[0]
        print('\n' + '[-_0 Scanning Target] ' + str(target))
        for port in portsArray:
            resultsOfScan.append(scanPort(converted_ip, port, time))
    except:
        pass
    else:
        return noneType(resultsOfScan)


# Scans one target between a range of port i.e. ports 1-5
def scanRange(target, rangeLB, rangeUP, time):
    try:
        converted_ip = checkIP(target)[0]
        print('\n' + '[-_0 Scanning Target] ' + str(target) + "2")
        for port in range(rangeLB, rangeUP):
            resultsOfScan.append(scanPort(converted_ip, port, time))
    except:
        pass
    else:
        return noneType(resultsOfScan)


# main scan function: Makes a connection, and attempts to get the banner
def scanPort(ipaddress, port, timeout):
    try:  # make a connection
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ipaddress, port))
        try:  # try  decode the banner and add it to the array, if not do nothing
            banner = getBanner(sock).decode().strip('\n').strip('\r').lower()
        except:
            pass
        else:  # if it get the banner, return the banner and the corresponding port
            return banner, port
        finally:
            sock.close()
    except:
        pass


if __name__ == "__main__":
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
                print(colored('File Not Found !', color='red'))

        for ip_add in targets.split(','):
            print('[-_0 Scanning ' + ip_add + ']')
            if portIsRange:
                # a list of banners and their ports
                bannerAndPort = scanRange(ip_add, portArray[0], portArray[1], int(timer))
            else:
                bannerAndPort = scan1(ip_add, portArray, int(timer))

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
                                colored(str(portArray[bannerArray.index(line.strip().lower())]), color='cyan',
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