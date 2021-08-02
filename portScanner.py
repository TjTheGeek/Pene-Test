import socket
from IPy import IP
from termcolor import colored


# Scans one target at specific port/s i.e. ports 1,7,20,80,100
def scan1(target, portArray, timeout):
    try:
        converted_ip = checkIP(target)[0]
        print('\n' + '[-_0 Scanning Target]' + str(target))
        for portNumber in portArray:
            scanPort(converted_ip, portNumber, timeout)
    except:
        pass


# Scans one target between a range of port i.e. ports 1-5
def scanRange(target, rangeLB, rangeUP, timeout):
    try:
        convertedIp = checkIP(target)[0]
        print('\n' + '[-_0 Scanning Target] ' + str(target))
        for port in range(rangeLB, rangeUP + 1):  # range Lower Bound(LB) and Upper Bound(UP)
            scanPort(convertedIp, port, timeout)
    except:
        pass


# checks if IP addresses are valid, and converts domains to IP addresses
def checkIP(ip):
    try:
        IP(ip)  # THe IP() function returns the same IP that was inputted, if its an IP address.
        return ip, True
    except ValueError:  # If an incorrect type is received i.e. a domain which is a domain.
        try:  # convert the domain to an ip
            return socket.gethostbyname(ip), True
        except socket.gaierror:  # not a domain
            return print('Input error Try Again'), False


# retrieves the banner from target machine when connection is made
def getBanner(s):
    return s.recv(1024)


# main scan function: Makes a connection, and attempts to get the banner
def scanPort(ip_address, port, timeout):
    try:  # try connect
        sock = socket.socket()
        sock.settimeout(int(timeout))
        sock.connect((ip_address, port))
    except:  # if theses an error connecting do nothing
        return print(colored('[-] Port Closed :', 'red') + str(port)), False
    else:
        try:
            banner = getBanner(sock)
            return print(
                colored('[+] Open Port ', 'green') + str(port) + ' : ' + colored(str(banner.decode().strip('\n')),
                                                                                 'yellow')), True, True
        except:  # if not just say the port is open
            return print(colored('[+] Open Port ', 'green') + str(port)), True, False
    finally:  # then close the connection
        sock.close()


if __name__ == "__main__":
    try:
        print('_____PORTSCANNER____')
        pr, tr, tmr = False, False, False
        timer, ports, targets, portsArray = str(), str(), str(), list()

        while not tr:  # Keep repeating the question until user inputs are valid
            targets = input('[+] Enter Target/s To Scan(split multiple targets with): ').strip(' ')

            for ipAddress in targets.split(','):  # for every ip address in the inputted targets target
                if checkIP(ipAddress)[1]:  # check if its a valid ip
                    tr = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(ipAddress + ' not an ip address')
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
                        print('invalid port number specified:' + port + '\nTry Again')
                        break  # ends the iteration once an error is found
            elif '-' in ports:
                for port in ports.split('-'):
                    if port.isdigit():
                        pr = True
                    else:
                        pr = False
                        print('invalid port number specified:' + port + '\nTry Again')
                        break  # break from the for loop
            else:
                if ports.isdigit():
                    pr = True
                else:
                    pr = False
                    print('invalid port number\nTry Again')

        while not tmr:
            timer = input('[+] Enter timeout time in seconds i.e 5 = fives seconds ').strip(' ')
            if timer.isdigit():
                tmr = True
            else:
                print('invalid time number specified:' + port + '\nTry Again')
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
                print(port)
                portsArray.append(int(port.strip(' ')))

            for ipAddress in targets.split(','):
                scan1(ipAddress, portsArray, timer)

    except KeyboardInterrupt:
        print('\n\nbye.')
        exit(0)
