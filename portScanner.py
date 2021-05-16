import socket
from IPy import IP


def scan1(target, portArray, timeout):
    try:
        converted_ip = check_ip(target)[0]
    except:
        pass
    else:
        print('\n' + '[-_0 Scanning Target] ' + str(converted_ip))
        print(portArray)
        for portnum in portArray:
            scan_port(converted_ip, portnum, timeout)


def scanRange(target, rangeLB, rangeUP, timeout):
    try:
        converted_ip = check_ip(target)[0]
        print('\n' + '[-_0 Scanning Target] ' + str(target) + "2")
        for port in range(rangeLB, rangeUP + 1):
            scan_port(converted_ip, port, timeout)
    except:
        pass


# check if its an ip
# converts domain to an Ip address
def check_ip(ip):
    try:
        IP(ip)
        return ip, True
    except ValueError:
        try:  # convert the ip
            return socket.gethostbyname(ip), True
        except socket.gaierror:  # incorrect input
            return print('Input error\nTry Again'), False


def get_banner(s):
    return s.recv(1024)


def scan_port(ipaddress, port, timeout):
    try:  # try connect
        sock = socket.socket()
        sock.settimeout(int(timeout))
        sock.connect((ipaddress, port))
        try:
            banner = get_banner(sock)
            print('[+] Open Port ' + str(port) + ' : ' + str(banner.decode().strip('\n')))
        except:  # if not just say the port is open
            print('[+] Open Port ' + str(port))
    except:  # if theses an error connecting do nothing, go to the next
        pass
    finally:  # then close the connection
        sock.close()

if __name__ == "__main__":
    try:
        pr, tr, tmr = False, False, False
        time, ports, targets = str(), str(), str()
        while not tr:  # Keep repeating the question until user inputs are valid
            targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ').strip(' ')

            for ip_add in targets.split(','):  # for every ip address in the inputted targets target
                if check_ip(ip_add.strip(' '))[1]:  # check if its a valid ip
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
                    scanRange(ip_add, portsArray[0], portsArray[1], time)
                else:
                    scan1(ip_add, portsArray, time)
        else:
            print('There is a single target: no "," detected')
            if value != 1:
                print('Range')
                scanRange(targets.strip(' '), portsArray[0], portsArray[1], time)
            else:
                print('Single')
                print(targets, portsArray, time)
                scan1(targets, portsArray, time)
    except KeyboardInterrupt:
        print('\n\nbye.')
