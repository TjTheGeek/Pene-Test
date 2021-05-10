import socket
from IPy import IP


def scan1(target, ports, time=500):
    try:
        converted_ip = check_ip(target)
    except:
        pass
    else:
        print('\n' + '[-_0 Scanning Target] ' + str(target) + "1")
        print(ports)
        for n in ports:
            scan_port(converted_ip, n, time)


def scan(target, rangeLB=79, rangeUP=84, time=2):
    try:
        converted_ip = check_ip(target)
        print('\n' + '[-_0 Scanning Target] ' + str(target) + "2")
        for port in range(rangeLB, rangeUP):
            scan_port(converted_ip, port, time)
    except:
        pass


# check if the domain or ipaddress is formatted correctly
def check_ip(ip):
    try:
        IP(ip)
        return ip
    except ValueError:
        return "Domain or Ip incorrect: " + str(ip)


def get_banner(s):
    return s.recv(1024)


banners = []
open_ports = []


def scan_port(ipaddress, port, timeout):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ipaddress, port))
        # try  decode the banner and add it to the array, if not do nothing
        try:
            banner = get_banner(sock).decode().strip('\n').strip('\r')
            banners.append(banner)
        except:
            pass
        else:
            open_ports.append(port)
    except:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')
    ports = input('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ')
    time = int(input('[+] Enter timeout time in seconds '))
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
                scan(ip_add, portsArray[0], portsArray[1], time)
            else:
                scan1(ip_add, portsArray, time)
    else:
        # if its not a specific target or targets i.e a range
        if value != 1:
            scan(targets.strip(' '), portsArray[0], portsArray[1], time)
        else:
            scan1(targets.strip(' '), portsArray, time)
