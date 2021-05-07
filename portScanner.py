import socket
from IPy import IP


def scan1(target, ports,time=500):
    converted_ip = check_ip(target)
    print('\n' + '[-_0 Scanning Target] ' + str(target))
    print(ports)
    for n in ports:
        scan_port(converted_ip, n, time)


def scan(target, rangeLB=79, rangeUP=84, time=2):
    converted_ip = check_ip(target)
    print('\n' + '[-_0 Scanning Target] ' + str(target))
    for port in range(rangeLB, rangeUP):
        scan_port(converted_ip, port, time)


def check_ip(ip):
    try:
        IP(ip)
        return ip
    except ValueError:
        return socket.gethostbyname(ip)


def get_banner(s):
    return s.recv(1024)


def scan_port(ipaddress, port,timeout):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((ipaddress, port))
        try:
            banner = get_banner(sock)
            print('[+] Open Port ' + str(port) + ' : ' + str(banner.decode().strip('\n')))
        except:
            print('[+] Open Port ' + str(port))
    except:
        pass


if __name__ == "__main__":
    targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')

    if ',' in targets:

        for ip_add in targets.split(','):
            print (ip_add)
            scan(ip_add.strip(' '))

    else:
        scan(targets)
