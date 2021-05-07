import portScanner


def Portscanner():
    targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')
    ports = input('[+] Enter Port/s To Scan(multiple ports with - for range i.e 79-100): ')
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
                portScanner.scan(ip_add, portsArray[0], portsArray[1], time)
            else:
                portScanner.scan1(ip_add, portsArray, time)
    else:
        # if its not a specific target or targets i.e a range
        if value != 1:
            portScanner.scan(targets.strip(' '), portsArray[0], portsArray[1], time)
        else:
            portScanner.scan1(targets.strip(' '), portsArray, time)

if __name__ == '__main__':
    print("[1] PortScanner")
    option = str(input("Pick a program: "))
    Portscanner()
    if option == "1":
        Portscanner()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
