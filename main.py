import portScanner
import portScanner_vulscan

def Portscanner_options():
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
                portScanner.scan(ip_add, portsArray[0], portsArray[1], time)
            else:
                portScanner.scan1(ip_add, portsArray, time)
    else:
        # if its not a specific target or targets i.e a range
        if value != 1:
            portScanner.scan(targets.strip(' '), portsArray[0], portsArray[1], time)
        else:
            portScanner.scan1(targets.strip(' '), portsArray, time)

def Vulscan():
    targets = input('[+] Enter Target/s To Scan(split multiple targets with ,): ')
    ports = input('[+] Enter Port/s To Scan(multiple ports with - for range or , for specific ports): ')
    vul_file = input('[+] * Enter Path To The File With Vulnerable Softwares: ')
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
                portScanner_vulscan.scan(ip_add, portsArray[0], portsArray[1], time)
            else:
                portScanner_vulscan.scan1(ip_add, portsArray, time)
    else:
        # if its not a specific target or targets i.e a range
        if value != 1:
            portScanner_vulscan.scan(targets.strip(' '), portsArray[0], portsArray[1], time)
        else:
            portScanner_vulscan.scan1(targets.strip(' '), portsArray, time)
    try:
        with open(vul_file, 'r') as file:
            count = 0
            for banner in portScanner_vulscan.banners:
                file.seek(0)
                for line in file.readlines():
                    if line.strip() in banner:
                        print('[!!] VULNERABLE BANNER: "' + banner + '" ON PORT: ' + str(portScanner_vulscan.open_ports[count]))
                count += 1
    except FileNotFoundError:
        print("File not accessible")
    finally:
        file.close()


if __name__ == '__main__':

    print("[1] PortScanner")
    option = str(input("Pick a program: "))
    if option == "1":
        Portscanner_options()
    elif option == "2":
        Vulscan()
    else:
        print("Not an option")



# See PyCharm help at https://www.jetbrains.com/help/pycharm/
