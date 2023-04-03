import ipaddress
import netifaces
import scapy.all as scapy
import threading

lock = threading.Lock()
IPS = list()


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
