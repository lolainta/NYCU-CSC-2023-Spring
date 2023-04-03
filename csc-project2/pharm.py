#!./.env/bin/python
import os
from utils import get_victims


def main():
    ips = get_victims()
    print("Hello")


if __name__ == '__main__':
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    main()
