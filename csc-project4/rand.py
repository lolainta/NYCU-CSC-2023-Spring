from pwn import *
import sys
import datetime as dt
from datetime import time
print(sys.argv)
r=remote(sys.argv[1],sys.argv[2])
seed=int(dt.datetime.now().timestamp())
ans=os.popen(f'./rand {seed}').read()
r.sendline(ans.encode())
print(r.recvline().decode().strip())

