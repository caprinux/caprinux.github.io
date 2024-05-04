from pwn import *

e = ELF("./challenge")
worthy_addr = list(e.search(b"worthy\x00"))
print([hex(i) for i in worthy_addr])
