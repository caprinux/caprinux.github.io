import ida_idp
import ida_auto
import idc
import ida_funcs
import ida_hexrays
import ida_bytes
import ida_ua
import re
import keystone
import stitcher # https://github.com/allthingsida/allthingsida/blob/main/ctfs/y0da_flareon10/sticher.py

ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
mxcsr_loc = 0x140097AF0+0x7f0000
base = 0x140097AF0 

CONTEXT_STRUCT = {
0x00000030: "ContextFlags",
0x00000034: "mxcsr", 
0x00000038: "SegCs",
0x0000003A: "SegDs",
0x0000003C: "SegEs",
0x0000003E: "SegFs",
0x00000040: "SegGs",
0x00000042: "SegSs",
0x00000044: "EFlags",
0x00000048: "Dr0",
0x00000050: "Dr1",
0x00000058: "Dr2",
0x00000060: "Dr3",
0x00000068: "Dr6",
0x00000070: "Dr7",
0x00000078: "rax",
0x00000080: "rcx",
0x00000088: "rdx",
0x00000090: "rbx",
0x00000098: "rsp",
0x000000A0: "rbp",
0x000000A8: "rsi",
0x000000B0: "rdi",
0x000000B8: "r8",
0x000000C0: "r9",
0x000000C8: "r10",
0x000000D0: "r11",
0x000000D8: "r12",
0x000000E0: "r13",
0x000000E8: "r14",
0x000000F0: "r15",
0x000000F8: "rip",               
}

class UWOP_CODES:
    UWOP_PUSH_NONVOL     = 0
    UWOP_ALLOC_LARGE     = 1
    UWOP_ALLOC_SMALL     = 2
    UWOP_SET_FPREG       = 3
    UWOP_SAVE_NONVOL     = 4
    UWOP_SAVE_NONVOL_FAR = 5
    UWOP_EPILOG          = 6
    UWOP_SPARE_CODE      = 7
    UWOP_SAVE_XMM128     = 8
    UWOP_SAVE_XMM128_FAR = 9
    UWOP_PUSH_MACHFRAME  = 10

codes = UWOP_CODES()

# in this function, we can secretly fixup encrypted instructions
def disassemble_at(address):
    insn_to_disassemble = ida_ua.insn_t()
    cur = address
    
    while True:
        cur += ida_ua.decode_insn(insn_to_disassemble, cur)

        if insn_to_disassemble.get_canon_mnem() == "call":
            call_loc = insn_to_disassemble.ip

            routine = call_loc + ida_bytes.get_dword(call_loc+1) + 5
            len_decrypted_insn = ida_bytes.get_byte(routine+2) - 0x29

            insn = ida_ua.insn_t()

            ida_ua.decode_insn(insn, routine)
            ida_bytes.patch_bytes(insn.Op1.addr, int(call_loc+5-(base&0xffff)).to_bytes(8, 'little')) # we resolve the dependency of call_loc+5

            ida_ua.decode_insn(insn, routine+14)
            ah = ida_bytes.get_byte(insn.Op2.addr) # we depend on insn.Op2.addr

            ida_ua.decode_insn(insn, routine+20)
            decrypted_insn = (((ah<<8) + insn.Op2.addr) & 0xffffffff).to_bytes(4, 'little') + ida_bytes.get_bytes(routine+0x26, len_decrypted_insn-4)
            ida_bytes.patch_bytes(routine+0x22, decrypted_insn)
            tmp = ida_ua.insn_t()
            ida_ua.create_insn(routine+0x22)
            ida_ua.decode_insn(tmp, routine+0x22)
            
            if decrypted_insn[0] == 0xe9:
                absolute_loc = (int.from_bytes(decrypted_insn[1:5], 'little') + 5 + (routine + 0x22)) & 0xffffffff
                new_rela_offset = (absolute_loc - (5 + call_loc)) & 0xffffffff
                decrypted_insn = decrypted_insn[0:1] + new_rela_offset.to_bytes(4, 'little') + decrypted_insn[5:]
            elif tmp.Op1.type == 0x1 and tmp.Op2.type == 0x2:
                decrypted_insn = bytes(ks.asm(f"lea {ida_idp.get_reg_name(tmp.Op1.reg, 8)}, ds:{hex(tmp.Op2.addr)}", addr=call_loc)[0])
                if len(decrypted_insn) > len_decrypted_insn:
                    call_loc = call_loc - (len(decrypted_insn) - len_decrypted_insn)
                    decrypted_insn = bytes(ks.asm(f"lea {ida_idp.get_reg_name(tmp.Op1.reg, 8)}, ds:{hex(tmp.Op2.addr)}", addr=call_loc)[0])
                elif len(decrypted_insn) < len_decrypted_insn:
                    decrypted_insn += b"\x90" * (len_decrypted_insn - len(decrypted_insn))

            ida_bytes.patch_bytes(call_loc, decrypted_insn)
            print(f"successfully patched {hex(call_loc)}")

            insn_to_disassemble = ida_ua.insn_t()
            ida_ua.create_insn(call_loc)
            cur = call_loc + ida_ua.decode_insn(insn_to_disassemble, call_loc)

        if insn_to_disassemble.get_canon_mnem() == "jmp":
            if insn_to_disassemble.Op1.addr:
                cur = insn_to_disassemble.Op1.addr
            else:
                print("funny jump at", hex(cur))
        yield insn_to_disassemble

halt_address = base
to_be_stitched = [base]

for i in range(33):
    while True:
        # get next exception handler
        unwind_info = halt_address + ida_bytes.get_byte(halt_address+1) + 2
        unwind_info += int((unwind_info & 1) != 0)
        count_of_codes = ida_bytes.get_byte(unwind_info+2)
        handler_offs = ida_bytes.get_dword(unwind_info+2*(count_of_codes+int((count_of_codes&1) != 0))+4)
        exception_handler = base + handler_offs

        unwind_instructions = []

        # unwind stack
        unwind_codes = ida_bytes.get_bytes(unwind_info+4,count_of_codes*2)
        i = 0
        OFFSET = 0
        RSP_DEREF_OFFSET = 0
        REG_USED = False
        RSP_DEREFED = False
        FINAL_REG = None
        while (i < count_of_codes*2):
            match (unwind_codes[i+1] & 0xf):
                case codes.UWOP_PUSH_NONVOL:
                    FINAL_REG = CONTEXT_STRUCT[0x78 + (unwind_codes[i+1] >> 4) * 8]
                    print("UWOP_PUSH_NONVOL")
                    i += 2
                case codes.UWOP_ALLOC_LARGE:
                    if (unwind_codes[i+1] >> 4):
                        if REG_USED or RSP_DEREFED:
                            OFFSET += int.from_bytes(unwind_codes[i+2:i+6], 'little')
                        else:
                            RSP_DEREF_OFFSET += int.from_bytes(unwind_codes[i+2:i+6], 'little')
                        print("UWOP_ALLOC_LARGE")
                        i += 6
                    else:
                        if REG_USED or RSP_DEREFED:
                            OFFSET += int.from_bytes(unwind_codes[i+2:i+4], 'little') * 8
                        else:
                            RSP_DEREF_OFFSET += int.from_bytes(unwind_codes[i+2:i+4], 'little') * 8
                        print("UWOP_ALLOC_LARGE")
                        i += 4
                case codes.UWOP_ALLOC_SMALL:
                    if REG_USED or RSP_DEREFED:
                        OFFSET += ((unwind_codes[i+1] >> 4) * 8) + 8
                    else:
                        RSP_DEREF_OFFSET += ((unwind_codes[i+1] >> 4) * 8) + 8
                    print("UWOP_ALLOC_SMALL")
                    i += 2
                case codes.UWOP_SET_FPREG:
                    REG_USED = CONTEXT_STRUCT[0x78+ (ida_bytes.get_byte(unwind_info+3) & 0xf) * 8]
                    OFFSET -= (ida_bytes.get_byte(unwind_info+3) >> 4) * 16
                    print("UWOP_SET_FPREG")
                    i += 2
                case codes.UWOP_PUSH_MACHFRAME: # RSP is dereferenced!
                    RSP_DEREF_OFFSET += (unwind_codes[i+1] >> 4) * 8
                    RSP_DEREF_OFFSET += 0x18
                    RSP_DEREFED = True
                    print("UWOP_PUSH_MACHFRAME")
                    i += 2
                case _:
                    print(f"count of codes: {count_of_codes}\nunwind codes: {unwind_instructions}\nunwind info: {hex(unwind_info)}")
                    print("@@@@@@@@@@@@@@@@ i donut recognize this opcode")
                    break

        if count_of_codes:
            unwind_instructions = []
            if REG_USED:
                unwind_instructions.append(ks.asm(f"mov {FINAL_REG}, {REG_USED}")[0])
                unwind_instructions.append(ks.asm(f"mov {FINAL_REG}, [{FINAL_REG}+{OFFSET}]")[0])
            elif RSP_DEREFED:
                unwind_instructions.append(ks.asm(f"mov {FINAL_REG}, [rsp+{RSP_DEREF_OFFSET}]")[0])
                unwind_instructions.append(ks.asm(f"mov {FINAL_REG}, [{FINAL_REG}+{OFFSET}]")[0])
            else:
                print(f"count of codes: {count_of_codes}\nunwind codes: {unwind_instructions}\nunwind info: {hex(unwind_info)}")
                print("i do not know how to resolve this...")
                raise Exception

            unwind_instructions = b"".join([bytes(i) for i in unwind_instructions])
            ida_bytes.patch_bytes(halt_address, unwind_instructions)
            ida_ua.create_insn(halt_address)
            halt_address += len(unwind_instructions)
            

        # fixup halt
        insn = b"\xe9"
        insn += (exception_handler - halt_address - 5).to_bytes(4, 'little')
        ida_bytes.patch_bytes(halt_address, insn)
        ida_ua.create_insn(halt_address)


        # fixup exception handler, we disassemble until next 'hlt'
        gen = disassemble_at(exception_handler)
        context_record_register = False
        final_insns = [] # stores the final sets of instructions for each stub
        tainted = [] # stores registers that are written to. this is to know which registers has been tainted since the last stub
        unused_registers = ["r10", "r11", "r8", "rax", "rcx", "rdx", "rdi", "rsi", "rbx", "r12", "r13", "r14", "r15", "rbp", "r9"] # stores all registers that has yet to be used in the stub
        tainted_resolve = {}

        while True:
            x = next(gen)
            raw = generate_disasm_line(x.ip, 1)

            if (x.Op1.type in [0x1, 0x2, 0x3, 0x4]):
                r = ida_idp.get_reg_name(x.Op1.reg, 8)
                if r in unused_registers:
                    unused_registers.remove(r)

            if (x.Op2.type in [0x1, 0x2, 0x3, 0x4]):
                r = ida_idp.get_reg_name(x.Op2.reg, 8)
                if r in unused_registers:
                    unused_registers.remove(r)

            if (x.Op3.type in [0x1, 0x2, 0x3, 0x4]):
                r = ida_idp.get_reg_name(x.Op3.reg, 8)
                if r in unused_registers:
                    unused_registers.remove(r)

            # case 1: mnemonic is ldmxcsr, and its not a nop
            if "ldmxcsr" in raw.lower():
                if CONTEXT_STRUCT[x.Op1.addr] != "mxcsr":
                    new = f"mov ds:{mxcsr_loc}, {CONTEXT_STRUCT[x.Op1.addr]}"
                    r = CONTEXT_STRUCT[x.Op1.addr]
                    if r in unused_registers:
                        unused_registers.remove(r)
                    final_insns.append(new)
                    print(raw, "=>", new)
            
            # case 2: mov rXX, [r9+0x28] <-- we are setting the context record
            elif x.get_canon_mnem() == "mov" and x.Op2.reg == 0x9 and x.Op2.addr == 0x28:
                context_record_register = ida_idp.get_reg_name(x.Op1.reg, 8)
                print(f"context record is stored in {context_record_register}")

            # case 3: we are using our context record register
            elif context_record_register and context_record_register in raw:

                if (context_record_register in ida_idp.get_reg_name(x.Op2.reg, 8) and x.Op2.type == 0x4) or (context_record_register in ida_idp.get_reg_name(x.Op1.reg, 8) and x.Op1.type == 0x4):

                    subj = re.findall(r"\[" + context_record_register + r"\+\w+?h]", raw)[0]
                    offs = int(re.findall(r"\+(\w+?)h", subj)[0], 16)

                    reg_to_use = CONTEXT_STRUCT[offs]
                    r = CONTEXT_STRUCT[offs]
                    if r in unused_registers:
                        unused_registers.remove(r)

                    if reg_to_use in tainted:
                        # if reg_to_use in tainted_resolve:
                        #     reg_to_use = tainted_resolve[reg_to_use]
                        # else:
                        tainted_resolve[reg_to_use] = unused_registers.pop(0)
                        final_insns.insert(0, f"mov {tainted_resolve[reg_to_use]}, {reg_to_use}")
                        reg_to_use = tainted_resolve[reg_to_use]
                        print("TAINTED", hex(x.ip))

                    if reg_to_use == "mxcsr":
                        new = raw.replace(subj, f"ds:{mxcsr_loc}")
                        final_insns.append(new)
                        print(raw, "=>", new)
                    # we have to account for the case where the context register is tainted
                    else:
                        new = raw.replace(subj, reg_to_use)
                        final_insns.append(new)
                        print(raw, "=>", new)
                else:
                    final_insns.append(raw)

                # case 3a: we are modifying our context record register in Op1
                if context_record_register in ida_idp.get_reg_name(x.Op1.reg, 8):
                    context_record_register = False

                if x.Op1.type == 0x1:
                    tainted.append(ida_idp.get_reg_name(x.Op1.reg, 8))

            else:
                if x.Op1.type == 0x1:
                    tainted.append(ida_idp.get_reg_name(x.Op1.reg, 8))

                if raw[:2] == "db":
                    raise Exception
                final_insns.append(raw)
                
            if x.get_canon_mnem() == "hlt":
                halt_address = x.ip
                print("halt at",hex(halt_address))
                ida_ua.create_insn(halt_address)
                break 

        cur = exception_handler
        kill = False
        for insn in final_insns[:-2]:
            if ';' in insn:
                insn = insn.split(";")[0]
            if 'loc_' in insn:
                insn = insn.replace("loc_", "ds:0x")
            if 'unk_' in insn:
                insn = insn.replace("unk_", "ds:0x")
            if 'jmp' in insn:
                kill = True
            i = ks.asm(insn, addr=cur)[0]
            ida_bytes.patch_bytes(cur, bytes(i))
            cur += len(i)

        i = ks.asm(f"jmp {halt_address}", addr=cur)[0]
        ida_bytes.patch_bytes(cur, bytes(i))
        if kill:
            break

    if i != 32:
        stage_addr = int("0x"+re.findall(r"unk_(\w+)", final_insns[-2])[0], 16)
        to_be_stitched.append(stage_addr)

# create stage functions
i = 1
for idx, stage_addr in enumerate(to_be_stitched[:-1]):
    ida_funcs.add_func(stage_addr)
    stitcher.stitch(do_stitch=True, addr=stage_addr)
    ida_auto.auto_wait()
    idc.set_name(stage_addr, f"stage{i}")
    i += 1

# give sane symbol names
xor_table = 0x140094AC0
or_table = 0x1400952C0
addition_table = 0x140095AC0
overflow_table = 0x1400962C0
subtraction_table = 0x140096AC0
underflow_table = 0x1400972C0
tables = [xor_table, or_table, addition_table, overflow_table, subtraction_table, underflow_table]

for i in range(256):
    for j in tables:
        idc.create_qword(j+i*8)
    idc.set_name(xor_table+i*8, f"xor_table_{hex(i)[2:].zfill(2)}")
    idc.set_name(addition_table+i*8, f"addition_table_{hex(i)[2:].zfill(2)}")
    idc.set_name(subtraction_table+i*8, f"subtraction_table_{hex(i)[2:].zfill(2)}")
    idc.set_name(underflow_table+i*8, f"underflow_table_{hex(i)[2:].zfill(2)}")
    idc.set_name(overflow_table+i*8, f"overflow_table_{hex(i)[2:].zfill(2)}")
    idc.set_name(or_table+i*8, f"or_table_{hex(i)[2:].zfill(2)}")

# dump decompilation
for i in range(1, 33):
    with open(rf"C:\Users\user\Desktop\Flare-On 11\9\serpentine\decompilations\stage{i}.txt", "w") as f:
        f.write(str(ida_hexrays.decompile(idc.get_name_ea(0, f"stage{i}"))))