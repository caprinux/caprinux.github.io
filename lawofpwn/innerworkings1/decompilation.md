---
layout: post
title: From Binary back to Assembly, from Assembly back to C
permalink: /lawofpwn/innerworkings/decompilation
---

## New Concepts Covered
- Disassembly
- Decompilation

---

<br>

## Disassembly
---

When approaching pwn challenges, most of them provide a binary, but do not give you the source code or assembly code. How do you tackle such challenges then?

You will now learn **disassembly**, which allows you to convert a binary back to its assembly code.

There is a convenient linux command line tool called `objdump` which allows us to easily convert our C code back to assembly.

We can run `objdump` with the `-d` flag which signifies **disassemble**, and the **-M intel** to display our instructions in assembly syntax.

_if you do not provide **-M intel** flag, you will see AT&T syntax assembly which is **cancer**_

![image](/lawofpwn/images/objdump.png)
