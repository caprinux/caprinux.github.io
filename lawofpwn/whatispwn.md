---
layout: post
title: What is Pwn?
permalink: /whatispwn
categories: prologue
---

## Concepts Covered:

Binary Exploitation ... really comes down to **finding a vulnerability** in the program and **exploiting it** to gain control of a shell or modifying the program's functions. ~ ctf101

In pwn challenges, we are often provided with a **vulnerable Linux-ELF binary**, whereby we will have to **find a vulnerability** and exploit it to obtain a flag.

<br>

Concepts/Techniques:

- Understanding C programs
  - The C Library (LIBC)
- Assembly
  - Registers
  - Calling Conventions
- Binary Security
  - No eXecute (NX)
  - Address Space Layout Randomization (ASLR)
  - Stack Canaries/Cookies
  - Relocation Read-Only (RELRO)
- Reverse-Engineering
  - Decompilation
- The Stack
- Buffer
  - Buffer Overflow
- Pwntools
- Global Offset Table (GOT)
- Format String Exploitation
- Return Oriented Programming
  - Ret2win
  - Ret2Libc
  - SIGRop
  - Ret2csu

<br>

## What do I need?

1. The most important tool you need is ``google``. Google is love, google is life.
2. You need a decompiler, use either [Ghidra](https://ghidra-sre.org/) or [IDA Pro](https://hex-rays.com/ida-pro). _i will be using ghidra during my tutorials since it is the free option_
3. You need Linux. I suggest `Windows Subsystem for Linux (WSL)` or a `Linux VM`. I'm personally running Kali Linux on virtual box.
4. You need pwntools and python on your linux. ``pip install pwntools`` should install pwntools. Google if you have any issues!

_more to come!!_
