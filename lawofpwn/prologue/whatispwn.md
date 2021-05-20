---
layout: post
title: What is Pwn?
permalink: /lawofpwn/prologue/whatispwn
---


Binary Exploitation ... really comes down to **finding a vulnerability** in the program and **exploiting it** to gain control of a shell or modifying the program's functions. ~ ctf101

In pwn challenges, we are often provided with a **vulnerable Linux-ELF binary**, whereby we will have to **find a vulnerability** and exploit it to obtain a flag.

<br>

## Concepts/Techniques:
---
- Understanding C programs
  - The C Library (LIBC)
- Assembly
  - Registers
  - Calling Conventions
- Binary Security
  - No eXecute (NX)
  - Address Space Layout Randomization (ASLR) & Position Independent Executable (PIE)
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
- Shellcoding
- Return Oriented Programming
  - Ret2win
  - Ret2Libc
  - SIGRop
  - Ret2csu

<br>

## What do I need to know?
---
I won't be teaching how to use Linux so please learn and read it up yourself!

There is a fun Linux BASH based war-game that is CTF-like called [Bandit](https://overthewire.org/wargames/bandit/), check it out!

Other than that, it would be great to know a little bit about `C and Python`, but if you don't, it's fine!

I didn't know any programming languages when I first started pwning either :)
<br>

## What do I need?
---
1. The most important tool you need is ``google``. Google is love, google is life.
2. You need a decompiler, use either [Ghidra](https://ghidra-sre.org/) or [IDA Pro](https://hex-rays.com/ida-pro). _i will be using ghidra during my tutorials since it is the free option_
3. You need Linux. I suggest `Windows Subsystem for Linux (WSL)` or a `Linux VM`. I'm personally running Kali Linux on virtual box.
4. You need pwntools and python on your linux. ``pip install pwntools`` should install pwntools. Google if you have any issues!

<br>

## What are binaries?
---
Binaries, or executables, are **machine code** for a computer to execute. It is usually written in ``C or C++ programming``, which is then compiled with a compiler into machine code such that the computer understands.

#### Ok how do I run these so called 'binaries'?

You need a linux terminal. You can simply run it with `./` if it is in your local directory.  

For example, if my binary is called **binary**, I can run it with `./binary`.

#### How do I compile my C code into a binary?

Linux has a convenient C compiler called the `GNU Compiler Collection (gcc)`.

Simply run ``gcc <path to c file> -o <output binary path>`` on your linux terminal.

---

<div style="text-align: right"> <a href="/lawofpwn/innerworkings/how_does_c_programming_work">How does C programming work?</a> </div>
