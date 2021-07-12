---
layout: page
title: Pwn for Fun and Profit
permalink: /lawofpwn/
---

_Pwn for Fun and Profit_ is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge on `The Art of Pwn`.

I wrote this tutorial to provide people with the things I hope I knew / was told when I first started off on my pwn journey.

I hope that you enjoy this tutorial as much as I enjoyed writing it, and that it was useful to you.

<br>

- **Prologue**
  1. [What is Pwn?](/lawofpwn/prologue/whatispwn)

- **The ELF Executable**
  1. [The C Program](/lawofpwn/innerworkings/how_does_c_programming_work)
  2. [Assembly and the Stack](/lawofpwn/innerworkings/how_does_assembly_work)
  3. [The Tables of the Binary](/lawofpwn/innerworkings/pltgot)
  4. [Binary Decompilation](/lawofpwn/innerworkings/decompilation)


- **Securities of a Binary**
  1. [no eXecute (NX)](/lawofpwn/checksec/NX)
  2. [Stack Canary](/lawofpwn/checksec/canary)
  3. [Binary Randomization (ASLR/PIE)](/lawofpwn/checksec/aslr_pie)
  4. [Relocation Read-Only (RELRO)](/lawofpwn/checksec/relro)

- **Breaking The Stack**
  1. [Buffer Overflow](/lawofpwn/stack/bof)
        * [WhiteHacks 2021 - Puddi Puddi](/lawofpwn/stack/bof#whitehacks-2021---puddi-puddi)
        * [dCTF 2021 - Pinch_Me](/lawofpwn/stack/bof#dctf-2021---pinch-me) _(dynamic analysis, little-endian)_
  2. [Return 2 Win](/lawofpwn/stack/ret2win)

- **Return Oriented Programming**
  1. [What is Return Oriented Programming?](/lawofpwn/rop/whatisrop)
  2. [ROP Gadgets](/lawofpwn/rop/ropgadgets)
  3. [Return 2 Libc: The Concept](/lawofpwn/rop/ret2libc1)
  4. [Return 2 Libc: Execution](/lawofpwn/rop/ret2libc2)


<br>

---

<br>

## Additional Resources

* [Good Reads](https://tinyurl.com/infosecgrail)
  * Hacking: The Art of Exploitation 2
  * Practical Binary Analysis
  * The Shellcoders Handbook 2nd Edition
  * Practical Reverse Engineering

* WarGames/CTFs
  * [PicoCTF](https://play.picoctf.org/practice )
  * [Narnia OverTheWire](https://overthewire.org/wargames/narnia/)
  * [Pwnable KR](https://pwnable.kr/play.php )
  * [Pwnable TW](https://pwnable.tw/challenge/)

* Learning Resources
  * [CTF101](https://ctf101.org/)
  * [Nightmare](https://guyinatuxedo.github.io/00-intro/index.html)
  * [Live OverFlow](https://tinyurl.com/liveoverflowtutorial)
  * [Pwn College](https://pwn.college/) (lecture+practices)
  * [RPISEC](https://github.com/RPISEC/MBE) (lecture+practice)
  * [Principles of Pwning (PoP)](https://dystopia.sg/pwning/)
