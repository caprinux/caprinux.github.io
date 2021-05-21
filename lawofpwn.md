---
layout: page
title: Pwn for Fun and Profit
permalink: /lawofpwn/
---

_Pwn for Fun and Profit_ is a progressive tutorial series that aims to be noob-friendly enough for anyone to dive in, and equip them with the skills to come out with substantial knowledge of `The Art of Pwn`.

I wrote this tutorial to provide people with the things I hope I knew / was told when I first started off on my pwn journey.

I hope that you enjoy this tutorial as much as I enjoyed writing it, and that it was useful to you.

<br><br>

### Chapter 1: Prologue
  1. [What is Pwn?](/lawofpwn/prologue/whatispwn)

### Chapter 2: Innerworkings of a binary Part 1
  1. [How does C programming work?](/lawofpwn/innerworkings/how_does_c_programming_work)
  2. [How does Assembly work and introduction to the Stack.](/lawofpwn/innerworkings/how_does_assembly_work)
  3. [The Tables of the Binary (GOT/PLT)](/lawofpwn/innerworkings/pltgot)
  4. [From Binary back to C code, aka Decompilation](/lawofpwn/innerworkings/decompilation)


### Chapter 3: Securities of a binary
  1. [no eXecute (NX)](/lawofpwn/checksec/NX)
  2. [Stack Canary](/lawofpwn/checksec/canary)
  3. [Binary Randomization (ASLR/PIE)](/lawofpwn/checksec/aslr_pie)
  4. [Relocation Read-Only (RELRO)](/lawofpwn/checksec/relro)

### Chapter 4: Exploiting the Stack
  1. [Buffer Overflow](/lawofpwn/stack/bof)
        * [WhiteHacks 2021 - Puddi Puddi](/lawofpwn/stack/bof#whitehacks-2021---puddi-puddi)
        * [dCTF 2021 - Pinch_Me](/lawofpwn/stack/bof#dctf-2021---pinch-me) _(dynamic analysis, little-endian)_
  2. [Return 2 Win](/lawofpwn/stack/ret2win) 


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
