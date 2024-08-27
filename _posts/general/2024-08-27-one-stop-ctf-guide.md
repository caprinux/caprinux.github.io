---
title: Your One Stop CTF Resource Guide
description: CTF resource compilation
date: 2024-08-27 17:00:00 +0800
categories: [Resources]
tags: []
---


## What are CTFs? 👾

CTFs are **gamified cybersecurity competitions**, where you solve different challenges for “flags”, or an answer of sorts!

In true _l33t hacker_ terms, this would be sort-of **hacking an application to obtain a password** (aka the "flag" in this context) as proof that you have compromised the system.

They are a **fun way** of developing cybersecurity skill sets, as well as to reinforce and learn more new knowledge on hacking and cybersecurity concepts.

Something important to note is that CTFs are **not a realistic overview of day-to-day work that cybersecurity professionals do**. As mentioned, they are meant to be a fun way of testing your knowledge and skills that you possess.

### CTF Formats

These CTF competitions usually occur in two formats --- **Jeopardy and Attack & Defence**. 

**Jeopardy** provides participants with a series of challenges of different technical domains for participants to solve and submit the flag to the CTF platform for points.

On the contrary, in an **attack-defense CTF format**, each team is provided with a machine that is **running some vulnerable services**. Participants will have to **exploit these vulnerabilities in the other team's machines to gain points, while fixing their own services so that they won't be attacked**.

## Getting Started ⛳

### Setting up a CTF Environment

The most important thing you need before getting started is your very own Linux environment.

The recommended and straightforward setup would be to download a **pre-built Kali Linux VM** [here](https://www.kali.org/get-kali/#kali-virtual-machines), and download VMWare workstation Pro by following the instructions [here](https://www.mikeroysoft.com/post/download-fusion-ws/).

Alternatively, Windows user can also opt to use [Windows Subsystem for Linux (WSL)](https://learn.microsoft.com/en-us/windows/wsl/install). **Ensure that you are using WSL2 and not WSL1.**

### Where to find CTFs?

Usually for local CTFs, you have to look out for advertisement blasts nearer to the dates or learn about it via word of mouth.

Usually you can follow the social media of different cybersecurity groups around Singapore to get more news about happenings in the scene.

For CTFs in general, you can find many international CTFs happening almost every weekend on [CTFtime](https://ctftime.org/).

## Learning Resources 📚

There are various kind of resources shared below.

Some of them are more general while most of them are specific to certain cybersecurity domains.

### Good Overall Training Platforms

If you're just looking for some platform to explore and try out and learn some basic CTF skills, these are some good places to start.

They provide beginner guides and beginner-friendly challenges for you to attempt all year round.

- [PicoCTF](https://play.picoctf.org/)
- [Dreamhack](http://dreamhack.io/) - _this contain training resources and challenges for every category mentioned below <3_

### General cybersecurity knowledge

- [WhiteHacks 2021](https://www.notion.so/Whitehacks-2021-b066154e4adb4567a9201b983decee1d) - _good contextual basics for beginners_
- [LiveOverflow YouTube](https://www.youtube.com/watch?v=8ev9ZX9J45A&ab_channel=LiveOverflow) - _for the visual/auditory learners_

An important fundamental in Cybersecurity is getting used to a Linux Terminal. These following resources familiarizes you with navigating around a linux shell.

- [cmdchallenge](https://cmdchallenge.com/)
- [OverTheWire Bandit](https://overthewire.org/wargames/bandit/)

### Reverse Engineering

> Reverse Engineering is typically the process of taking a program and understanding the functionality of a program by converting it to and then understanding the assembly/code behind a program.
{:.prompt-info}

- [omu.rce](https://omu.rce.so/) - _learn about low-level assembly and linux basics_
- [challenges.re](https://challenges.re/) - _a comprehensive book on reverse engineering with practices_
- [crackmes.one](https://crackmes.one/) - _a series of programs to reverse engineer and crack_

### Binary Exploitation / Pwn

> Binary Exploitation involves taking a program, reverse engineering it to identify vulnerabilities within a program, and finally exploiting it in order to get access to a remote system or modifying the functionality of the program.
{:.prompt-info}

- [Nightmare](https://guyinatuxedo.github.io/00-intro/index.html) - _collection of pwn writeups on different topics. learn by examples!_
- [RopEmporium](https://ropemporium.com/index.html) - _guide and practice on some pwn stuff_
- [Pwn College](https://pwn.college/) - _covers all kind of pwn concepts from beginner to advanced_
- [Modern Binary Exploitation](https://github.com/RPISEC/MBE) - _old but gold resources, from [rpisec](https://rpis.ec/about/)_ 

Abit of a shameless plug, and still empty at the moment but watch this page for a zero to hero pwn guide!

- [my pwndocs](https://pwn.elmo.sg/)


### Forensics

> Forensics is the art of recovering the digital trail left on a computer. There are plently of methods to find data which is seemingly deleted, not stored, or worse, covertly recorded.
{:.prompt-info}

Digital Forensics is typically such a broad topic, and there is no one stop resource to learn about it.

However you can look at [CTF101](https://ctf101.org/forensics/overview/) to see some common topics that you can google and do more research about!

### Cryptography

> Cryptography as a topic is about implementing complex and unbreakable encryption algorithms in order to secure our data online. In CTFs, we look at the math behind these algorithms and find ways to target weaknesses in these algorithms in order to break weak implementations of them. In general, just mathy stuff D:
{:.prompt-info}

- [CryptoHack 🥇](https://cryptohack.org/challenges/) - _one of the most popular and exhaustive crypto platform out there_
- [cryptopals](https://cryptopals.com/)

### Web Exploitation

> Web Exploitation involves finding vulnerabilities in web applications and exploiting it to gain some kind of higher privileges.
{:.prompt-info}

- [PortSwigger 🥇](https://portswigger.net/web-security) - _cover many different classes of web vulnerabilties with practical labs_
- [Lord of the SQLi](https://los.rubiya.kr/) - _deep dive into SQL injection with basic to advanced challenges_
- [Websec.fr](https://websec.fr/) - _another practice platform with web challenges_

### Blockchain Security

> Blockchain involves the auditing of Smart Contracts to find exploitable bugs _(usually more logical bugs unlike pwn)_ that can potentially be used to steal money out of a Smart Contract.
{:.prompt-info}

- [Ethernaut](https://ethernaut.openzeppelin.com/) - _beginner friendly guide to smart contract vulnerabilities with practices_
- [onlypwner.xyz](https://onlypwner.xyz/) - _practice platform with smart contract challenges_ 

## Tools ⚒

In order to solve different kinds of complicated problems, we have to learn to use different set of tools to approach it.

### Pwn / Binary Exploitation / Reverse Engineering

- [IDA Pro](https://hex-rays.com/ida-pro/) / [Binary Ninja](https://binary.ninja/) / [Ghidra](https://ghidra-sre.org/) - _disassembler/decompiler to reverse engineer any executables_
- [WinDBG](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/) / [x64dbg](https://x64dbg.com/) - _useful debugger for windows programs_
- [GDB](https://sourceware.org/gdb/) - _debugger for linux programs_
- [PwnDBG](https://github.com/pwndbg/pwndbg) / [GEF](https://github.com/hugsy/gef) - _extensions for GDB which makes it much more usable_
- [PwnTools](https://github.com/gallopsled/pwntools) - _automation when interacting with programs and remote services_
    - [one\_gadget](https://github.com/david942j/one_gadget) - _find one gadgets in a program_ (installed with Pwntools)
    - [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) - _find ROPgadgets in a program_ (installed with Pwntools)
- [SysInternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) - _trace what a windows program does when ran_
- [JADX](https://github.com/skylot/jadx) / [JEB](https://www.pnfsoftware.com/) - _decompile android APKs to java code_
- [Angr](https://angr.io/) - _symbolic execution_
- [Unicorn](https://www.unicorn-engine.org/) - _binary emulation_

### Web Exploitation

- [Burpsuite](https://portswigger.net/burp) - _suite of tools to manipulate web traffic_
- [curl](https://curl.se/) / [httpie](https://httpie.io/) - _command line tools to directly send a request to a website_
- [requests](https://pypi.org/project/requests/) / [beautifulsoup](https://pypi.org/project/beautifulsoup4/) - _python libraries to automate website interaction_
- [dirsearch](https://github.com/maurosoria/dirsearch) - _brute force website paths_

### Forensics / Miscellaneous

- [CyberChef](https://gchq.github.io/CyberChef/) - _all kind of byte manipulation_
- [AperiSolve](https://aperisolve.fr/) - _one stop solution to image steganograph_
- [binwalk](https://github.com/ReFirmLabs/binwalk) - _identifying/extracting embedded files_
- [FTK Imager](https://www.exterro.com/digital-forensics-software/ftk-imager) / [Autopsy](https://www.autopsy.com/) - _analyze disk/image files_
- [Wireshark](https://www.wireshark.org/) - _analyze network packet captures_
- [Volatility](https://github.com/volatilityfoundation/volatility3) - _used to analyze memdump of an entire computer_
- [Crackstation](https://crackstation.net/) - _look up known hashes_
- [John](https://www.openwall.com/john/) - _used to brute force hashes_

### Cryptography

- [SageMath](https://www.sagemath.org/) - _python with additional cryptography math functions_
