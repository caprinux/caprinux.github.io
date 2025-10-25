---
title: Flare-On 12 — Uncovering Key Functionalities within Obfuscated Binaries using WinDBG 🌀
description: brief writeup for pwn challenges
date: 2025-10-25 00:00:00 +0800
categories: [Writeups]
tags: [rev]
toc: True
img_path: /assets/posts/2025-10-25-flare-on-12-challenge-8/
---

The annual Flare-On has just concluded recently and I did not manage to find enough time to finish the final challenge. Regardless, here is a brief writeup for challenge 8 `FlareAuthentiactor`{:filepath} to showcase how I used **Time Travel Debugging** and **WinDBG** to solve the challenge quickly without much de-obfuscation.

## Overview

We are given a program `FlareAuthenticator.exe`{:filepath} that is using [Qt6](https://doc.qt.io/qt-6/) for the interface.

![program run](flareauthenticator.png)
_program interface_

In this program, you input 25 digits and press Ok/Enter, then it will probably do some checks on the input before printing _"Wrong Password"_ or the flag if the input is correct.

If we open this executable in IDA, we can find that the control flow is heavily obfuscated with some arithmetic calculations and indirect jumps.

```c
// Hidden C++ exception states: #wind=2
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // rax
  _QWORD *v4; // rax
  unsigned int v5; // r8d
  __int64 v6; // r9
  __int64 v7; // rax
  __int64 v8; // rdx
  int result; // eax
  _QWORD v10[6]; // [rsp+280h] [rbp+200h] BYREF
  _QWORD v11[12]; // [rsp+2B0h] [rbp+230h] BYREF
  _QWORD v12[6]; // [rsp+310h] [rbp+290h] BYREF
  _BYTE v13[32]; // [rsp+340h] [rbp+2C0h] BYREF
  _BYTE *v14; // [rsp+360h] [rbp+2E0h]
  _QWORD v15[6]; // [rsp+370h] [rbp+2F0h] BYREF
  _QWORD v16[12]; // [rsp+3A0h] [rbp+320h] BYREF
  _QWORD v17[6]; // [rsp+400h] [rbp+380h] BYREF
  _BYTE v18[48]; // [rsp+430h] [rbp+3B0h] BYREF
  _BYTE v19[24]; // [rsp+460h] [rbp+3E0h] BYREF
  char v20; // [rsp+478h] [rbp+3F8h] BYREF
  _BYTE v21[40]; // [rsp+528h] [rbp+4A8h] BYREF
  int v22; // [rsp+558h] [rbp+4D8h] BYREF
  __int64 v23; // [rsp+578h] [rbp+4F8h]
  __int64 v24; // [rsp+5A0h] [rbp+520h]

  v24 = -2;
  v17[4] = v19;
  v17[0] = v19;
  v17[3] = &v20;
  v17[1] = &v22;
  v17[5] = v18;
  v16[10] = &v22;
  v16[4] = v18;
  v16[0] = v19;
  v16[3] = v21;
  v15[4] = &v22;
  v15[0] = v21;
  v15[3] = v19;
  v15[1] = v16;
  v14 = v18;
  v12[4] = v13;
  v12[0] = v21;
  v12[3] = v18;
  v12[1] = v13;
  v11[10] = v18;
  v11[4] = v17;
  v11[0] = v12;
  v11[3] = v21;
  v10[4] = v15;
  v10[0] = v11;
  v23 = 5077;
  v3 = (_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400B2C20 - 0x61CA5AEA5D8FE855LL))(v10);
  v4 = (_QWORD *)((__int64 (__fastcall *)(_QWORD))((char *)off_1400BE0E8 - 0x4B9400AA2EA9857LL))(*v3);
  *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD))((char *)off_1400A40B8 - 0x484D1B890A23D747LL))(*v4) + 40LL) = 5077;
  v5 = 317585751LL
     * *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400A4F60 + 0x7F9E14D77541BCEBLL))(v12)
                 + 40LL)
     % 0x17340C1AuLL;
  v6 = 2 * (v5 - (v5 | 0xEB65EA04)) - 691284984LL;
  *(_QWORD *)(*(_QWORD *)((__int64 (__fastcall *)(_QWORD *))((char *)off_1400AFA30 - 0x795AF00FA5764B41LL))(v12) + 40LL) = ((v6 | ((v5 | 0xFFFFFFFFEB65EA04uLL) - (v5 & 0xB65EA04))) + (v6 & ((v5 | 0xFFFFFFFFEB65EA04uLL) - (v5 & 0xB65EA04)))) % 0x17340C1A;
  v7 = *(_QWORD *)((char *)off_1400C2FD0 + 0x403154473A52C437LL) | 0xF73D01C0B270C6CLL;
  v8 = 2 * (*(_QWORD *)((char *)off_1400C2FD0 + 0x403154473A52C437LL) - v7) + 0x1EE7A038164E18D8LL;
  __asm { jmp     rax }
  return result;
}
```

This makes static analysis unfeasible without first spending alot of time writing some de-obfuscation scripts to resolve all the indirect jumps and calls.

## The Approach

The key idea is that we only need to understand **how our input is validated**, and we do not necessarily need to fully reverse-engineer and understand the whole program.

This means that we can simply filter out all the noise and directly look for the code that reads and processes our input using a series of hardware breakpoints to trace read/writes to out input via dynamic analysis. 

## Solving the Challenge

Here's our plan:

1. Record a [TTD](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/time-travel-debugging-overview) trace of our program in IDA
2. Identify which Qt6 API is responsibly for receiving user input
3. Set hardware breakpoints to trace where our input is used

### Record a TTD trace of our program

Before running the EXE, we have to set the environment variable according to what was given in `run.bat`.

![set up environment variable](set_envvar.png)
_set up environment variable in windows_

Recording a TTD trace of the executable should be as simple as this

![ttd setup](ttd_setup.png)
_running the exe in windbg_

While WinDBG is recording a trace of the executable, we will key in some random input and hit Enter so we can follow how the program processes this in the trace.

In my case, I inputted `1231231231231231231231231` which returned "wrong".

### Identifying the API that gets input

This took a little trial and error, but we can go through some of the more likely APIs in the EXE imports to find what is returning our input. Ultimately, I identified that `Qt6Widgets!QAbstractButton::text` function would return the input of the user.  

```py
# go to the next call of the function
0:000> g Qt6Widgets!QAbstractButton::text
Time Travel Position: 124D7:269F
Qt6Widgets!QSpinBox::prefix:
00007ffb`ab42b430 4053            push    rbx

# run until return
0:000> pt
Time Travel Position: 124D7:26B5
Qt6Widgets!QSpinBox::prefix+0x25:
00007ffb`ab42b455 c3              ret

# view the return value
0:000> dps rax L1
00000032`712fb3b8  00000209`9bbc9f70 # we observe the return value is a pointer to a pointer

# if we view the pointer, we can see our input `3`
0:000> db poi(rax)
00000209`9bbc9f70  04 00 00 00 00 00 00 00-01 00 00 00 00 00 00 00  ................
00000209`9bbc9f80  33 00 00 00 00 00 00 00-4d 6f 3a ce 00 3a 00 88  3.......Mo:..:..
00000209`9bbc9f90  01 00 00 00 00 00 00 00-40 76 75 93 fb 7f 00 00  ........@vu.....
00000209`9bbc9fa0  c0 79 75 93 fb 7f 00 00-4f 6f 38 ce 00 3b 00 8c  .yu.....Oo8..;..
00000209`9bbc9fb0  01 00 00 00 00 00 00 00-01 00 00 00 00 00 00 00  ................
00000209`9bbc9fc0  37 00 00 00 00 00 00 00-49 6f 3e ce 00 3c 00 88  7.......Io>..<..
00000209`9bbc9fd0  1c 00 00 80 fb 7f 00 00-50 fc 74 ab fb 7f 00 00  ........P.t.....
00000209`9bbc9fe0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

Now let's parse the return value of all calls to this function as shown above.

```py
# delete all breakpoints
0:000> bc *

# set breakpoint at the return of the function
# everytime we hit the breakpoint, we print the unicode value at (*rax)+0x10 and continue
0:000> bp Qt6Widgets!QAbstractButton::text+0x25 "du poi(rax)+0x10; g"

# now we go back to the start of the trace and run
0:000> !tt 0; g
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9dc0  "4"
00000209`9bbc9be0  "5"
00000209`9bbc9c40  "6"
00000209`9bbc9fc0  "7"
00000209`9bbc9d60  "8"
00000209`9bbc9a20  "9"
00000209`9bbd18b0  "DEL"
00000209`9bbd1b50  "0"
00000209`9bbd1850  "OK"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9dc0  "4"
00000209`9bbc9be0  "5"
00000209`9bbc9c40  "6"
00000209`9bbc9fc0  "7"
00000209`9bbc9d60  "8"
00000209`9bbc9a20  "9"
00000209`9bbd18b0  "DEL"
00000209`9bbd1b50  "0"
00000209`9bbd1850  "OK"

00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9b80  "2"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f80  "3"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9bbc9f40  "1"
00000209`9c4ec4c0  "OK"
```

As you can see, apart from the setup stuff at the front, we can see our input being returned from the function _(although its repeated 3 times)_.

### Tracing our input

Another handy feature of WinDbg is the timeline feature at the bottom of the screen. We can use this to view when the function is called in the entire trace of the function.

![img](ttd_timeline.png)
_add new timeline_ 

![img](ttd_timeline_2.png)
_timeline view_

We can double click on any of the green arrows to jump to that point. We note a cluster of green arrows which is likely where it takes in our 25 digit inputs. If you double click on any of the arrow within the cluster, you should see something like this

```
0:000> dx @$cursession.TTD.Calls("Qt6Widgets!QAbstractButton::text+0x25")[0x32]
@$cursession.TTD.Calls("Qt6Widgets!QAbstractButton::text+0x25")[0x32]                
    EventType        : 0x0
    ThreadId         : 0x2d34
    UniqueThreadId   : 0x2
    TimeStart        : 128B5:22EF [Time Travel]
    TimeEnd          : 128B5:22F0 [Time Travel]
    Function         : Qt6Widgets!QSpinBox::prefix+0x25
    FunctionAddress  : 0x7ffbab42b455
    ReturnAddress    : 0x7ff6497361fd
    ReturnValue      : 0x32712fb3b8
    Parameters      
    SystemTimeStart  : Saturday, 25 October 2025 12:38:52.878
    SystemTimeEnd    : Saturday, 25 October 2025 12:38:52.878
```

We can click on **TimeEnd** to jump to the return of the function.

```
# automatically appears when you click on TimeEnd
0:000> dx -s @$create("Debugger.Models.TTD.Position", 75957, 8944).SeekTo()
(6444.2d34): Break instruction exception - code 80000003 (first/second chance not available)
Time Travel Position: 128B5:22F0

# we can see the number that was inputted here
0:000> du poi(rax)+0x10
00000209`9bbc9f80  "3"

# we clear all breakpoints
0:000> bc *

# we set a hardware breakpoint that triggers when the memory reads 1 byte from this address
0:000> ba r1 00000209`9bbc9f80
```

#### convertFromUnicode

As you can see, we now trace our input `3` by setting a hardware breakpoint. If we continue, we should notice that it is 

```
0:000> g
Breakpoint 0 hit
Time Travel Position: 128B5:254B
Qt6Core!QUtf8::convertFromUnicode+0x164:
00007ffb`93d267d4 4983c102        add     r9,2

0:000> t- # step backwards
Time Travel Position: 128B5:254A
Qt6Core!QUtf8::convertFromUnicode+0x160:
00007ffb`93d267d0 410fb709        movzx   ecx,word ptr [r9] ds:00000209`9bbc9f80=0033

0:000> pt # step until return
Time Travel Position: 128B5:2586
Qt6Core!QUtf8::convertFromUnicode+0x269:
00007ffb`93d268d9 c3              ret

0:000> da poi(rax)+0x10 # the ascii version of our input
00000209`9c4eba00  "3"
```

We are able to observe that our input is read in the `convertFromUnicode` function and the converted ascii value is stored in `0x00002099c4eba00`.

#### ByteArray::operator[]

Since this is nothing important yet, we will continue tracing our value by setting another hardware breakpoint and continuing the execution.

```
0:000> bc * # clear breakpoint
0:000> ba r1 00000209`9c4eba00 # set access breakpoint

# continue
0:000> g
Breakpoint 0 hit
Time Travel Position: 128B5:261F
Qt6Core!QByteArrayView::operator[]+0x8:
00007ffb`93bd6f78 c3              ret

# take one step back
# our input is read into rax
0:000> t-
Time Travel Position: 128B5:261E
Qt6Core!QByteArrayView::operator[]+0x4:
00007ffb`93bd6f74 0fb60402        movzx   eax,byte ptr [rdx+rax] ds:00000209`9c4eba00=33 

# we see the value is saved into 0x0000032712fa82f
0:000> t
FlareAuthenticator+0x1665f:
00007ff6`4973665f 8885bf030000    mov     byte ptr [rbp+3BFh],al ss:00000032`712fa82f=00
```

From this, we can observe that the input is read into `eax` register in some array access function and saved into a memory address at `0x00000032712fa82f`. We can continue to trace this value.

#### customHashFunction

```
0:000> t
Time Travel Position: 128B5:2621
FlareAuthenticator+0x16665:
00007ff6`49736665 eb00            jmp     FlareAuthenticator+0x16667 (00007ff6`49736667)

0:000> ba r1 00000032`712fa82f

0:000> g
Breakpoint 0 hit
Time Travel Position: 128B5:264A
FlareAuthenticator+0x1671e:
00007ff6`4973671e 440fbec8        movsx   r9d,al

0:000> t-
Time Travel Position: 128B5:2649
FlareAuthenticator+0x16718:
00007ff6`49736718 8a85bf030000    mov     al,byte ptr [rbp+3BFh] ss:00000032`712fa82f=33

0:000> u rip L20
FlareAuthenticator+0x16718:
00007ff6`49736718 8a85bf030000    mov     al,byte ptr [rbp+3BFh]
00007ff6`4973671e 440fbec8        movsx   r9d,al
00007ff6`49736722 4489c8          mov     eax,r9d
00007ff6`49736725 f7d0            not     eax
00007ff6`49736727 4189d3          mov     r11d,edx
00007ff6`4973672a 41f7d3          not     r11d
00007ff6`4973672d 4109c3          or      r11d,eax
00007ff6`49736730 89d0            mov     eax,edx
00007ff6`49736732 4401c8          add     eax,r9d
00007ff6`49736735 4189c2          mov     r10d,eax
00007ff6`49736738 4589d8          mov     r8d,r11d
00007ff6`4973673b 478d441001      lea     r8d,[r8+r10+1]
00007ff6`49736740 4409ca          or      edx,r9d
00007ff6`49736743 29d0            sub     eax,edx
00007ff6`49736745 89c2            mov     edx,eax
00007ff6`49736747 4409c2          or      edx,r8d
00007ff6`4973674a 4421c0          and     eax,r8d
00007ff6`4973674d 01d0            add     eax,edx
00007ff6`4973674f 6689c2          mov     dx,ax

00007ff6`49736752 488b05e7960a00  mov     rax,qword ptr [FlareAuthenticator+0xbfe40 (00007ff6`497dfe40)]
00007ff6`49736759 49b89165bc305770ed64 mov r8,64ED705730BC6591h
00007ff6`49736763 4c01c0          add     rax,r8
00007ff6`49736766 ffd0            call    rax
```

We see that our input is now put through some complicated and possibly obfuscated arithmetic operations before being passed into some indirect call via the `RDX` register.

```
# step until call

0:000> tc
Time Travel Position: 128B5:265F
FlareAuthenticator+0x16766:
00007ff6`49736766 ffd0            call    rax {FlareAuthenticator+0x81760 (00007ff6`497a1760)}
```

We see that the input is passed into a function at `FlareAuthenticator+0x81760`. If we open this in IDA, it does some complicated mixed boolean arithmetic which is difficult to figure out.

Let's try to analyze this blackbox.

```
# we view the RDX (2nd parameter) passed into every call to this function in the trace

0:000> dx @$cursession.TTD.Calls("FlareAuthenticator+0x81760").Select(c => c.Parameters[1])
@$cursession.TTD.Calls("FlareAuthenticator+0x81760").Select(c => c.Parameters[1])                
    [0x0]            : 0x2000548000001
    [0x1]            : 0x131
    [0x2]            : 0x2000548000002
    [0x3]            : 0x232
    [0x4]            : 0x2000548000003
    [0x5]            : 0x333
    [0x6]            : 0x2000548000004
    [0x7]            : 0x431
    [0x8]            : 0x2000548000005
    [0x9]            : 0x532
    [0xa]            : 0x2000548000006
    [0xb]            : 0x633
    [0xc]            : 0x2000548000007
    [0xd]            : 0x731
    [0xe]            : 0x2000548000008
    [0xf]            : 0x832
    [0x10]           : 0x2000548000009
    [0x11]           : 0x933
    [0x12]           : 0x200054800000a
    [0x13]           : 0xa31
    [0x14]           : 0x200054800000b
    [0x15]           : 0xb32
    [0x16]           : 0x200054800000c
    [0x17]           : 0xc33
    [0x18]           : 0x200054800000d
    [0x19]           : 0xd31
    [0x1a]           : 0x200054800000e
    [0x1b]           : 0xe32
    [0x1c]           : 0x200054800000f
    [0x1d]           : 0xf33
    [0x1e]           : 0x2000548000010
    [0x1f]           : 0x1031
    [0x20]           : 0x2000548000011
    [0x21]           : 0x1132
    [0x22]           : 0x2000548000012
    [0x23]           : 0x1233
    [0x24]           : 0x2000548000013
    [0x25]           : 0x1331
    [0x26]           : 0x2000548000014
    [0x27]           : 0x1432
    [0x28]           : 0x2000548000015
    [0x29]           : 0x1533
    [0x2a]           : 0x2000548000016
    [0x2b]           : 0x1631
    [0x2c]           : 0x2000548000017
    [0x2d]           : 0x1732
    [0x2e]           : 0x2000548000018
    [0x2f]           : 0x1833
    [0x30]           : 0x2000548000019
    [0x31]           : 0x1931
```

**Bingo!** It seems like the input is encoded in 2 byte format `<index_of_input><input_character>`. We can ignore the weird junk values at every other call to the function.

We'll also take a look at the return values of these functions.

```
0:000> dx @$cursession.TTD.Calls("FlareAuthenticator+0x81760").Select(c => c.ReturnValue)
@$cursession.TTD.Calls("FlareAuthenticator+0x81760").Select(c => c.ReturnValue)                
    [0x0]            : 0x279342f
    [0x1]            : 0x6235f14
    [0x2]            : 0xc678db8
    [0x3]            : 0x806e2b
    [0x4]            : 0x87d0f40
    [0x5]            : 0xe616e02
    [0x6]            : 0xcc48d40
    [0x7]            : 0x23e2d01
    [0x8]            : 0xc60a7f3
    [0x9]            : 0xdf3f269
    [0xa]            : 0x716c0d7
    [0xb]            : 0xf88afac
    [0xc]            : 0x32c5f65
    [0xd]            : 0xdd47b84
    [0xe]            : 0xb49d7af
    [0xf]            : 0x8b60aed
    [0x10]           : 0x1b186d3
    [0x11]           : 0x33982f9
    [0x12]           : 0x545d8d5
    [0x13]           : 0x716356b
    [0x14]           : 0x6b2f406
    [0x15]           : 0xb8c31dc
    [0x16]           : 0x9a868c
    [0x17]           : 0xf25fa0c
    [0x18]           : 0x7024229
    [0x19]           : 0xd718955
    [0x1a]           : 0x48bdaae
    [0x1b]           : 0xe89f9b4
    [0x1c]           : 0x5f8f14f
    [0x1d]           : 0x5604724
    [0x1e]           : 0x9d5d059
    [0x1f]           : 0xbee5acd
    [0x20]           : 0xdc0222f
    [0x21]           : 0x973dbdd
    [0x22]           : 0x3d1d2b6
    [0x23]           : 0x938c620
    [0x24]           : 0xd63209a
    [0x25]           : 0xd36638c
    [0x26]           : 0xb3c02cb
    [0x27]           : 0x10d98c6
    [0x28]           : 0x6fb781e
    [0x29]           : 0xaaf62d0
    [0x2a]           : 0xf2d7eee
    [0x2b]           : 0x901f8c8
    [0x2c]           : 0xca922ea
    [0x2d]           : 0xf1fc1ff
    [0x2e]           : 0xadf00df
    [0x2f]           : 0xe60579b
    [0x30]           : 0x4775803
    [0x31]           : 0xc34fa83
```

Our input seems to go through some complicated arithmetic and transformed into 4 byte hashes!

### Tracing the hash

Now we know how our input is parsed into a hash value, we can continue tracing it.

#### Multiplying the Hashes

We first jump to the return of the second call of the function where it returns the hash of `0x131` which is `0x6235f14`.

```
0:000> dx @$cursession.TTD.Calls("FlareAuthenticator+0x81760")[1]
@$cursession.TTD.Calls("FlareAuthenticator+0x81760")[1]                
    EventType        : 0x0
    ThreadId         : 0x2d34
    UniqueThreadId   : 0x2
    TimeStart        : 11DFE:A64 [Time Travel]
    TimeEnd          : 11DFE:1148 [Time Travel]
    Function         : FlareAuthenticator+0x81760
    FunctionAddress  : 0x7ff6497a1760
    ReturnAddress    : 0x7ff649736768
    ReturnValue      : 0x6235f14
    Parameters      
    SystemTimeStart  : Saturday, 25 October 2025 12:38:52.196
    SystemTimeEnd    : Saturday, 25 October 2025 12:38:52.196
0:000> dx -s @$create("Debugger.Models.TTD.Position", 73214, 4424).SeekTo()
(6444.2d34): Break instruction exception - code 80000003 (first/second chance not available)
Time Travel Position: 11DFE:1148
```

We then step through a few instructions to observe what it is doing.

```
0:000> t
Time Travel Position: 11DFE:1148
FlareAuthenticator+0x16768:
00007ff6`49736768 4889c1          mov     rcx,rax

0:000> t
Time Travel Position: 11DFE:1149
FlareAuthenticator+0x1676b:
00007ff6`4973676b 488b85c0030000  mov     rax,qword ptr [rbp+3C0h] ss:00000032`712fa830=000000000279342f

0:000> t
Time Travel Position: 11DFE:114A
FlareAuthenticator+0x16772:
00007ff6`49736772 480fafc1        imul    rax,rcx
0:000> r rcx
rcx=0000000006235f14
0:000> r rax
rax=000000000279342f

0:000> t
Time Travel Position: 11DFE:114B
FlareAuthenticator+0x16776:
00007ff6`49736776 48898548030000  mov     qword ptr [rbp+348h],rax ss:00000032`712fa7b8=00007ffc980ddb6d
```

As we can see, it multiplies two values `0x6235f14` and `0x279342f` together and saves it into `0x00000032712fa7b8`. The two values that it multiplied together are the hashes from the first 2 calls of the `customHashFunction`{:filepath} that is called from our input of the digit `1` in the first input box.

#### Accumulating the result

```
0:000> bc *
0:000> ba r4 00000032`712fa7b8
0:000> g
Breakpoint 0 hit
Time Travel Position: 11DFE:1224
FlareAuthenticator+0x16ad0:
00007ff6`49736ad0 488b5078        mov     rdx,qword ptr [rax+78h] ds:00000032`712ffaf8=0000000000000000
0:000> t-
Time Travel Position: 11DFE:1223
FlareAuthenticator+0x16ac9:
00007ff6`49736ac9 4c8b8d48030000  mov     r9,qword ptr [rbp+348h] ss:00000032`712fa7b8=000f2eb6684284ac

0:000> u rip L20
FlareAuthenticator+0x16ac9:
00007ff6`49736ac9 4c8b8d48030000  mov     r9,qword ptr [rbp+348h]
00007ff6`49736ad0 488b5078        mov     rdx,qword ptr [rax+78h]
00007ff6`49736ad4 4c89c9          mov     rcx,r9
00007ff6`49736ad7 48f7d1          not     rcx
00007ff6`49736ada 4989d0          mov     r8,rdx
00007ff6`49736add 49f7d0          not     r8
00007ff6`49736ae0 4909c8          or      r8,rcx
00007ff6`49736ae3 4889d1          mov     rcx,rdx
00007ff6`49736ae6 4c01c9          add     rcx,r9
00007ff6`49736ae9 4d8d440801      lea     r8,[r8+rcx+1]
00007ff6`49736aee 4c09ca          or      rdx,r9
00007ff6`49736af1 4829d1          sub     rcx,rdx
00007ff6`49736af4 4889ca          mov     rdx,rcx
00007ff6`49736af7 4c09c2          or      rdx,r8
00007ff6`49736afa 4c21c1          and     rcx,r8
00007ff6`49736afd 4801d1          add     rcx,rdx
00007ff6`49736b00 48894878        mov     qword ptr [rax+78h],rcx
```

We note that the multiplied value goes through some set of operations with `[rax+0x78]` and the result is saved back into `[rax+0x78]`

We can trace how this value is transformed over time by setting more hardware breakpoints.

```
0:000> ba r4 00000032`712ffaf8 "r rip; r r9; dp rax+0x78 L1; g"

0:000> g
rip=00007ff649736ad4
r9=000f2eb6684284ac
00000032`712ffaf8  00000000`00000000
rip=00007ff649736b04
r9=000f2eb6684284ac
00000032`712ffaf8  000f2eb6`684284ac
rip=00007ff649736ad4
r9=0006391d7049dde8
00000032`712ffaf8  000f2eb6`684284ac
rip=00007ff649736b04
r9=0006391d7049dde8
00000032`712ffaf8  001567d3`d88c6294
rip=00007ff649736ad4
r9=007a11de14c79e80
00000032`712ffaf8  001567d3`d88c6294
rip=00007ff649736b04
r9=007a11de14c79e80
00000032`712ffaf8  008f79b1`ed540114
rip=00007ff649736ad4
r9=001ca2f34f18cd40
00000032`712ffaf8  008f79b1`ed540114
rip=00007ff649736b04
r9=001ca2f34f18cd40
00000032`712ffaf8  00ac1ca5`3c6cce54
rip=00007ff649736ad4
r9=00acb3ff351198ab
00000032`712ffaf8  00ac1ca5`3c6cce54
rip=00007ff649736b04
r9=00acb3ff351198ab
00000032`712ffaf8  0158d0a4`717e66ff
rip=00007ff649736ad4
r9=006e1e405c548974
00000032`712ffaf8  0158d0a4`717e66ff
rip=00007ff649736b04
r9=006e1e405c548974
00000032`712ffaf8  01c6eee4`cdd2f073
rip=00007ff649736ad4
r9=002be31f155ab714
00000032`712ffaf8  01c6eee4`cdd2f073
rip=00007ff649736b04
r9=002be31f155ab714
00000032`712ffaf8  01f2d203`e32da787
rip=00007ff649736ad4
r9=006255b824338303
00000032`712ffaf8  01f2d203`e32da787
rip=00007ff649736b04
r9=006255b824338303
00000032`712ffaf8  025527bc`07612a8a
rip=00007ff649736ad4
r9=000575f94a1e493b
00000032`712ffaf8  025527bc`07612a8a
rip=00007ff649736b04
r9=000575f94a1e493b
00000032`712ffaf8  025a9db5`517f73c5
rip=00007ff649736ad4
r9=00255e081f63ba07
00000032`712ffaf8  025a9db5`517f73c5
rip=00007ff649736b04
r9=00255e081f63ba07
00000032`712ffaf8  027ffbbd`70e32dcc
rip=00007ff649736ad4
r9=004d5ba7b7c6db28
00000032`712ffaf8  027ffbbd`70e32dcc
rip=00007ff649736b04
r9=004d5ba7b7c6db28
00000032`712ffaf8  02cd5765`28aa08f4
rip=00007ff649736ad4
r9=000924ce94df0690
00000032`712ffaf8  02cd5765`28aa08f4
rip=00007ff649736b04
r9=000924ce94df0690
00000032`712ffaf8  02d67c33`bd890f84
rip=00007ff649736ad4
r9=005e391dd240e89d
00000032`712ffaf8  02d67c33`bd890f84
rip=00007ff649736b04
r9=005e391dd240e89d
00000032`712ffaf8  0334b551`8fc9f821
rip=00007ff649736ad4
r9=0042193cc5270058
00000032`712ffaf8  0334b551`8fc9f821
rip=00007ff649736b04
r9=0042193cc5270058
00000032`712ffaf8  0376ce8e`54f0f879
rip=00007ff649736ad4
r9=00201bb9ea8ed81c
00000032`712ffaf8  0376ce8e`54f0f879
rip=00007ff649736b04
r9=00201bb9ea8ed81c
00000032`712ffaf8  0396ea48`3f7fd095
rip=00007ff649736ad4
r9=0075583891352145
00000032`712ffaf8  0396ea48`3f7fd095
rip=00007ff649736b04
r9=0075583891352145
00000032`712ffaf8  040c4280`d0b4f1da
rip=00007ff649736ad4
r9=0081fa523e38b793
00000032`712ffaf8  040c4280`d0b4f1da
rip=00007ff649736b04
r9=0081fa523e38b793
00000032`712ffaf8  048e3cd3`0eeda96d
rip=00007ff649736ad4
r9=0023394341031ac0
00000032`712ffaf8  048e3cd3`0eeda96d
rip=00007ff649736b04
r9=0023394341031ac0
00000032`712ffaf8  04b17616`4ff0c42d
rip=00007ff649736ad4
r9=00b0e0c55a4d6238
00000032`712ffaf8  04b17616`4ff0c42d
rip=00007ff649736b04
r9=00b0e0c55a4d6238
00000032`712ffaf8  056256db`aa3e2665
rip=00007ff649736ad4
r9=000bd4c34161b102
00000032`712ffaf8  056256db`aa3e2665
rip=00007ff649736b04
r9=000bd4c34161b102
00000032`712ffaf8  056e2b9e`eb9fd767
rip=00007ff649736ad4
r9=004a9b4a38cf1460
00000032`712ffaf8  056e2b9e`eb9fd767
rip=00007ff649736b04
r9=004a9b4a38cf1460
00000032`712ffaf8  05b8c6e9`246eebc7
rip=00007ff649736ad4
r9=0088b763cb6fb9f0
00000032`712ffaf8  05b8c6e9`246eebc7
rip=00007ff649736b04
r9=0088b763cb6fb9f0
00000032`712ffaf8  06417e4c`efdea5b7
rip=00007ff649736ad4
r9=00bf7b1f10223116
00000032`712ffaf8  06417e4c`efdea5b7
rip=00007ff649736b04
r9=00bf7b1f10223116
00000032`712ffaf8  0700f96c`0000d6cd
rip=00007ff649736ad4
r9=009c4964e3f15005
00000032`712ffaf8  0700f96c`0000d6cd
rip=00007ff649736b04
r9=009c4964e3f15005
00000032`712ffaf8  079d42d0`e3f226d2
rip=00007ff649736ad4
r9=003684bcd9a0f789
00000032`712ffaf8  079d42d0`e3f226d2
rip=00007ff649736b04
r9=003684bcd9a0f789
00000032`712ffaf8  07d3c78d`bd931e5b
rip=00007ff649741e2d
r9=aede8e79460a2cb8
```

`r9` stores the multiplied result of the two hash values. It can be observed that the value at `[rax+0x78]` is simply a sum of these values. _Effectively, the complicated looking assembly instructions implements an addition operation._

We can see that the final access of this value is in a different address -- `0x7ff649741e2d`. Let's look at what's there.

```
0:000> bd *
0:000> g- 00007ff649741e2d
Time Travel Position: 14452:1EB9
FlareAuthenticator+0x21e2d:
00007ff6`49741e2d 48b901c4fe79572dc40b mov rcx,0BC42D5779FEC401h
0:000> t-
Time Travel Position: 14452:1EB8
FlareAuthenticator+0x21e29:
00007ff6`49741e29 488b4078        mov     rax,qword ptr [rax+78h] ds:00000032`712ffaf8=07d3c78dbd931e5b

0:000> u rip L20
FlareAuthenticator+0x21e29:
00007ff6`49741e29 488b4078        mov     rax,qword ptr [rax+78h]
00007ff6`49741e2d 48b901c4fe79572dc40b mov rcx,0BC42D5779FEC401h
00007ff6`49741e37 4829c8          sub     rax,rcx
00007ff6`49741e3a 0f94c0          sete    al
```

The value is compared against a hardcoded value `0xBC42D5779FEC401`.

### Piecing the puzzle together

Without any static analysis, we are able to identify the entire checking algorithm for this challenge.

1. Everytime we input a number, two hash values are generated based on the number inputted and the index where it is inputted.
2. These two hash values are multiplied together and added to the final sum.
3. The final sum is compared against a hardcoded value `0xBC42D5779FEC401`.

### Solution

Now, we just need to extract the multiplied hash value of each number at each index of the input.

We can run the program in WinDBG _(without TTD)_, and set this breakpoint `bp FlareAuthenticator+0x16776 "r rax;g"` which will break immediately after the `imul` print out the result and continue.

Then, we repeatedly enter `0` to get the resultant hash of `0` in each index of the input. We should see something like this in WinDbg

```
rax=0019b3240445aa06 # resultant hash of entering 0 in the first digit
rax=006f63394844df78 # resultant hash of entering 0 in the second digit
rax=006df6a4586e71c0 # ...
rax=004ea15fc542c9c0
rax=003ac57453ace252
rax=006402164c9fdb19
rax=00069b5253875b96
rax=009c0d47eac35d2d
rax=00030b9da3c1bfe7
rax=003a03c1d1d02f29
rax=001d392355df459c
rax=0008484a22a795e4
rax=000be331dd3107ad
rax=0019c7c11da4e4a2
rax=001796e76685e997
rax=009bdc1f78073127
rax=00cce53b2df56140
rax=001dc6931c286db2
rax=00139d946e9d6d82
rax=0072a31cfde71ef6
rax=0040a5db3578d586
rax=00c427156a9e2860
rax=00537869c92a42d0
rax=008cc856e432bc50
rax=00020ccd008ad41a
```

Once we extract every hash value, we can finally write the script and use `z3` to solve this system of equations.

```py
from z3 import *

values = """
0019b3240445aa06
006f63394844df78
006df6a4586e71c0
004ea15fc542c9c0
003ac57453ace252
006402164c9fdb19
00069b5253875b96
009c0d47eac35d2d
00030b9da3c1bfe7
003a03c1d1d02f29
001d392355df459c
0008484a22a795e4
000be331dd3107ad
0019c7c11da4e4a2
001796e76685e997
009bdc1f78073127
00cce53b2df56140
001dc6931c286db2
00139d946e9d6d82
0072a31cfde71ef6
0040a5db3578d586
00c427156a9e2860
00537869c92a42d0
008cc856e432bc50
00020ccd008ad41a
... truncated ...
"""

raw_values = [int(i, 16) for i in values.split("\n") if i]
final_matrix = [raw_values[i::25] for i in range(25)]

target = 0xBC42D5779FEC401

s = Solver()
vars = [Int(f"v{i}") for i in range(len(final_matrix))]

for i, lst in enumerate(final_matrix):
    s.add(Or([vars[i] == val for val in lst]))

s.add(Sum(vars) == target)
print(s.check())
m = s.model()
solns = [m[i] for i in vars]

ans = [final_matrix[i].index(solns[i]) for i in range(len(solns))]
print(ans)

# sat
# [4, 4, 9, 8, 2, 9, 1, 3, 1, 4, 8, 9, 1, 2, 1, 0, 5, 2, 1, 4, 4, 9, 2, 9, 6]
```

The final solve script can be found [here](/assets/posts/2025-10-25-flare-on-12-challenge-8/solve.py).

![flag](flag.png)

## Reflections

Most of the time, this is a very contrived way to reverse-engineer, since you lose visibility over much of the functionalities of the program.
 
BUT, it is very effective when you are reverse-engineering with a specific goal in mind. _(i.e. finding how network traffic is used in a malware to identify c2 command tree etc.)_

We are also able to fully solve Challenge 7 in the same way but it is slightly more tedious.

WinDBG is an extremely powerful tool with the most extensive support for Time-Travel Debugging and LinQ queries are also very powerful.

My only complaint is that it gets very repetitive to trace variables with hardware breakpoints after awhile. I've been wanting to write some tool or script to automate this process, but I have not found the motivation to do so. If you have any ideas or if this has inspired you to work on it, do reach out!

Until next time.