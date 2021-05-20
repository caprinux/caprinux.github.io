---
layout: post
title: How does C Programming work?
permalink: /lawofpwn/innerworkings/how_does_c_programming_work
---

## New Concepts Covered
---
- C Library
- Analyzing C Code

<br>

## Analysis
---

Consider a simple C program as such. Let's try to figure out what it does.

```c
#include <stdio.h>

int main() {
    char name[10];

    puts("What is your name?");
    scanf("%10s", &name);
    printf("Hello %s", &name);
    return 0;
}
```

`#include <stdio.h>`

On line 1, the program **initializes the C library** which allows you to use functions from the C library such as the `puts`, `printf`, `scanf` that you see in the program.
<br>

`char name[10];`

Inside the main function, a character variables is set, with buffer size 10.

What this means is that, the variable name can only hold 10 characters.

<br>

```c
  puts("What is your name?");
  scanf("%10s", &name);
  printf('Hello %s', &name);
```


`puts()` Simply outputs a message with a newline.

`scanf("%10s", &name)` simply takes an input string of 10 characters and 'saves' it in name variable. Anything after the 10th character is ignored.

`printf('%s', &name)` outputs a variable in string format.  

Now reading through the whole C program, it becomes rather apparent that the logic is something like:

1. It first puts "What is your name?"
2. It then scans an input into name,
3. and prints it out.

![image](/lawofpwn/images/cprogram1.png)

<br>

## Delve deeper

Let's delve a little bit deeper and look at how these functions are being called.

```c
puts("What is your name?");
```

When a program tries to execute a `puts` call, it will first look for `puts()` in the **C Library**, or **LIBC** in short.

When it find `puts`, it will then import the function from the library into the binary.

Hence when this `puts()` is now called, it returns to LIBC and then executes whatever instructions is in the `LIBC puts()`.

Hence,

> The term "libc" is commonly used as a shorthand for the "standard C library", a library of standard functions that can be used by all C programs.

<br>

---

Is this unfamiliar to you? Don't worry, it was for me as well, but it's fine.

Just hold on to the gist of how to read C programs as you explore more C programs and become more familiar with it.

<br>

Food for thought — How does the computer understand these instructions though?
