+++
date = '2026-06-29T06:17:33+07:00'
draft = false
title = 'TryHackMe PWN101 Write-Up (Part 3)'
+++

Hi, it's good to be back again. This is the third part of my PWN101 series in which I will try to explain what I learnt about integer overflow and introduction to format string attack.

## Challenge 4: Integer Overflow
Running the chall instance, we see that it asks for two numbers, and then add them up.

```
$ nc 10.48.154.76 9005
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 105


-------=[ BAD INTEGERS ]=-------
|-< Enter two numbers to add >-|

]>> 1
]>> 2

[*] ADDING 1 + 2
[*] RESULT: 3
```

Nothing suspicious here, so let's try decompiling it.

```c
void main(void)

{
  long in_FS_OFFSET;
  uint a;
  uint b;
  uint c;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts("-------=[ BAD INTEGERS ]=-------");
  puts("|-< Enter two numbers to add >-|\n");
  printf("]>> ");
  __isoc99_scanf(&DAT_0010216f,&a);
  printf("]>> ");
  __isoc99_scanf(&DAT_0010216f,&b);
  c = b + a;
  if (((int)a < 0) || ((int)b < 0)) {
    printf("\n[o.O] Hmmm... that was a Good try!\n",(ulong)a,(ulong)b,(ulong)c);
  }
  else if ((int)c < 0) {
    printf("\n[*] C: %d",(ulong)c);
    puts("\n[*] Popped Shell\n[*] Switching to interactive mode");
    system("/bin/sh");
  }
  else {
    printf("\n[*] ADDING %d + %d",(ulong)a,(ulong)b);
    printf("\n[*] RESULT: %d\n",(ulong)c);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

As we see, there it declares three integers, `a`, `b`, and `c`, and takes our two numbers into `a` and `b`. Then it will pop a shell if all of these three conditions are met: `a >= 0`,`b >= 0`, and `c < 0`.

However, we see a problem here. What two positive numbers such that, when added together, becomes a negative number? It doesn't seem to make sense...

### Numeral Systems
Remember that any kind of data can be represented in merely 1's and 0's in computers? Say, for example, we have a series of numbers which is written in decimal (base-10), like the number `1, 2, 3, 4, 5, .., 10`. In binary (or base-2), these decimal numbers can be denoted like this:

```
0 = 0000
1 = 0001
2 = 0010
3 = 0011
4 = 0100
5 = 0101
6 = 0110
7 = 0111
8 = 1000
9 = 1001
10 = 1010
# note: here, I used only 4 bits (4 binary digits) to represent them.
```

Similarly, we can have a really large integer, like 18391920 and represent it in binary. Since it's a large number, we need more bits to be able to represent it.

```
1000110001010001101110000
```

Or, interestingly, we can even represent _negative_ numbers in binary. How is that possible? Historically, there are a few different ways on how to achieve that, but the most reliable one today is the [two's complement](https://en.wikipedia.org/wiki/Two's_complement) method. In fact, this is what makes signed integers or `int` data type in C able store negative values. The "signed" term itself comes from the possible presence of negative sign, like -3, -90, -231, and so on.

### A little bit on two's complement
Because the challenge we're dealing with has to do with binary representation of numbers, I think it won't harm to learn a little bit about the two's complement method. Besides that I find trying to re-rexplain things in my own words to help me learn better, just like a lot of us.

Before that, I wanted to mention that there's a [great video](https://www.youtube.com/watch?v=lKTsv6iVxV4) made by Computerphile that explains this method in better depth, so it's worth checking out. It also explains the historical reasons of why this method becomes much more reliable than the others.

Okay, let's get into it.

There are three general steps in order to do two's complement. Say we want to represent the decimal number 47, which is -47, in binary. The first thing we need to do is to take the binary representation of 47 (in this case I'll use 32 bits to do it), which is 
```
00000000000000000000000000101111
```
Notice that the leading bit, which is the leftmost bit, will be the sign bit. Why? The reason simply is because we decide it to be, because we want to have a way to tell whether a number is negative or positive. Since it's 0, it means our number is a positive number, which is true.

The next step is to invert all bits, which leaves us with this value:
```
11111111111111111111111111010000
```
Lastly, we need to add 1 to it. Therefore, it becomes

```
11111111111111111111111111010001
```
which is exactly the number `-47` in decimal. We can easily verify this using any binary-to-32-bit signed integer [converter](https://www.binaryconvert.com/convert_signed_int.html) online.

### A possibility for overflow
A data type is limited by the size it can hold. That's why we see a lot of different data types, even for numbers, in C. For example, we can use `int` if we know we're only going to use it to store small integers. But for longer ones, like 17 billion, an `int` is not going to be able to store it; instead, we can use `long long int`.

The reason comes back to the fact that everything in computer is stored in 1's and 0's. If we refer to the C/C++ documentation, an `int` data type is 32-bits in size. That means, it can represent any value (in binary) from
```
00000000000000000000000000000000
```
until
```
11111111111111111111111111111111
```
Now, using these 32 slots of binary digits, with each slot having two possible values (either 1 or 0), how many different numbers can be constructed?

We can use permutation for doing it, which gives us `2^(32)` = 4294967296 unique numbers.

Because `int` is signed, we don't want start from 0 and end with `4294967295`. Rather, we start from the lowest possible negative value, which gives us the range `-2147483648` until `2147483647`, which still has exactly 4294967296 numbers within this range, except now we can store negative numbers.

This is where things get more interesting. Since `int` is limited to this range, what happens if we try to assign an `int` variable with the value _just_ above the maximum value, like `2147483648`?

To better illustrate this, let's actually take the 32-bit signed int representation of the number 2147483647. This will be
```
01111111111111111111111111111111
```
Now, we want to get the binary representation of 2147483648, so let's add 1 to it.
```
01111111111111111111111111111111
00000000000000000000000000000001
--------------------------------- +
...
```
Because 1 + 1 = 2, in binary it will be exactly 10. The rightmost 1 + 1 will cause the digit next to it to carry over 1, and thus creating some sort of "domino" effect, which leaves the leftmost digit to change into 1.

```
1111111111111111111111111111111  --> carry(s)
01111111111111111111111111111111
00000000000000000000000000000001
--------------------------------- +
10000000000000000000000000000000
```
As we see, the resulting number is
```
10000000000000000000000000000000
```
We can ask ourselves, what does this value represent in a 32-bit signed integer? Well... It turns out the answer is exactly 
```
-2147483648
```
which is totally different than what we expected! At first, we thought adding 1 to 2147483647 would result in 2147483648. But it strangely ends up being a very small negative number instead. This behaviour is called wrapping. In other words, it "wraps" back to the lowers possible value in the `int` range.

You can also try adding 2 into 2147483647, which will make two's complement wrap it into -2147483647, and adding 3 into 2147483647 causes it to wrap into -2147483646, and so on.

### Back to the challenge
Now, we know what it takes to make a negative number out of the sum of two positive numbers. We can input 2147483647 as the first number, and 1 as the second number. The server will thus try to add those two numbers together, which will causes an integer overflow, wrapping it into the value -2147483648. Therefore, all three conditions all met, giving us a shell.

```
$ nc 10.48.154.76 9005
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 105


-------=[ BAD INTEGERS ]=-------
|-< Enter two numbers to add >-|

]>> 2147483647
]>> 1

[*] C: -2147483648
[*] Popped Shell
[*] Switching to interactive mode
ls
flag.txt
pwn105
pwn105.c
cat flag.txt
THM{VerY_b4D_1n73G3rsss}
```
Flag: `THM{VerY_b4D_1n73G3rsss}`

## Challenge 6: Format String Attack
This challenge is quite different from the previous, but given the relatively short length I think it's fine to put it under the same post.

T.B.A.
