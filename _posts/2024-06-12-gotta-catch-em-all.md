---
layout: post
title:  "Gotta Catch'em All Writeup"
date:   2024-06-12 00:00:00 -0400
categories: tryhackme easy
tags: writeup tryhackme easy CTF
---
## Introduction
This is an easy challenge box on
[TryHackMe](https://tryhackme.com/r/room/anonymousplayground){:target="_blank"}{:rel="noopener noreferrer"}.

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Ports
Let's start with a port scan to see open ports and
services

```bash
rustscan -a VICTIM_IP -- -A -os scan -sC
```
![scan1](/images/catch-em-all/scan1.png)

![scan2](/images/catch-em-all/scan2.png)

We have two open ports
- 22: SSH
- 80: HTTP

### Web Server
> View the homepage source and find credentials
{: .prompt-tip }
Let's visit the web server on port 80 and see what
we can find

![homepage](/images/catch-em-all/homepage.png)

Looks like it's running an Apache webserver. We can
run subdirectory bruteforcing to find hidden files on
the server but our foothold into the server is already
present! Next we should check the source of the homepage

![pokemon src](/images/catch-em-all/pokemon-src.png)

A colon is usualy used to separate a username from a
password. By ignoring the tags we have a potential username
and password!

We can also check what's printed in the console

![web console](/images/catch-em-all/web-console.png)

Cute it's a list of gen 1 pokemon. There isn't anything
else to find here so don't get too distracted

## Initial Foothold
> Use the credentials to `ssh` into the server
{: .prompt-tip }

### Grass Type Flag
> Search `pokemon`'s home directory
{: .prompt-tip }

There are a few folders in `pokemon`'s home directory.
We can check the first level of all of these folders
using `ls` and a wildcard

```bash
ls *
```

![pokemon dirs](/images/catch-em-all/pokemon-dirs.png)

The `Desktop` directory has an interesting zip file,
so let's check its contents

```bash
cd ~/Desktop
unzip P0kEm0n.zip
```

![grass unzip](/images/catch-em-all/grass-unzip.png)

It has the grass type flag! We can read a file's content
with the `cat` command

```bash
cd P0kEm0n
cat grass-type.txt
```

![grass hex](/images/catch-em-all/grass-type-hex.png)

Seems like the flag has been encoded into hex. We can
decode this (and the other flags) with
[cyberchef](https://cyberchef.org/){:target="_blank"}{:rel="noopener noreferrer"}

![grass flag](/images/catch-em-all/grass-type-flag.png)

### Water Type Flag
> Where are the web server files located?
{: .prompt-tip }

Next we should check the web server files. This is usually
located in `/var/www/html` so let's see if there is
anything interesting

![water rot](/images/catch-em-all/water-type-rot.png)

It's the water type flag! It's encoded again so let's
use
[cyberchef](https://cyberchef.org/){:target="_blank"}{:rel="noopener noreferrer"}
with the `ROT 13 Brute Force` option

![water flag](/images/catch-em-all/water-flag.png)

Two flags down, two more to go

## Horizontal Escalation
> Check all the folders in `pokemon`'s home directory
{: .prompt-tip }

When we first checked `pokemon`'s home directory there
was another folder in the `Videos` directory

![pokemon dirs](/images/catch-em-all/pokemon-dirs.png)

Let's traverse this directory to the bottom and read
any files we find

![ash creds](/images/catch-em-all/ash-creds.png)

The colon makes a comeback and it gives us 
credentials for the `ash` user! We can switch users 
with the command

```bash
su ash
```

## Root
> What `sudo` privileges does our new user have?
{: .prompt-tip }

Now that we're a new user we should see what privileges
we have. We can check if we can run any `sudo` commands
by using the `-l` flag

```bash
sudo -l
```

![ash sudo](/images/catch-em-all/ash-sudo.png)

We have full `sudo` permissions! We can escalate to `root`
by running `su` with `sudo`

```bash
sudo su
```

![ash root](/images/catch-em-all/ash-root.png)

We can access everything on the server now so let's
start looking for flags

### Fire Type Flag
> Search the server for a flag with the `find` command
{: .prompt-tip }

Since we don't know where the flag is located we can
use the `find` command which can search for the name
of a file in a directory. By specifying the `/` directory
we can search the entire server and we're looking for
a `txt` file with `fire` in its name

```bash
find / -type f -name "*fire*.txt" -ls 2>/dev/null
```

![find fire](/images/catch-em-all/find-fire.png)

We found it! Let's read it with `cat`

![fire b64](/images/catch-em-all/fire-b64.png)

Now let's decode it with
[cyberchef](https://cyberchef.org/){:target="_blank"}{:rel="noopener noreferrer"}
and the `Base64` option

![fire flag](/images/catch-em-all/fire-flag.png)

### Root Flag
> Check the `/home` directory
{: .prompt-tip }

The root flag is usually in `/root/root.txt` but it
isn't there! We can check the directories of other
users in `/home` but by checking this directory
we immediately find the flag

![root flag](/images/catch-em-all/root-flag.png)

## Conclusion
By investigating the source of the web server's homepage
we were able to find `ssh` credentials to gain a foothold
into the system. Enumerating common directories lead us
to the first two flags. They were in a `zip` file
and the web server's default directory. Further enumeration
gave us the credentials of the `ash` user. By checking
`ash`'s `sudo` permissions we were able to escalate
our privileges to `root`.
Using `find` and investigating the `/home` directory
we were able to obtain the final two flags.
