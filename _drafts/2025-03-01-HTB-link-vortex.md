---
layout: post
title:  "HTB Link Vortex Writeup"
date:   2035-03-01 12:00:00 -0500
categories: hackthebox HTB-easy
tags: writeup hackthebox easy CTF HTB git-dumper subdomains symlinks
---
## Introduction
This is an easy Linux machine on
[HackTheBox](https://tryhackme.com/r/room/anonymousplayground){:target="_blank"}{:rel="noopener noreferrer"}.

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
You can't hack into a server if you don't know
anything about it! We want to gather as much information
about the system as possible.

### Port Scan
Let's start with a port scan to see what services are
accessible

```bash
rustscan -a MACHINE_IP -- -A -oA scan -sC
```

![rustscan1](/images/htb-link-vortex/rustscan1.png)

![rustscan2](/images/htb-link-vortex/rustscan2.png)

We have two open ports:
- 22: SSH
- 80: HTTP

### Website
To visit the website we'll need to add the following to
our `/etc/hosts` file

```
MACHINE_IP linkvortex.htb
```

Checking the homepage, we encounter the following

// homepage

Looks like a blog about understanding computer parts.
Scrolling to the bottom of th epage, we see that it's
run with a service called 
[ghost](https://ghost.org){:target="_blank"}{:rel="noopener noreferrer"}.
Visiting the link, we learn that ghost is a Content Management
Service (CMS) which helps users build websites by managing
web content.

Finding the version of a deployed service can help us find
publically disclosed vulnerabilities or exploits for the
instance we're working with. Thankfully, ghost includes the
running version in the page source code

![ghost-version](/images/htb-link-vortex/ghost-version.png)

### Login
We know that the website is running Ghost CMS, but wher is
the login page? We might be able to find this through
directory bruteforcing, but an easier step is to check `robots.txt`.
This file is used by website indexers to specify directories
they don't want to be publically accessible on a search engine.

`robots.txt` has a few entries

![robots-txt](/images/htb-link-vortex/robots-txt.png)

The most promising is the `/ghost/` directory since that's the
name of the CMS. When we visit this page, we're brought here

![ghost-login](/images/htb-link-vortex/ghost-login.png)

Nice, keep this in mind for later

### Subdomains
In addition to the base domain of `linkvortex.htb`, the website
might host other websites! To check this, we can run a
subdomain bruteforce using `wfuzz`

```bash
wfuzz -c --hc 302 -t 50 -u http://linkvortex.htb -H 'Host: FUZZ.linkvortex.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 20
```

![subdomains](/images/htb-link-vortex/subdomains.png)

Looks like there is another website hosted on `dev.linkvortex.htb`.
Just like with the original website, we'll need to add the
IP mapping to our `/etc/hosts` file

```
MACHINE_IP linkvortex.htb dev.linkvortex.htb
```

If we visit the new site there isn't anything particularly
interesting to find

### Dirsearch
Even if nothing jumps out initially, we should still run
reconnaisance! `robots.txt` doesn't exist on this site, so
let's run a directory bruteforce to find some hidden directories
and files

// dev-dirsearch

A `.git` directory is interesting

![git-directory](/images/htb-link-vortex/git-directory.png)

This folder usually appears when other files are being tracked
by a git repo. Using
[git-dumper](https://github.com/arthaud/git-dumper.git){:target="_blank"}{:rel="noopener noreferrer"}
we can copy the repo from a running website to our local
machine

```bash
git-dumper http://dev.linkvortex.htb/.git dev.linkvortex.htb
```

## Initial Foothold
We've discovered everything which will lead us to a shell onto
the system. We just need to put the pieces together.

### Git Repo
Taking a look at the repo we downloaded from the `dev` subdomain,
we have quite a few files to comb through. Instead of trying
to understand each one, we can check what files have been
modified since the last commit.

Using VSCode, we can open up the folder and check the modified
files in the GUI

![git-password](/images/htb-link-vortex/git-password.png)

If you want to stay in the terminal, we can run the command

```bash
git diff HEAD^:./
```

![git-password2](/images/htb-link-vortex/git-password-2.png)

In either case, we see that the password for a test case
was changed. This is extremely suspicious, so let's logging in
as the `admin` user at `http://linkvortex.htb/ghost`

// login

### Arbitrary File Read
We know the server is running Ghost CMS version 5.58. Looking
for public exploits, we find 
[this git repo](https://github.com/0xyassine/CVE-2023-40028){:target="_blank"}{:rel="noopener noreferrer"}.
It demonstrates an arbitrary file read on Ghost CMS sites
for authenticated users. We've met all the prerequisites, so
it's worth a shot.

Reading the code you execute is always good practice so we
can effectively debug and problems we encounter. Noticing that
the `GHOST_URL` variable points to `127.0.0.1`, we simply need
to change the value to `http://linkvortex.htb` to make our
script work. 

So we can read arbitrary files on the server, but what files
do we want to read? Looking back at the `git` repo we pulled
from the `dev` subdomain, read the `Dockerfile`.

![dockerfile](/images/htb-link-vortex/dockerfile.png)

On startup, the website copies a config file to
`/var/lib/ghost/config.production.json`

![config-read](/images/htb-link-vortex/config-read.png)

Looks like the config file had email credentials!

### User Flag
We have new credentials so let's `SSH` into the box and retrieve
`user.txt`

![user-txt](/images/htb-link-vortex/user-txt.png)

## Privilege Escalation
Enumerating the `sudo` privileges of bob, there is one command
we can run

![sudo](/images/htb-link-vortex/sudo.png)

The shell script contains the following content

![symlink-source](/images/htb-link-vortex/symlink-source.png)

## Conclusion
