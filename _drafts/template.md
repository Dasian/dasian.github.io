---
layout: post
title:  "HTB Template Writeup"
date:   2025-07-20 12:00:00 -0500
categories: hackthebox HTB-medium
tags: writeup hackthebox medium CTF HTB
---
## Introduction
This is a medium Linux machine on
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

![rustscan1](/images/htb-template/rustscan1.png)

We have two open ports:
- 22: SSH
- 80: HTTP

## Intial Foothold
## Privilege Escalation
## Conclusion
