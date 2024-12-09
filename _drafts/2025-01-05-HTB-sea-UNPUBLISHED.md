---
layout: post
title:  "HTB Sea Writeup"
date:   2025-01-05 12:00:00 -0500
categories: hackthebox HTB-easy
tags: writeup hackthebox HTB easy CTF
---
## Introduction
This is a medium challenge box on
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
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

// rustscan1

We have two open ports:
- 22: SSH
- 80: HTTP

## Intial Foothold
## Privilege Escalation
## Conclusion
