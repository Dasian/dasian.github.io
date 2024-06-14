---
layout: post
title:  "Template"
date:   2024-05-22 00:00:00 -0400
categories: tryhackme medium
tags: writeup tryhackme medium CTF
---
## Introduction
This is a medium challenge box on
[TryHackMe](https://tryhackme.com/r/room/anonymousplayground){:target="_blank"}{:rel="noopener noreferrer"}.
It'll take 3-5 minutes to boot up

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Port Scan
Let's start with a port scan to see what services are
accessible

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

[link](){:target="_blank"}{:rel="noopener noreferrer"}
![image](/images/sokka.jpg)
