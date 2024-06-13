---
layout: post
title:  "CyberLens Writeup"
date:   2024-06-13 00:00:00 -0400
categories: tryhackme easy
tags: writeup tryhackme easy CTF windows metasploit
---
## Introduction
This is a easy challenge box on
[TryHackMe](https://tryhackme.com/r/room/cyberlensp6){:target="_blank"}{:rel="noopener noreferrer"}.
It'll take 5 minutes to boot up

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Hosts
First we should add the following to `/etc/hosts` so
we can access the domain

```hosts
MACHINE_IP cyberlens.thm
```

### Ports
Now let's see what ports and services are available to
us with a port scan

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/cyberlens/scan1.png)
![scan2](/images/cyberlens/scan2.png)
![scan3](/images/cyberlens/scan3.png)

There are quite a few ports open! This is normal for
a Windows box. We only need to pay attention to two ports
- 80: HTTP
- 61777: HTTP

### Web Server
> Visit all the web servers and proxy their traffic
{: .prompt-tip }
Let's visit the homepage and see what is available

![image extractor](/images/cyberlens/image-extractor.png)

Seems like there's a service that extracts metadata
from a file. Let's send a test file and proxy the request
through Burp

![extraction test](/images/cyberlens/extraction-test.png)

![burp port](/images/cyberlens/burp-port.png)

We get a decent amount of information here. We see that
the file is being parsed by
[Apache Tika](https://tika.apache.org/){:target="_blank"}{:rel="noopener noreferrer"}
and the service sends a `PUT` request to port `61777`

In our inital port scan we saw this port running `HTTP` so
let's visit that endpoint

![tika version](/images/cyberlens/tika-version.png)

So this is where the tika service is being hosted and we're
also given a version!

## Initial Foothold
> Look for public exploits with a version number
{: .prompt-tip }

We have a service name and version so let's use `searchploit`
to see if we have any exploits

![searchsploit tika](/images/cyberlens/searchsploit-tika.png)

There's a command injection exploit for versions 1.15 - 1.17!
This is available as a module on
[metasploit](https://www.metasploit.com/){:target="_blank"}{:rel="noopener noreferrer"}
so let's use that to make things easier.

We can start metasploit with the command
```bash
msfconsole
```

Then we can find and use the module we want with the
`search` command

```
search tika
use 0
```

![msf tika](/images/cyberlens/msf-tika.png)

Now we need to set the options for the modules. 
Available options can be seen with the `show options`
command. The format for setting options is

```
set OPTION_NAME OPTION_VALUE
```

For example to set the target port `RPORT` to `61777` we
would run
```
set RPORT 61777
```

Repeat this for all the required options. In the end it
should look like something like this

![msf options](/images/cyberlens/msf-options.png)

Now we run the module with the `run` command and hope
we get a shell

![meterpreter1](/images/cyberlens/meterpreter1.png)

Perfect! Now we can read `user.txt` on `CyberLens`'
desktop

```
cat Users\\CyberLens\\Desktop\\user.txt
```

![user flag](/images/cyberlens/user-flag.png)

## Administrator
> Use metasploit's local exploit suggester
{: .prompt-tip }

Now that we're on the box we should try to escalate our
privileges. Fortunately, we're in a `meterpreter` shell
and `metasploit` has a module for that!

To use it we need to background our `meterpreter`
shell 

```
bg
```

Then we search for the module and set the options just
like the first `metasploit` module we used to gain a
foothold onto the system

```
search exploit suggester
use 0
```

![exploit suggester](/images/cyberlens/exploit-suggester.png)

After running the module we see that the target is
vulnerable to `exploit/windows/local/always_install_elevated`.
Let's use that module and see if it escalates our privileges

![meterpreter2](/images/cyberlens/meterpreter2.png)

It works! We have an `Administrator` shell now so we
can read the admin flag

```
cat Users\\Administrator\\Desktop\\admin.txt
```

![admin flag](/images/cyberlens/admin-flag.png)

## Conclusion
By investigating open HTTP ports on `80` and `61777` we
were able to find a vulnerable service. Using `searchsploit`
we were able to find an exploit module on `metasploit`
which gave us a foothold onto the
system. Using `metasploit`'s local exploit suggester we
were able to escalate to `Administrator` privileges.
