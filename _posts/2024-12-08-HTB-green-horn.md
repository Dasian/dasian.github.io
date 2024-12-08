---
layout: post
title:  "HTB Green Horn Writeup"
date:   2024-12-08 12:00:00 -0500
categories: hackthebox HTB-easy
tags: writeup hackthebox HTB easy CTF source-code depixelize
---
## Introduction
This is an easy machine on
[HackTheBox](https://app.hackthebox.com/machines/GreenHorn){:target="_blank"}{:rel="noopener noreferrer"}.

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

![rustscan1](/images/htb-green-horn/rustscan1.png)

![rustscan2](/images/htb-green-horn/rustscan2.png)

We have three open ports:
- 22: SSH
- 80: HTTP
- 3000: HTTP

### Website
With most HTB machines we need to map the machine IP to
a domain name before we can visit the website. In your
`/etc/hosts` file add the following

```
VICTIM_IP greenhorn.htb
```

Visiting the site hosted on port 80 we find

![homepage](/images/htb-green-horn/homepage.png)

There are not many pages we can access but notice the
`admin` and `pluck` links on the bottom.
Clicking on `admin` redirects us to a login page

![pluck-login](/images/htb-green-horn/pluck-login.png)

We don't have any credentials but it'll be useful later.

### Gitea
Our scan tells us there is another web service
on port 3000. Port numbers can be
specified after the domain name. Visiting
`http://greenhorn.htb:3000` leads us here

![gitea-homepage](/images/htb-green-horn/gitea-homepage.png)

Doing some research,
[Gitea](https://about.gitea.com/){:target="_blank"}{:rel="noopener noreferrer"}
is a version control system (similar to GitHub or GitLab).
Unregistered users don't have access to a lot of resources,
so create an account to dig deeper.

With an account we can visit the `Explore` tab

![gitea-explore](/images/htb-green-horn/gitea-explore.png)

Looks like we found the source code for the `pluck` site on
port 80!

## Intial Foothold
### Leaked Credentials
> What sensitive information can you find in the repo?
{: .prompt-tip }

It may seem daunting trying to explore an entire code repo,
so we'll narrow our scope. We don't need to understand
how the entire website works, we just want to find a way into
the `pluck` admin dashboard.

Searching through the `/data/settings` directory, we find a
file called `pass.php`

![gitea-password](/images/htb-green-horn/gitea-password.png)

This looks like a hashed password! Save it to a file and
we can crack it with `john`

```
john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt
```

![john-formats](/images/htb-green-horn/john-formats.png)

Looks like our hash matches multiple different formats. Using
[this site](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
we know our hash type is `SHA 512`. Let's update our cracking command
using the `--format` flag

```
john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt --format=RAW-SHA512
```

![cracked-password](/images/htb-green-horn/cracked-password.png)

Awesome! Test the password on the `pluck` login page we found
earlier

![pluck-dashboard](/images/htb-green-horn/pluck-dashboard.png)

### Shell
> How can we add malicious `php` to a Content Management System?
{: .prompt-tip }

By abusing the `install module` feature of pluck, we can
upload a malicious module containing a `php` reverse shell!
This feature is found by going to options > manage modules

![pluck-install-module](/images/htb-green-horn/pluck-install-module.png)

Now let's prepare the payload. Using this
[reverse shell generator](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
we can create a `php` reverse shell. Change the IP to your
machine's IP and the port to 4444. 

Save the `php` reverse shell to a file called `shell.php` and
add it to a `zip` file.

```bash
zip payload.zip shell.php
```

The malicious module is ready! Before uploading it, we need to
setup a listener to accept the incoming shell request. In
a new terminal run

```bash
nc -lvnp 4444
```

We're ready to install the module! Upload the `zip` file
then visit
`http://greenhorn.htb/data/modules/payload/shell.php`.
This will active our reverse shell payload and gives us
a foothold into the system

![revshell](/images/htb-green-horn/www-data-revshell.png)

## Privilege Escalation (User)
> What credentials do we have?
{: .prompt-tip }

Visiting the `/home` directory reveals the `junior` user.
People aren't good at remembering unique usernames and 
passwords for all their accounts, so credential
are often reused. Knowing this, let's reuse the password from the
`pluck` admin dashboard.

![user-txt](/images/htb-green-horn/user-txt.png)

We got it! Aside from the `user.txt` flag, there is another
file called `Using OpenVAS.pdf`. Let's
download this file to our system to investigate.

There are a few ways to exfiltrate data but this time I'll encode
the file in `base64`

```bash
base64 "Using OpenVAS.pdf"
```

Copy and paste the output into a text file on your machine,
then decode the file

```bash
base64 --decode b64.txt > "Using OpenVAS.pdf"
```

## Privilege Escalation (root)
> Looks like `root`'s password was blurred in the document.
> Is there a way to depixelize it?
{: .prompt-tip }

First let's open the exfiltrated `pdf` file

![pdf-msg](/images/htb-green-horn/pdf-msg.png)

A blurred out password! Thankfully, there are ways to
retrieve the original image.
[Depix](https://github.com/spipm/Depix){:target="_blank"}{:rel="noopener noreferrer"}
is a tool which depixelize an image.
For consistency, I used
[this website](https://tools.pdf24.org/en/){:target="_blank"}{:rel="noopener noreferrer"}
to extract the blurred password image (0.png) from the `pdf`.

After cloning the 
[Depix repo](https://github.com/spipm/Depix){:target="_blank"}{:rel="noopener noreferrer"}
we can depixelize the image

```bash
python3 depix.py -p 0.png -s images/searchimages/debruinseq_notepad_Windows10_spaced.png
```

This command tries to match the pixelized character to a normal
Windows 10 notepad character. The generated image gives us the `root` password!
We can `SSH` into the box as `root` and capture the flag

![root-txt](/images/htb-green-horn/root-txt.png)

## Conclusion
A `Gitea` instance on port 3000 hosts the `pluck` website code. Reading
the source, we can find a hashed password that gives us access to the
`pluck` admin dashboard. A malicious module containing a `php` reverse
shell gives the attacker a foothold into the system. Reusing the
`pluck` admin credentials, we're able to access the `junior` account.
`junior`'s home directory has a `pdf` file with a blurred out `root`
password. Using 
[depix](https://github.com/spipm/Depix){:target="_blank"}{:rel="noopener noreferrer"},
we're able to depixelize the password and `ssh` into the machine
as `root`!
