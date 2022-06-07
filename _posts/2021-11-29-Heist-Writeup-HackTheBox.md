---
title:  "Heist Writeup [ES] - HackTheBox"
date:   2021-11-29 13:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, windows, dump-credentials]
---

[Heist](https://app.hackthebox.com/machines/201) es una máquina **Linux** de dificultad fácil ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup de su resolución.


## Información


![Info](/images/HTB/Heist/01-info.png)


## Enumeración

### Rustscan - NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos. En este caso se utilizará [Rustscan](https://github.com/RustScan/RustScan), proporcionando comandos de nmap para realizar el escaneo desde un solo comando.

* ```rustscan 10.10.10.149 -- -sC -sV | tee ports-rustcan```

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
Open 10.10.10.149:80
Open 10.10.10.149:135
Open 10.10.10.149:445
Open 10.10.10.149:5985
Open 10.10.10.149:49669

(...)

PORT      STATE SERVICE       REASON  VERSION
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Support Login Page
|_Requested resource was login.php
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
445/tcp   open  microsoft-ds? syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

* Resumen puertos

| Puerto    | Estado  | Servicio                        |
|-----------|---------|---------------------------------|
| 80/tcp    | Abierto | http - Microsoft IIS httpd 10.0 |
| 135/tcp   | Abierto | Microsoft Windows RPC           |
| 445/tcp   | Abierto | SMB - microsoft-ds              |
| 5985/tcp  | Abierto | WinRM - Microsoft HTTPAPI httpd |
| 49669/tcp | Abierto | Microsoft Windows RPC           |

### Enumeración web

Lo primero será ingresar a la web y ver que hay expuesto. Se aprecia un login, en donde existe la opción de ingresar como usuario invitado.

![](/images/HTB/Heist/05-web-login.png)

Al entrar como invitado se visualiza una especie de mesa de ayuda con información que podría ser relevante. De primeras se identifica que los usuarios **Hazard** y **admin** pueden ser usuarios potenciales del sistema.

![](/images/HTB/Heist/10-guest-login.png)

El ticket contiene un archivo adjunto que al abrirlo, revela un archivo de configuración de un router cisco.

![](/images/HTB/Heist/15-attachment.png)

De esto podemos extraer potenciales usuarios y contraseñas. Pero antes, habrá que tratar de convertir o crackear los hashes obtenidos.

```plaintext
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91

username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
```

En el caso de las ```password 7``` existe un [recurso online](https://www.firewall.cx/cisco-technical-knowledgebase/cisco-routers/358-cisco-type7-password-crack.html) que permite desencriptar este tipo de contraseñas.

![](/images/HTB/Heist/20-decrypt-password1.png)

![](/images/HTB/Heist/25-decrypt-password2.png)

Para el último hash, deberemos utilizar ```john``` para romperlo con fuerza bruta utilizando ```rockyou.txt```

* ```john --wordlist=/usr/share/wordlists/rockyou.txt hash```

![](/images/HTB/Heist/30-john-password3.png)

Por lo tanto, tendríamos lo siguiente.

* ```users.txt```

```plaintext
hazard
rout3r
admin
```
* ```passwords.txt```

```plaintext
$uperP@ssword
Q4)sJu\Y8qz*A3?d
stealth1agent
```

## Acceso inicial

Con esta información y utilizando [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec), realizaremos un password spray para detectar si existen credenciales válidas con la información que se ha recopilado hasta el momento.

![](/images/HTB/Heist/35-smb-login.png)

Testeando nuevamente con **CME** validamos que el usuario no tiene permisos para el acceso remoto al protocolo **WinRM**.

![](/images/HTB/Heist/38-winrm-failed-test.png)

Continuando con la enumeración, ahora que tenemos credenciales válidas, se puede intentar un brute-forcing de usuarios a través de RID. Y al cabo de unos segundos se obtienen más usuarios.

![](/images/HTB/Heist/40-smb-rid.png)

Se agregan al archivo ```users.txt``` y realizaremos nuevamente el password spray. 

> Esta vez utilizando el módulo ```smb_login``` de metasploit, ya que por algún motivo **CME** no muestra más matches una vez que encuentra una credencial válida.

![](/images/HTB/Heist/45-user-login.png)

Y como resultado se obtiene una credencial válida para el user **Chase**. Nuevamente se intenta el login a través de **WinRM**, esta vez con éxito.

![](/images/HTB/Heist/50-winrm-test.png)

## Escalada de privilegios

Procedemos a loguear al sistema con [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

* ```evil-winrm -i 10.10.10.149 -u 'Chase' -p 'Q4)sJu\Y8qz*A3?d'```

Una vez dentro, haciendo enumeración básica, se detecta algo inusual, al revisar los procesos se ve que está en ejecución **Firefox**, el cual no viene instalado por defecto en Windows. Esto nos da un indicio de que es probable que juegue un rol en la escalada de privilegios.

![](/images/HTB/Heist/55-processes.png)

Siguiendo esta lógica, lo siguiente será realizar un dump del proceso de Firefox para ver que se encuentra almacenado. Para esto utilizaremos una herramienta nativa de Microsoft que se puede descargar desde su web oficial - [Procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump).

Descargamos la herramienta y la subimos a la máquina víctima.

![](/images/HTB/Heist/70-procdump-upload.png)

En su primera ejecución, deberemos aceptar el **EULA** y posterior a esto realizar el **dump**. Para esto existen los siguientes modos:

![](/images/HTB/Heist/72-dump-types.png)

En esta ocasión utilizaremos el modo **Full**, especificando un PID o número de proceso de Firefox.

* ```.\procdump64.exe -ma 6380```

![](/images/HTB/Heist/75-procdump-firefox.png)

Al cabo de unos segundos obtendremos un archivo con extensión ```.dmp``` el cual podríamos intentar leer utilizando ```strings```. Esto se puede realizar transfiriendo el archivo hacia nuestro **Parrot** o bien subir el binario para Windows de la herramienta ```strings```. 

Por lo tanto, haciendo uso de [Impacket](https://github.com/SecureAuthCorp/impacket) para compartir un server **SMB**, transferiremos el archivo a nuestra máquina para leer su contenido.

1. ```strings firefox.exe_211214_081618.dmp -n 30 > output.txt```
2. ```grep --color "password" output.txt```
  
![](/images/HTB/Heist/90-pass-dump.png)

Y obtenemos la siguiente string.

```plaintext
http://localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
```
De la cual se puede leer la password ```4dD!5}x/re8]FBuZ```. Podemos suponer que esta es la contraseña del usuario **Administrador**, por lo que ya podemos conectarnos y leer las flags.

![](/images/HTB/Heist/100-flags.png)

Y esto sería todo para la máquina Heist, una máquina sencilla pero viene bien para repasar conceptos.