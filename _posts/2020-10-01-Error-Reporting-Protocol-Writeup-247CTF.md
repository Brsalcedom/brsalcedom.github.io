---
title:  "Error Reporting Protocol [ES] - 247CTF"
date:   2020-10-01 04:00:00 -0400
categories: [247CTF]
toc: true
comments: false
tags: [ctf, networking]
---

Si te gusta resolver CTF, [247CTF](https://247ctf.com/) definitivamente es una página que debes visitar. En ella encontrarás una variedad de desafíos de distintas categorías que van desde lo más básico hasta avanzado.

En esta ocasión compartiré un writeup del reto **Error Reporting Procotol** el cual corresponde a uno del tipo **Networking**. La plataforma nos facilitará una captura .pcap que deberemos analizar. 

## Información

![Challenge Info](/images/247CTF/error_reporting_protocol/00-info.png "Challenge Info")

> Can you identify the flag hidden within the error messages of this ICMP traffic?

## Desarrollo

Primero abriremos el archivo ```error_reporting.pcap``` que nos proporciona la plataforma con la herramienta **tshark**:

```bash
tshark -r error_reporting.pcap
```

![Captura](/images/247CTF/error_reporting_protocol/01-capture.png "Captura")

La captura consiste en su totalidad en paquetes **icmp**, de los cuales el primero es del tipo **request** y los 1711 restantes son **reply**. Esto lo podemos verificar con tshark utilizando el parámetro ```-Y``` y especificando filtros como lo haríamos en wireshark, es decir:

```bash
tshark -r error_reporting.pcap -Y "not icmp"
```

El comando no nos arrojará resultado producto de que todos los paquetes contenidos en la captura son icmp.

Continuando con el análisis, es posible que estos paquetes contengan información en el campo **data**, para verificarlo desde tshark podemos utilizar el parámetro ```-Tjson``` que nos mostrará la estructura del paquete en formato json:

```bash
tshark -r error_reporting.pcap -Tjson 2>/dev/null
```

![Estructura paquetes](/images/247CTF/error_reporting_protocol/02-capture.png "Estructura paquetes")

Como se puede apreciar en la imagen, el campo data posee información en hexadecimal. Por lo tanto, lo que haremos será filtrar solo ese campo de todos los paquetes icmp y posteriormente decodificarlos. Para ello desde tshark ejecutamos:

```bash
tshark -r error_reporting.pcap -Tfields -e data.data 2>/dev/null
```

![data](/images/247CTF/error_reporting_protocol/03-capture.png "data")

```bash
tshark -r error_reporting.pcap -Tfields -e data.data 2>/dev/null | xxd -r -p
```

![Decode](/images/247CTF/error_reporting_protocol/04-capture.png "Decode")


El resultado de la decodificación hexadecimal nos muestra el mensaje ```Send the flag!``` seguido de JFIFC y posteriormente vemos datos ilegibles. el mensaje **Send the flag!** correponde a la data contenida en el primer paquete icmp (request), y el resto de la data corresponde a los reply.

El texto **JFIFC** inmediatamente nos hace pensar en que esta data es un dump hexadecimal de una imagen JPG, la cual puede ser facilmente revertida con la utilidad **xxd** desde consola.

Lo que haremos será enviar escribir en un archivo .txt la data de todos los paquete reply icmp de la captura. Posteriormente le haremos un reverse con xxd:

```bash
xxd -r -p hex.txt image.jpg
```
Finalmente abriremos la imagen y veremos lo siguiente:

![Flag](/images/247CTF/error_reporting_protocol/05-flag.png "Flag")

Con esto concluye el reto, el cual resultó muy divertido e interesante. 