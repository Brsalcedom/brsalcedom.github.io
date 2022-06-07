---
title:  "Blackhole Challenge Writeup [ES] - HackTheBox"
date:   2020-07-26 12:20:55 -0400
categories: [HTB]
toc: true
comments: false
tags: [ctf, misc]
---

En esta ocasión estaremos realizando el Challenge **Blackhole** de la plataforma [HackTheBox](https://hackthebox.eu) que pertenece a la categoria MISC. A continuación el detalle desde la plataforma:

![Challenge info](/images/HTB/Blackhole/00-challenge-info.png "Challenge info")


Para empezar obtenemos un archivo llamado Blackhole.zip, el cual al descomprimirlo nos generará el archivo ```hawking```.

![Blackhole.zip files](/images/HTB/Blackhole/01-files.png "Blackhole.zip files")

Lo primero será visualizar la imagen para verificar si existe algún tipo de información útil en su interior.

![Stephen Hawking](/images/HTB/Blackhole/02-hawking.png "Stephen Hawking")

Como se puede apreciar, es una imagen con la fotografía **Stephen Hawking** y la frase ***"Life would be tragic if it weren't funny."***. En primera instancia pensé que se podía tratar de una pista para conseguir la flag, por lo que busqué en internet para después de un tiempo darme cuenta de que la resolución no iba por ese camino.

Ya que verificamos que la imagen no contiene mayor información relevante, toca revisar el fichero. Lo primero es ejecutar el comando ```file``` para ver con que tipo de archivo estamos tratando.


![File info](/images/HTB/Blackhole/03-rename-file.png "File info")

Vemos que se trata de un archivo **JPEG** pero éste no viene con la extensión, por lo que renombramos el archivo para poder aplicar la utilidad ```Stegcracker``` sobre él. Esto para observar si contiene algún archivo oculto en su interior. Haciendo uso del diccionario ***rockyou.txt*** le aplicamos fuerza bruta.

```bash
stegcracker hawking.jpg /usr/share/wordlists/rockyou.txt
```

![Stegcracker](/images/HTB/Blackhole/04-stegcracker.png "Stegcracker")

Al cabo de unos minutos obtenemos un match con la contraseña ***hawkingez*** y como resultado nos genera el archivo ```hawking.jpg.out```. Le aplicamos un ```cat``` y vemos una cadena de caracteres que parecen estar codificados en **base64**. 

Luego de realizar dos decodificaciones seguidas en base64, obtendremos el mensaje que se visualiza a continuación, el cual tiene un formato similar al de la **flag** que buscamos:

![Decode](/images/HTB/Blackhole/05-decode1.png "Decode")

```plaintext
Efqbtqz Iuxxumy Tmiwuzs ime mz Qzsxuet ftqadqfuomx btkeuouef, oaeyaxasuef, mzp mgftad, ita ime pudqofad ar dqeqmdot mf ftq Oqzfdq rad Ftqadqfuomx Oaeyaxask mf ftq Gzuhqdeufk ar Omyndupsq mf ftq fuyq ar tue pqmft. Tq ime ftq Xgomeumz Bdarqeead ar Ymftqymfuoe mf ftq Gzuhqdeufk ar Omyndupsq nqfiqqz 1979 mzp 2009. Tmiwuzs motuqhqp oayyqdoumx egooqee iuft eqhqdmx iadwe ar babgxmd eouqzoq uz ituot tq pueogeeqe tue aiz ftqaduqe mzp oaeyaxask uz sqzqdmx. Tue naaw M Nduqr Tuefadk ar Fuyq mbbqmdqp az ftq Ndufuet Egzpmk Fuyqe nqef-eqxxqd xuef rad m dqoadp-ndqmwuzs 237 iqqwe. Tmiwuzs ime m rqxxai ar ftq Dakmx Eaouqfk, m xurqfuyq yqynqd ar ftq Bazfuruomx Mompqyk ar Eouqzoqe, mzp m dqoubuqzf ar ftq Bdqeupqzfumx Yqpmx ar Rdqqpay, ftq tustqef ouhuxumz mimdp uz ftq Gzufqp Efmfqe. Uz 2002, Tmiwuzs ime dmzwqp zgynqd 25 uz ftq NNO\’e baxx ar ftq 100 Sdqmfqef Ndufaze.
TFN{Z3hqD_x3F_fT3_n4eFmDp5_S3f_K0g_p0iZ}
```

A simple vista el mensaje parece estar codificado en **ROT13**, por lo que con la ayuda de [CyberChef](https://gchq.github.io/CyberChef/), luego de unos intentos, obtendremos nuestro mensaje decodificado junto con la **flag**.

![Decode 2](/images/HTB/Blackhole/06-decode2.png "Decode 2")
