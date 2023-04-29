# End-Of-Bagel

## Подключаемся к vpn от HTB.

```
sudo openvpn /home/kali/Downloads/lab_smipos.ovpn
```

1) Проверяем открытые порты с помощью программы Zenmap. 
```
nmap -T4 -A -v 10.10.11.201
```

```
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e:4e:13:41:f2:fe:d9:e0:f7:27:5b:ed:ed:cc:68:c2 (ECDSA)
|_  256 80:a7:cd:10:e7:2f:db:95:8b:86:9b:1b:20:65:2a:98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 29 Apr 2023 17:52:21 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 29 Apr 2023 17:52:37 GMT
|     Connection: close
|   Help, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 29 Apr 2023 17:52:47 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sat, 29 Apr 2023 17:52:21 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (version).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| http-title: Bagel &mdash; Free Website Template, Free HTML5 Template by fr...
```
![image](https://user-images.githubusercontent.com/77785989/235317015-6dc072ee-1538-4f68-a1a8-379ff423c5cf.png)

Как мы видим - открыто 3 порта: 22, 5000, 8000.

2) Помещаем 10.10.11.201 bagel.htb в папку с хостами.
```
cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
10.10.11.201 bagel.htb
```
![image](https://user-images.githubusercontent.com/77785989/235317321-13dfaf59-6944-4994-b9aa-bf91698d519e.png)

3) Смотрим информацию о сайте с помощью команды whatweb.
```
whatweb 10.10.11.201:5000
http://10.10.11.201:5000 [400 Bad Request] Country[RESERVED][ZZ], HTTPServer[Microsoft-NetCore/2.0], IP[10.10.11.201]
```
 
```
whatweb 10.10.11.201:8000
http://10.10.11.201:8000 [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.10.11.201], Python[3.10.9], RedirectLocation[http://bagel.htb:8000/?page=index.html], Title[Redirecting...], Werkzeug[2.2.2]
http://bagel.htb:8000/?page=index.html [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.10.11.201], JQuery, Meta-Author[freehtml5.co], Modernizr[2.6.2.min], Open-Graph-Protocol, Python[3.10.9], Script, Title[Bagel &mdash; Free Website Template, Free HTML5 Template by freehtml5.co], Werkzeug[2.2.2], X-UA-Compatible[IE=edge]
```
![image](https://user-images.githubusercontent.com/77785989/235317771-c87b67b4-1f99-4bb4-b708-c5534bfc45fa.png)

Порт 5000 выдает ошибку, а порт 8000 перенаправляет нас на страницу http://bagel.htb:8000/?page=index.html

Как мы можем видеть: в адресной строке имеется * page?=.html *
Значит мы можем попробовать что-нибудь вытянуть с помощью LFI.
```
Local File Inclusion
LFI — это возможность использования и выполнения локальных файлов на серверной стороне. Уязвимость позволяет удаленному пользователю получить доступ с помощью специально сформированного запроса к произвольным файлам на сервере, в том числе содержащую конфиденциальную информацию.
```
