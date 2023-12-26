## CheatSheet 

### 1.Most used nmap command

#### 1.1 NMAP
    * scan -Pn -sn TARGET                 : Search all alive host with or without open ports 
    * scan -sV -n TARGET                  : Fingerprint all exposed services
    * scan -sV -n TARGET -p SEVICE_PORT   : Fingerprint a specific exposed service
    * scan -O -n TARGET                   : Find Operating System

#### 1.2 Metasploit
    * auxiliary/scanner/smb/smb_version 

### 3.DNS Misconfiguration

    * dig @authorative_dns_server -t axfr DOMAIN      :    Exploiting zone transfer to display all subdomains
    * Exploiting zone transfer to display zone

### 2.SMB Misconfiguration

    Mount shared drive : 
    * Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
    * Windows : net use K: \\IPTarget\SharedDrive


### 4.Exploitation


### 3.Post Exploitation

#### 3.1 ByPass UAC

##### 3.1.1 All OS

    * Method 1 : Search Local Exploit using MSF
    * Method 2 : Impersonate privileged users

##### 3.1.2 Specific Windows

    * Method 3 : Via Windows Services 
  
##### 3.1.3 Specific Linux

### 5.Sniffing

#### 5.1 MiTM between vtcim1 & victm2 using arp poisonning
* arpspoof -i tap0 -t vic1_IP -r vic2_IP
*  arpspoof -i tap0 -t vic2_IP -r vic2_IP
