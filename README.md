## CheatSheet 

### 1.Scanning Strategy

    Search all alive host with or without open ports : 
    

### 3.DNS Misconfiguration

    * Exploiting zone transfer to display all subdomains
    * Exploiting zone transfer to display zone

### 2.SMB Misconfiguration

    Mount shared drive : 
    Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
    Windows : net use K: \\IPTarget\SharedDrive

### 2.Sniffing

#### 2.1 MiTM between vtcim1 & victm2 using arp poisonning

### 3.Post Exploitation

#### 3.1 ByPass UAC

##### 3.1.1 All OS

    * Method 1 : Search Local Exploit using MSF
    * Method 2 : Impersonate privileged users

##### 3.1.2 Specific Windows

    * Method 3 : Via Windows Services 
  
##### 3.1.3 Specific Linux

