## CheatSheet 

### 1.Scanning Strategy

    Search all alive host with or without open ports : 
    
### 2.SMB Misconfiguration

    Mount shared drive : 
    Linux   : mount -t cifs -o user=USER,password=PWD,rw //IP/share
    Windows : net use K: \\IPTarget\SharedDrive



### 3.Post Exploitation

#### 3.1 ByPass UAC

* Method 1 : Search Local Exploit using MSF
* Method 2 : Impersonate privileged users

  
** Windows
  *** Method 3 : Via Windows Services 
