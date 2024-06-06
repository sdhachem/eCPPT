# Function to check if a process is running with elevated privileges
function Is-ProcessElevated {
    param (
        [int]$processId
    )
    try {
        $process = Get-WmiObject Win32_Process -Filter "ProcessId = $processId"
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $processOwner = (Get-WmiObject Win32_OperatingSystem).GetOwnerSid().Sid
        
        # Get the owner SID of the process
        $ownerSid = (New-Object System.Security.Principal.SecurityIdentifier($process.GetOwnerSid().Sid)).Translate([System.Security.Principal.NTAccount]).Value

        # Get the SID of the current user
        $currentUserSid = $token.User.Value
        
        # Compare SIDs to determine if the process has higher privileges
        if ($ownerSid -ne $currentUserSid) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

# Function to check if the current user has write permissions to the file
function Test-WritePermission {
    param (
        [string]$filePath
    )
    try {
        $acl = Get-Acl -Path $filePath
        $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -eq $user -and $access.FileSystemRights -match "Write") {
                return $true
            }
        }
    } catch {
        return $false
    }
    return $false
}

# Function to check if a process is set to auto run
function Is-AutoRun {
    param (
        [string]$exePath
    )
    $autoRunPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($path in $autoRunPaths) {
        $autoRunKeys = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
        foreach ($key in $autoRunKeys.PSObject.Properties) {
            if ($key.Value -like "*$exePath*") {
                return $true
            }
        }
    }
    return $false
}

# Get the list of all running processes
$processes = Get-Process

# Array to store results
$modifiableProcesses = @()

# Iterate through each process
foreach ($process in $processes) {
    $processId = $process.Id
    $exePath = $process.Path

    if ($exePath -and (Is-ProcessElevated -processId $processId) -and (Test-WritePermission -filePath $exePath) -and (Is-AutoRun -exePath $exePath)) {
        $modifiableProcesses += [PSCustomObject]@{
            Name = $process.Name
            Id = $processId
            Path = $exePath
        }
    }
}

# Output the list of modifiable processes
$modifiableProcesses | Format-Table -AutoSize
