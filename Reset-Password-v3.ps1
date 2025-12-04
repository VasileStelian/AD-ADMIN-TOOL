# ============================================
#   AD ADMIN TOOL - PRODUCTION VERSION
#   Hash-Based Credential Storage (DPAPI)
# ============================================

#Requires -Version 5.1

# ------------------------------------------
# Configuration
# ------------------------------------------
$CONFIG = @{
    ServersFile = "./servers.txt"
    CacheFolder = "./.cache"
    MapFile     = "./.cache/.map"
    LogPath     = "./logs"
    AuditLog    = "./logs/audit.log"
}

# ------------------------------------------
# Create directories
# ------------------------------------------
@($CONFIG.CacheFolder, $CONFIG.LogPath) | ForEach-Object {
    if (-not (Test-Path $_)) { 
        New-Item -ItemType Directory -Path $_ -Force | Out-Null 
    }
}

# ------------------------------------------
# Hash-Based Filename Functions
# ------------------------------------------
function Get-ServerHash {
    param([string]$ServerName)
    
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hash = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ServerName.ToLower()))
    $hashString = [System.BitConverter]::ToString($hash).Replace("-", "").Substring(0, 12).ToLower()
    $md5.Dispose()
    
    return $hashString
}

function Get-CredentialFilePath {
    param([string]$ServerName)
    
    $hash = Get-ServerHash -ServerName $ServerName
    return Join-Path $CONFIG.CacheFolder "$hash.dat"
}

# ------------------------------------------
# Mapping File Functions
# ------------------------------------------
function Get-ServerMapping {
    if (-not (Test-Path $CONFIG.MapFile)) {
        return @{}
    }
    
    try {
        $mapping = Import-Clixml -Path $CONFIG.MapFile
        return $mapping
    } catch {
        return @{}
    }
}

function Save-ServerMapping {
    param([hashtable]$Mapping)
    
    $Mapping | Export-Clixml -Path $CONFIG.MapFile -Force
}

function Add-ServerToMapping {
    param([string]$ServerName)
    
    $mapping = Get-ServerMapping
    $hash = Get-ServerHash -ServerName $ServerName
    
    if (-not $mapping.ContainsKey($hash)) {
        $mapping[$hash] = @{
            ServerName = $ServerName
            Added = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        Save-ServerMapping -Mapping $mapping
    }
}

# ------------------------------------------
# Credential Storage Functions (DPAPI)
# ------------------------------------------
function Get-SavedCredential {
    param([string]$ServerName)
    
    $credFile = Get-CredentialFilePath -ServerName $ServerName
    
    if (-not (Test-Path $credFile)) {
        return $null
    }
    
    try {
        $credential = Import-Clixml -Path $credFile
        return $credential
    } catch {
        return $null
    }
}

function Save-Credential {
    param(
        [string]$ServerName,
        [PSCredential]$Credential
    )
    
    $credFile = Get-CredentialFilePath -ServerName $ServerName
    
    try {
        $Credential | Export-Clixml -Path $credFile -Force
        Add-ServerToMapping -ServerName $ServerName
        return $true
    } catch {
        return $false
    }
}

function Remove-SavedCredential {
    param([string]$ServerName)
    
    $credFile = Get-CredentialFilePath -ServerName $ServerName
    
    if (Test-Path $credFile) {
        Remove-Item -Path $credFile -Force
    }
}

# ------------------------------------------
# Audit logging
# ------------------------------------------
function Write-AuditLog {
    param(
        [string]$Action,
        [string]$TargetUser,
        [string]$Server,
        [string]$Status,
        [string]$Details = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $adminUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $entry = "$timestamp | $adminUser | $Server | $TargetUser | $Action | $Status | $Details"
    
    Add-Content -Path $CONFIG.AuditLog -Value $entry
}

# ------------------------------------------
# Server selection
# ------------------------------------------
if (-not (Test-Path $CONFIG.ServersFile)) {
    Write-Host "[ERROR] servers.txt not found" -ForegroundColor Red
    $sampleContent = @"
# AD Server List - Format: ServerName,IP:Port
# Examples:
# DC01,192.168.56.101:5985
# DC02,10.8.0.5:5985
"@
    Set-Content -Path $CONFIG.ServersFile -Value $sampleContent
    Write-Host "[INFO] Sample servers.txt created. Please edit and run again." -ForegroundColor Yellow
    exit 1
}

$rawServers = @(Get-Content -Path $CONFIG.ServersFile | Where-Object { $_.Trim() -ne "" -and $_ -notmatch '^#' })

if ($rawServers.Count -eq 0) {
    Write-Host "[ERROR] No servers in servers.txt" -ForegroundColor Red
    exit 1
}

$servers = @()
foreach ($entry in $rawServers) {
    if ($entry -match '^([^,]+),([^:]+):(\d+)$') {
        $servers += @{
            Name = $matches[1].Trim()
            IP = $matches[2].Trim()
            Port = [int]$matches[3]
        }
    } elseif ($entry -match '^([^,]+),([^:]+)$') {
        $servers += @{
            Name = $matches[1].Trim()
            IP = $matches[2].Trim()
            Port = 5985
        }
    }
}

if ($servers.Count -eq 0) {
    Write-Host "[ERROR] No valid servers found in servers.txt" -ForegroundColor Red
    exit 1
}

Write-Host "`nSelect server:" -ForegroundColor Cyan
for ($i = 0; $i -lt $servers.Count; $i++) {
    $srv = $servers[$i]
    Write-Host "  $($i+1). $($srv.Name) ($($srv.IP):$($srv.Port))"
}

do {
    $choice = Read-Host "`nChoose server number (1-$($servers.Count))"
    $index = ([int]$choice) - 1
} while ($index -lt 0 -or $index -ge $servers.Count)

$selectedServer = $servers[$index]
$serverName = $selectedServer.Name
$serverIP = $selectedServer.IP
$serverPort = $selectedServer.Port

Write-Host "`n[OK] Selected: $serverName (${serverIP}:${serverPort})`n" -ForegroundColor Green

# ------------------------------------------
# Session options
# ------------------------------------------
$sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

if ($serverPort -eq 5986) {
    $connectionUri = "https://${serverIP}:${serverPort}/wsman"
} else {
    $connectionUri = "http://${serverIP}:${serverPort}/wsman"
}

# ------------------------------------------
# Credential handling with validation
# ------------------------------------------
$credentialsValid = $false
$attemptCount = 0
$maxAttempts = 3

while (-not $credentialsValid -and $attemptCount -lt $maxAttempts) {
    $attemptCount++
    
    # Try to load saved credentials
    $adminCred = Get-SavedCredential -ServerName $serverName
    
    if ($null -eq $adminCred) {
        Write-Host "[i] No saved credentials for $serverName" -ForegroundColor Yellow
        $adminCred = Get-Credential -Message "Enter admin credentials for $serverName"
        
        if ($null -eq $adminCred) {
            Write-Host "[ERROR] Authentication failed" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[i] Using saved credentials for $serverName" -ForegroundColor Cyan
    }
    
    # Test credentials
    Write-Host "[...] Validating credentials..." -ForegroundColor Yellow
    
    try {
        $testSession = New-PSSession -ConnectionUri $connectionUri -Credential $adminCred -SessionOption $sessionOption -ErrorAction Stop
        Remove-PSSession $testSession
        
        Write-Host "[OK] Credentials validated`n" -ForegroundColor Green
        $credentialsValid = $true
        
        # Save credentials
        $saved = Save-Credential -ServerName $serverName -Credential $adminCred
        if (-not $saved) {
            Write-Host "[WARNING] Could not save credentials" -ForegroundColor Yellow
        }
        
        # Auto-detect domain name from server
        Write-Host "[...] Detecting domain..." -ForegroundColor Yellow
        try {
            $domainInfo = Invoke-Command -ConnectionUri $connectionUri -Credential $adminCred -SessionOption $sessionOption -ScriptBlock {
                Import-Module ActiveDirectory -ErrorAction Stop
                $domain = (Get-ADDomain).DNSRoot
                return $domain
            } -ErrorAction Stop
            
            $detectedDomain = $domainInfo
            Write-Host "[OK] Domain detected: $detectedDomain`n" -ForegroundColor Green
            
        } catch {
            Write-Host "[ERROR] Could not detect domain" -ForegroundColor Red
            exit 1
        }
        
    } catch {
        Write-Host "[ERROR] Authentication failed" -ForegroundColor Red
        
        # Remove bad credentials
        Remove-SavedCredential -ServerName $serverName
        
        if ($attemptCount -lt $maxAttempts) {
            Write-Host "[i] Please enter valid credentials ($($maxAttempts - $attemptCount) attempts remaining)`n" -ForegroundColor Yellow
            $adminCred = Get-Credential -Message "Enter admin credentials for $serverName"
            
            if ($null -eq $adminCred) {
                Write-Host "[ERROR] Authentication failed" -ForegroundColor Red
                exit 1
            }
        } else {
            Write-Host "[ERROR] Maximum authentication attempts reached" -ForegroundColor Red
            exit 1
        }
    }
}

# ------------------------------------------
# Username input
# ------------------------------------------
do {
    $username = Read-Host "Enter username (SAMAccountName)"
    $username = $username.Trim()
    
    if ($username -match '[^a-zA-Z0-9._-]') {
        Write-Host "[!] Invalid characters in username" -ForegroundColor Yellow
        $username = $null
    }
} while ([string]::IsNullOrWhiteSpace($username))

# ------------------------------------------
# User lookup
# ------------------------------------------
Write-Host "`n[...] Checking user on $serverName..." -ForegroundColor Yellow

try {
    $userInfo = Invoke-Command -ConnectionUri $connectionUri -Credential $adminCred -SessionOption $sessionOption -ScriptBlock {
        param($user)
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            return @{ Status = "MODULE_MISSING" }
        }
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        try {
            $adUser = Get-ADUser $user -Properties Enabled, LockedOut, PasswordLastSet -ErrorAction Stop
            return @{
                Status = "FOUND"
                Enabled = $adUser.Enabled
                LockedOut = $adUser.LockedOut
                PasswordLastSet = $adUser.PasswordLastSet
            }
        } catch {
            return @{ Status = "NOT_FOUND" }
        }
    } -ArgumentList $username -ErrorAction Stop
    
} catch {
    Write-Host "[ERROR] Connection failed" -ForegroundColor Red
    Write-AuditLog -Action "CONNECTION_FAILED" -TargetUser $username -Server $serverName -Status "FAILED" -Details "Connection error"
    exit 1
}

if ($userInfo.Status -eq "MODULE_MISSING") {
    Write-Host "[ERROR] ActiveDirectory module not installed on $serverName" -ForegroundColor Red
    exit 1
}

if ($userInfo.Status -eq "NOT_FOUND") {
    Write-Host "[ERROR] User '$username' not found on $serverName" -ForegroundColor Red
    Write-AuditLog -Action "USER_LOOKUP" -TargetUser $username -Server $serverName -Status "NOT_FOUND"
    exit 1
}

# ------------------------------------------
# Display user info
# ------------------------------------------
Write-Host "`n[OK] User found:" -ForegroundColor Green
Write-Host "    Enabled        : $($userInfo.Enabled)"
Write-Host "    Locked Out     : $($userInfo.LockedOut)"
Write-Host "    Password Set   : $($userInfo.PasswordLastSet)"

# ------------------------------------------
# Action menu
# ------------------------------------------
Write-Host "`nChoose action:" -ForegroundColor Cyan
Write-Host "  1. Reset password + unlock"
Write-Host "  2. Unlock account only"
Write-Host "  3. Disable account"
Write-Host "  4. Test credentials (verify password works)"
Write-Host "  5. Exit"

do {
    $action = Read-Host "`nSelection (1-5)"
} while ($action -notmatch '^[1-5]$')

if ($action -eq "5") {
    Write-Host "`nExiting." -ForegroundColor Yellow
    exit 0
}

# ------------------------------------------
# Password reset options
# ------------------------------------------
$requireChangeAtLogon = $false
$verifyPassword = $false

if ($action -eq "1") {
    Write-Host "`nPassword reset options:" -ForegroundColor Cyan
    $changeChoice = Read-Host "Require user to change password at next login? (y/n)"
    $requireChangeAtLogon = ($changeChoice -eq "y")
    
    $verifyChoice = Read-Host "Verify the new password works after reset? (y/n)"
    $verifyPassword = ($verifyChoice -eq "y")
}

# ------------------------------------------
# Confirmation for destructive actions
# ------------------------------------------
if ($action -eq "3") {
    Write-Host "`n[!] WARNING: This will DISABLE the account!" -ForegroundColor Red
    $confirm = Read-Host "Type 'DISABLE' to confirm"
    if ($confirm -ne "DISABLE") {
        Write-Host "`nCancelled." -ForegroundColor Yellow
        exit 0
    }
}

# ------------------------------------------
# Execute action
# ------------------------------------------
Write-Host "`n[...] Executing action..." -ForegroundColor Yellow

# Handle Test Credentials
if ($action -eq "4") {
    Write-Host "`nEnter credentials to test for user: $username" -ForegroundColor Cyan
    $testPasswordSecure = Read-Host "Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($testPasswordSecure)
    $testPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    try {
        $testResult = Invoke-Command -ConnectionUri $connectionUri -Credential $adminCred -SessionOption $sessionOption -ScriptBlock {
            param($user, $passwordToTest, $domain)
            
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $domain)
                
                if ($principalContext.ValidateCredentials($user, $passwordToTest)) {
                    $principalContext.Dispose()
                    return @{ Status = "VALID" }
                } else {
                    $principalContext.Dispose()
                    return @{ Status = "INVALID" }
                }
            } catch {
                return @{ 
                    Status = "ERROR"
                    Message = $_.Exception.Message
                }
            }
        } -ArgumentList $username, $testPasswordPlain, $detectedDomain -ErrorAction Stop
        
        Write-Host "`n===============================" -ForegroundColor Cyan
        Write-Host "CREDENTIAL TEST RESULTS" -ForegroundColor White
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "    User       : $username" -ForegroundColor Gray
        Write-Host "    Server     : $serverName" -ForegroundColor Gray
        Write-Host "    Domain     : $detectedDomain" -ForegroundColor Gray
        
        switch ($testResult.Status) {
            "VALID" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "PASSWORD WORKS!" -ForegroundColor Green
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $serverName -Status "VALID"
            }
            "INVALID" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "PASSWORD FAILED!" -ForegroundColor Red
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $serverName -Status "INVALID"
            }
            "ERROR" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "TEST ERROR" -ForegroundColor Yellow
                Write-Host "    Details    : $($testResult.Message)" -ForegroundColor Yellow
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $serverName -Status "ERROR" -Details $testResult.Message
            }
        }
        
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host ""
        exit 0
        
    } catch {
        Write-Host "[ERROR] Connection failed" -ForegroundColor Red
        exit 1
    }
}

# For other actions
try {
    $result = Invoke-Command -ConnectionUri $connectionUri -Credential $adminCred -SessionOption $sessionOption -ScriptBlock {
        param($user, $actionType, $passwordLength, $mustChangePassword, $domain, $shouldVerify)
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        try {
            switch ($actionType) {
                "1" {
                    function New-SimplePassword {
                        param([int]$Length = 12)
                        
                        $letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
                        $numbers = '0123456789'
                        $specials = '.#@'
                        $allChars = $letters + $numbers + $specials
                        
                        $password = ""
                        $password += $letters[(Get-Random -Minimum 0 -Maximum $letters.Length)]
                        $password += $letters.ToUpper()[(Get-Random -Minimum 0 -Maximum 26)]
                        $password += $numbers[(Get-Random -Minimum 0 -Maximum $numbers.Length)]
                        $password += $specials[(Get-Random -Minimum 0 -Maximum $specials.Length)]
                        
                        for ($i = $password.Length; $i -lt $Length; $i++) {
                            $password += $allChars[(Get-Random -Minimum 0 -Maximum $allChars.Length)]
                        }
                        
                        $passwordArray = $password.ToCharArray()
                        $shuffled = $passwordArray | Get-Random -Count $passwordArray.Length
                        return -join $shuffled
                    }
                    
                    $newPassword = New-SimplePassword -Length $passwordLength
                    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    
                    Set-ADAccountPassword $user -Reset -NewPassword $securePassword -ErrorAction Stop
                    Unlock-ADAccount $user -ErrorAction SilentlyContinue
                    Set-ADUser $user -ChangePasswordAtLogon $mustChangePassword -ErrorAction Stop
                    
                    $testResult = "SKIPPED"
                    if ($shouldVerify) {
                        # Small delay for AD replication
                        Start-Sleep -Seconds 2
                        
                        try {
                            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                            $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $domain)
                            
                            if ($principalContext.ValidateCredentials($user, $newPassword)) {
                                $testResult = "VERIFIED"
                            } else {
                                $testResult = "FAILED"
                            }
                            $principalContext.Dispose()
                        } catch {
                            $testResult = "ERROR: $($_.Exception.Message)"
                        }
                    }
                    
                    return @{
                        Status = "SUCCESS"
                        Action = "PASSWORD_RESET"
                        Password = $newPassword
                        Message = "Password reset and account unlocked"
                        MustChangePassword = $mustChangePassword
                        PasswordVerification = $testResult
                    }
                }
                
                "2" {
                    Unlock-ADAccount $user -ErrorAction Stop
                    return @{
                        Status = "SUCCESS"
                        Action = "UNLOCK"
                        Message = "Account unlocked"
                    }
                }
                
                "3" {
                    Disable-ADAccount $user -ErrorAction Stop
                    return @{
                        Status = "SUCCESS"
                        Action = "DISABLE"
                        Message = "Account disabled"
                    }
                }
            }
        } catch {
            return @{
                Status = "FAILED"
                Action = "ERROR"
                Message = $_.Exception.Message
            }
        }
    } -ArgumentList $username, $action, 12, $requireChangeAtLogon, $detectedDomain, $verifyPassword -ErrorAction Stop
    
} catch {
    Write-Host "[ERROR] Operation failed" -ForegroundColor Red
    Write-AuditLog -Action "EXECUTION_FAILED" -TargetUser $username -Server $serverName -Status "FAILED"
    exit 1
}

# ------------------------------------------
# Display results
# ------------------------------------------
Write-Host "`n===============================" -ForegroundColor Cyan

if ($result.Status -eq "SUCCESS") {
    Write-Host "[OK] SUCCESS" -ForegroundColor Green
    Write-Host "    User       : $username"
    Write-Host "    Server     : $serverName"
    Write-Host "    Action     : $($result.Action)"
    Write-Host "    Details    : $($result.Message)"
    
    if ($result.Password) {
        Write-Host "`n    NEW PASSWORD: " -ForegroundColor Yellow -NoNewline
        Write-Host $result.Password -ForegroundColor White
        
        if ($result.PasswordVerification -ne "SKIPPED") {
            switch ($result.PasswordVerification) {
                "VERIFIED" {
                    Write-Host "    Verification : " -ForegroundColor Gray -NoNewline
                    Write-Host "PASSWORD WORKS!" -ForegroundColor Green
                }
                "FAILED" {
                    Write-Host "    Verification : " -ForegroundColor Gray -NoNewline
                    Write-Host "VERIFICATION FAILED" -ForegroundColor Red
                }
                default {
                    if ($result.PasswordVerification.StartsWith("ERROR:")) {
                        Write-Host "    Verification : " -ForegroundColor Gray -NoNewline
                        Write-Host "Error during verification" -ForegroundColor Yellow
                        Write-Host "    Details      : $($result.PasswordVerification)" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Host "    Verification : Skipped (not requested)" -ForegroundColor Gray
        }
        
        if ($result.MustChangePassword) {
            Write-Host "    Change Policy: User MUST change at next login" -ForegroundColor Yellow
        } else {
            Write-Host "    Change Policy: User does NOT need to change password" -ForegroundColor Green
        }
    }
    
    $auditDetails = $result.Message
    if ($result.Password) {
        $auditDetails += " | MustChange: $($result.MustChangePassword) | Verified: $($result.PasswordVerification)"
    }
    Write-AuditLog -Action $result.Action -TargetUser $username -Server $serverName -Status "SUCCESS" -Details $auditDetails
    
} else {
    Write-Host "[X] FAILED" -ForegroundColor Red
    Write-Host "    Error: $($result.Message)"
    Write-AuditLog -Action $result.Action -TargetUser $username -Server $serverName -Status "FAILED" -Details $result.Message
}

Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""
