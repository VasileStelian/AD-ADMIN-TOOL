# ============================================
#   AD ADMIN TOOL - IMPROVED VERSION
# ============================================

#Requires -Version 5.1

# ------------------------------------------
# Configuration
# ------------------------------------------
$CONFIG = @{
    ServersFile = "./servers.txt"
    CredPath    = "./creds"
    LogPath     = "./logs"
    AuditLog    = "./logs/audit.log"
}

# Create directories if missing
@($CONFIG.CredPath, $CONFIG.LogPath) | ForEach-Object {
    if (-not (Test-Path $_)) { 
        New-Item -ItemType Directory -Path $_ -Force | Out-Null 
    }
}

# ------------------------------------------
# Audit logging function
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
    exit 1
}

$servers = @(Get-Content -Path $CONFIG.ServersFile | Where-Object { $_.Trim() -ne "" })

if ($servers.Count -eq 0) {
    Write-Host "[ERROR] No servers in servers.txt" -ForegroundColor Red
    exit 1
}

Write-Host "`nSelect server:" -ForegroundColor Cyan
for ($i = 0; $i -lt $servers.Count; $i++) {
    Write-Host "  $($i+1). $($servers[$i])"
}

do {
    $choice = Read-Host "`nChoose server number (1-$($servers.Count))"
    $index = ([int]$choice) - 1
} while ($index -lt 0 -or $index -ge $servers.Count)

$server = $servers[$index]
Write-Host "`n[OK] Selected: $server`n" -ForegroundColor Green

# ------------------------------------------
# Enhanced credential handling with auto-update
# ------------------------------------------
$credFile = Join-Path $CONFIG.CredPath "admin_$($server).xml"

# Function to test if credentials work
function Test-AdminCredentials {
    param(
        [PSCredential]$Credential,
        [string]$ServerName
    )
    
    try {
        $testResult = Invoke-Command -ComputerName $ServerName -Credential $Credential -ScriptBlock {
            return "SUCCESS"
        } -ErrorAction Stop
        
        return ($testResult -eq "SUCCESS")
    } catch {
        return $false
    }
}

# Try to load existing credentials
$credentialsValid = $false
$adminCred = $null

if (Test-Path $credFile) {
    Write-Host "[i] Found saved credentials for $server"
    
    try {
        $adminCred = Import-Clixml -Path $credFile
        Write-Host "[...] Verifying saved credentials..." -ForegroundColor Yellow
        
        if (Test-AdminCredentials -Credential $adminCred -ServerName $server) {
            Write-Host "[OK] Saved credentials are valid`n" -ForegroundColor Green
            $credentialsValid = $true
        } else {
            Write-Host "[WARNING] Saved credentials are no longer valid (password may have changed)" -ForegroundColor Yellow
            Write-Host "[i] Please enter the updated credentials`n" -ForegroundColor Cyan
            $credentialsValid = $false
        }
    } catch {
        Write-Host "[WARNING] Could not load saved credentials" -ForegroundColor Yellow
        $credentialsValid = $false
    }
}

# If no valid credentials, prompt for them
if (-not $credentialsValid) {
    $attemptCount = 0
    $maxAttempts = 3
    
    while (-not $credentialsValid -and $attemptCount -lt $maxAttempts) {
        $attemptCount++
        
        if ($attemptCount -eq 1 -and -not (Test-Path $credFile)) {
            Write-Host "[i] First-time login for $server" -ForegroundColor Cyan
        }
        
        $adminCred = Get-Credential -Message "Enter admin credentials for $server (Attempt $attemptCount of $maxAttempts)"
        
        if ($null -eq $adminCred) {
            Write-Host "[ERROR] Authentication cancelled" -ForegroundColor Red
            exit 1
        }
        
        Write-Host "[...] Testing credentials..." -ForegroundColor Yellow
        
        if (Test-AdminCredentials -Credential $adminCred -ServerName $server) {
            Write-Host "[OK] Credentials verified!" -ForegroundColor Green
            
            # Save the working credentials
            try {
                $adminCred | Export-Clixml -Path $credFile
                Write-Host "[OK] Credentials saved for future use`n" -ForegroundColor Green
            } catch {
                Write-Host "[WARNING] Could not save credentials, will prompt again next time" -ForegroundColor Yellow
            }
            
            $credentialsValid = $true
        } else {
            Write-Host "[ERROR] Invalid credentials - authentication failed" -ForegroundColor Red
            
            if ($attemptCount -lt $maxAttempts) {
                Write-Host "[i] Please try again`n" -ForegroundColor Yellow
            }
        }
    }
    
    if (-not $credentialsValid) {
        Write-Host "`n[ERROR] Maximum authentication attempts reached. Exiting." -ForegroundColor Red
        exit 1
    }
}

# ------------------------------------------
# Username input with validation
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
Write-Host "`n[...] Checking user on $server..." -ForegroundColor Yellow

try {
    $userInfo = Invoke-Command -ComputerName $server -Credential $adminCred -ScriptBlock {
        param($user)
        
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            return @{ 
                Status = "MODULE_MISSING"
                Error = "ActiveDirectory module not found on server" 
            }
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
            return @{ 
                Status = "NOT_FOUND"
                Error = $_.Exception.Message 
            }
        }
    } -ArgumentList $username -ErrorAction Stop
    
} catch {
    Write-Host "[ERROR] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-AuditLog -Action "CONNECTION_FAILED" -TargetUser $username -Server $server -Status "FAILED" -Details $_.Exception.Message
    exit 1
}

if ($userInfo.Status -eq "MODULE_MISSING") {
    Write-Host "[ERROR] ActiveDirectory module not installed on $server" -ForegroundColor Red
    Write-Host "        Install RSAT tools on the server first." -ForegroundColor Yellow
    exit 1
}

if ($userInfo.Status -eq "NOT_FOUND") {
    Write-Host "[ERROR] User '$username' not found on $server" -ForegroundColor Red
    Write-AuditLog -Action "USER_LOOKUP" -TargetUser $username -Server $server -Status "NOT_FOUND"
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
# Execute action remotely
# ------------------------------------------
Write-Host "`n[...] Executing action..." -ForegroundColor Yellow

# Handle Test Credentials separately (doesn't need remote execution)
if ($action -eq "4") {
    Write-Host "`nEnter credentials to test for user: $username" -ForegroundColor Cyan
    $testPasswordSecure = Read-Host "Password" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($testPasswordSecure)
    $testPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    
    try {
        $testResult = Invoke-Command -ComputerName $server -Credential $adminCred -ScriptBlock {
            param($user, $passwordToTest, $serverName)
            
            try {
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $serverName)
                
                if ($principalContext.ValidateCredentials($user, $passwordToTest)) {
                    $principalContext.Dispose()
                    return @{
                        Status = "VALID"
                        Message = "Credentials are VALID - password works!"
                    }
                } else {
                    $principalContext.Dispose()
                    return @{
                        Status = "INVALID"
                        Message = "Credentials are INVALID - password does not work"
                    }
                }
            } catch {
                return @{
                    Status = "ERROR"
                    Message = "Test failed: $($_.Exception.Message)"
                }
            }
        } -ArgumentList $username, $testPasswordPlain, $server -ErrorAction Stop
        
        # Display test results
        Write-Host "`n===============================" -ForegroundColor Cyan
        Write-Host "CREDENTIAL TEST RESULTS" -ForegroundColor White
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host "    User       : $username" -ForegroundColor Gray
        Write-Host "    Server     : $server" -ForegroundColor Gray
        
        switch ($testResult.Status) {
            "VALID" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "PASSWORD WORKS!" -ForegroundColor Green
                Write-Host "    Status     : Credentials validated successfully" -ForegroundColor Green
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $server -Status "VALID" -Details "Password validated successfully"
            }
            "INVALID" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "PASSWORD FAILED!" -ForegroundColor Red
                Write-Host "    Status     : Credentials are incorrect" -ForegroundColor Red
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $server -Status "INVALID" -Details "Password validation failed"
            }
            "ERROR" {
                Write-Host "`n    Result     : " -ForegroundColor Gray -NoNewline
                Write-Host "TEST ERROR" -ForegroundColor Yellow
                Write-Host "    Details    : $($testResult.Message)" -ForegroundColor Yellow
                Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $server -Status "ERROR" -Details $testResult.Message
            }
        }
        
        Write-Host "===============================" -ForegroundColor Cyan
        Write-Host ""
        exit 0
        
    } catch {
        Write-Host "[ERROR] Connection failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-AuditLog -Action "TEST_CREDENTIALS" -TargetUser $username -Server $server -Status "FAILED" -Details $_.Exception.Message
        exit 1
    }
}

# For other actions, continue with remote execution
try {
    $result = Invoke-Command -ComputerName $server -Credential $adminCred -ScriptBlock {
        param($user, $actionType, $passwordLength, $mustChangePassword, $serverName, $shouldVerify)
        
        Import-Module ActiveDirectory -ErrorAction Stop
        
        try {
            switch ($actionType) {
                "1" {
                    # Generate simpler password with letters, numbers, and .#@
                    function New-SimplePassword {
                        param([int]$Length = 12)
                        
                        $letters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
                        $numbers = '0123456789'
                        $specials = '.#@'
                        $allChars = $letters + $numbers + $specials
                        
                        $password = ""
                        
                        # Ensure at least one of each type
                        $password += $letters[(Get-Random -Minimum 0 -Maximum $letters.Length)]
                        $password += $letters.ToUpper()[(Get-Random -Minimum 0 -Maximum 26)]
                        $password += $numbers[(Get-Random -Minimum 0 -Maximum $numbers.Length)]
                        $password += $specials[(Get-Random -Minimum 0 -Maximum $specials.Length)]
                        
                        # Fill the rest randomly
                        for ($i = $password.Length; $i -lt $Length; $i++) {
                            $password += $allChars[(Get-Random -Minimum 0 -Maximum $allChars.Length)]
                        }
                        
                        # Shuffle the password
                        $passwordArray = $password.ToCharArray()
                        $shuffled = $passwordArray | Get-Random -Count $passwordArray.Length
                        return -join $shuffled
                    }
                    
                    $newPassword = New-SimplePassword -Length $passwordLength
                    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
                    
                    # Reset password
                    Set-ADAccountPassword $user -Reset -NewPassword $securePassword -ErrorAction Stop
                    
                    # Unlock account
                    Unlock-ADAccount $user -ErrorAction SilentlyContinue
                    
                    # Set change password at logon flag
                    Set-ADUser $user -ChangePasswordAtLogon $mustChangePassword -ErrorAction Stop
                    
                    # Only test password if requested
                    $testResult = "SKIPPED"
                    if ($shouldVerify) {
                        try {
                            Add-Type -AssemblyName System.DirectoryServices.AccountManagement
                            $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
                            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext($contextType, $serverName)
                            
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
    } -ArgumentList $username, $action, 12, $requireChangeAtLogon, $server, $verifyPassword -ErrorAction Stop
    
} catch {
    Write-Host "[ERROR] Remote execution failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-AuditLog -Action "EXECUTION_FAILED" -TargetUser $username -Server $server -Status "FAILED" -Details $_.Exception.Message
    exit 1
}

# ------------------------------------------
# Display results
# ------------------------------------------
Write-Host "`n===============================" -ForegroundColor Cyan

if ($result.Status -eq "SUCCESS") {
    Write-Host "[OK] SUCCESS" -ForegroundColor Green
    Write-Host "    User       : $username"
    Write-Host "    Server     : $server"
    Write-Host "    Action     : $($result.Action)"
    Write-Host "    Details    : $($result.Message)"
    
    if ($result.Password) {
        Write-Host "`n    NEW PASSWORD: " -ForegroundColor Yellow -NoNewline
        Write-Host $result.Password -ForegroundColor White
        
        # Show password verification status (only if verification was performed)
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
                    Write-Host "    Verification : $($result.PasswordVerification)" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "    Verification : Skipped (not requested)" -ForegroundColor Gray
        }
        
        # Show change password requirement
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
    Write-AuditLog -Action $result.Action -TargetUser $username -Server $server -Status "SUCCESS" -Details $auditDetails
    
} else {
    Write-Host "[X] FAILED" -ForegroundColor Red
    Write-Host "    Error: $($result.Message)"
    Write-AuditLog -Action $result.Action -TargetUser $username -Server $server -Status "FAILED" -Details $result.Message
}

Write-Host "===============================" -ForegroundColor Cyan
Write-Host ""
