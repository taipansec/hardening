function AccountsWithUserRight {
    <#
        .SYNOPSIS
            Gets all accounts that are assigned a specified privilege (modified version)
        .DESCRIPTION
            Retrieves a list of all accounts that hold a specified right (privilege). The accounts returned are those that hold the specified privilege directly through the user account, not as part of membership to a group.
        .EXAMPLE
            Get-AccountsWithUserRight SeServiceLogonRight
         .EXAMPLE
            Get-AccountsWithUserRight -Right SeServiceLogonRight,SeDebugPrivilege -Computer TESTPC
         .PARAMETER Right
            Name of the right to query. More than one right may be listed.
 
            Possible values:
                SeTrustedCredManAccessPrivilege Access Credential Manager as a trusted caller
                SeNetworkLogonRight Access this computer from the network
                SeTcbPrivilege Act as part of the operating system
                SeMachineAccountPrivilege Add workstations to domain
                SeIncreaseQuotaPrivilege Adjust memory quotas for a process
                SeInteractiveLogonRight Allow log on locally
                SeRemoteInteractiveLogonRight Allow log on through Remote Desktop Services
                SeBackupPrivilege Back up files and directories
                SeChangeNotifyPrivilege Bypass traverse checking
                SeSystemtimePrivilege Change the system time
                SeTimeZonePrivilege Change the time zone
                SeCreatePagefilePrivilege Create a pagefile
                SeCreateTokenPrivilege Create a token object
                SeCreateGlobalPrivilege Create global objects
                SeCreatePermanentPrivilege Create permanent shared objects
                SeCreateSymbolicLinkPrivilege Create symbolic links
                SeDebugPrivilege Debug programs
                SeDenyNetworkLogonRight Deny access this computer from the network
                SeDenyBatchLogonRight Deny log on as a batch job
                SeDenyServiceLogonRight Deny log on as a service
                SeDenyInteractiveLogonRight Deny log on locally
                SeDenyRemoteInteractiveLogonRight Deny log on through Remote Desktop Services
                SeEnableDelegationPrivilege Enable computer and user accounts to be trusted for delegation
                SeRemoteShutdownPrivilege Force shutdown from a remote system
                SeAuditPrivilege Generate security audits
                SeImpersonatePrivilege Impersonate a client after authentication
                SeIncreaseWorkingSetPrivilege Increase a process working set
                SeIncreaseBasePriorityPrivilege Increase scheduling priority
                SeLoadDriverPrivilege Load and unload device drivers
                SeLockMemoryPrivilege Lock pages in memory
                SeBatchLogonRight Log on as a batch job
                SeServiceLogonRight Log on as a service
                SeSecurityPrivilege Manage auditing and security log
                SeRelabelPrivilege Modify an object label
                SeSystemEnvironmentPrivilege Modify firmware environment values
                SeManageVolumePrivilege Perform volume maintenance tasks
                SeProfileSingleProcessPrivilege Profile single process
                SeSystemProfilePrivilege Profile system performance
                SeUnsolicitedInputPrivilege "Read unsolicited input from a terminal device"
                SeUndockPrivilege Remove computer from docking station
                SeAssignPrimaryTokenPrivilege Replace a process level token
                SeRestorePrivilege Restore files and directories
                SeShutdownPrivilege Shut down the system
                SeSyncAgentPrivilege Synchronize directory service data
                SeTakeOwnershipPrivilege Take ownership of files or other objects
        .PARAMETER Computer
            Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
    #>
    param (
        [Parameter(Mandatory=$true)][Alias('Privilege')][PS_LSA.Rights[]]$Right,
        [Parameter(Mandatory=$false)][Alias('System','ComputerName','Host')][String]$Computer
    )

    $lsa = New-Object PS_LSA.LsaWrapper($Computer)
    foreach ($Priv in $Right) {
        Write-Output $lsa.EnumerateAccountsWithUserRight($Priv)
    }
}

Function Pass {
    Write-Output 'The current setting meets the CIS requirements' `r

    [void]$true
}

Function Failed {
    Param (
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$field
    )
    
    if ($field -eq "") { $field = "Empty setting" }
    Write-Host "Currently set to: " -NoNewline
    Write-Host $field -ForegroundColor Red
    Write-Output "The policy doesn't meet CIS the requirements" `r

    [void]$false
}

Function Checker {
    Param (
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$field,
        [Parameter(Mandatory=$true)][string]$op,
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$req
    )

    # Need to code char conditions (eqc) - must be check, maybe a bug or something else
    switch($op) {
        "lt" {
                if ([int]$field -lt $req) {
                    Pass
                } else { Failed $field }
             }
        "le" {
                if ([int]$field -le $req) {
                    Pass
                } else { Failed $field }
             }
        "gt" {
                if ([int]$field -gt $req) {
                    Pass
                } else { Failed $field }
             }
        "ge" {
                if ([int]$field -ge $req) {
                    Pass
                } else { Failed $field }
             }
        "eq" {
                if ([int]$field -eq $req) {
                    Pass
                } else { Failed $field }
             }
        "ne" {
                if ([int]$field -ne $req) {
                    Pass
                } else { Failed $field }
             }
        "bool" {
                if ($field -eq $req) {
                    Pass
                } else { Failed $field }
            }
        "eqc" {
                if ($field -eq $req) {
                    Pass
                } else { Failed $field }
             }
        "match" {
                if ($field -match $req) {
                    Pass
                } else { Failed $field }
             }
    }
}

Function AccountPolicies {
    $PasswordPolicy = (Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue)

    Write-Host "##########################################" -ForegroundColor Yellow `r
    Write-Host "ACCOUNT POLICIES CHAPTER - Password Policy" -ForegroundColor Yellow
    Write-Host "##########################################" -ForegroundColor Yellow `r`n
    
    Write-Host "1.1.1 (L1) Ensure 'Enforce password history' is set to '24 or more password(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.PasswordHistoryCount.ToString() 'ge' 24

    Write-Host "1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0'" -ForegroundColor Green
    $mpa = (Checker $PasswordPolicy.MaxPasswordAge.Days 'le' 60)
    if ($mpa -eq 'True') {
        Checker $PasswordPolicy.MaxPasswordAge.Days 'ne' 0
    } else { $mpa }

    Write-Host "1.1.3 (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.MinPasswordAge.Days 'ge' 1

    Write-Host "1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.MinPasswordLength 'ge' 14

    Write-Host "1.1.5 (L1) Ensure 'Password must meet complexity requirements' is set to 'Enabled'" -ForegroundColor Green
    Checker $PasswordPolicy.ComplexityEnabled.ToString() 'bool' 'True'

    Write-Host "1.1.6 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'" -ForegroundColor Green
    Checker $PasswordPolicy.ReversibleEncryptionEnabled 'bool' 'False'


    Write-Host "#################################################" -ForegroundColor Yellow `r
    Write-Host "ACCOUNT POLICIES CHAPTER - Account Lockout Policy" -ForegroundColor Yellow
    Write-Host "#################################################" -ForegroundColor Yellow `r`n

    Write-Host "1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.LockoutDuration.Minutes 'ge' 15

    Write-Host "1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0'" -ForegroundColor Green
    $lt = (Checker $PasswordPolicy.LockoutThreshold 'le' 10)
    if ($lt -eq 'True') {
        Checker $PasswordPolicy.LockoutThreshold 'ne' 0
    } else { $lt }

    Write-Host "1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.LockoutObservationWindow.Minutes 'ge' 15
}

Function LocalPolicies {
    Write-Host "################################################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER - User Rights Assignement" -ForegroundColor Yellow
    Write-Host "################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -ForegroundColor Green
    $acmtc = AccountsWithUserRight SeTrustedCredManAccessPrivilege
    Checker $acmtc 'eqc' $null
    
    Write-Host "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'" -ForegroundColor Green
    $apos = AccountsWithUserRight SeTcbPrivilege
    Checker $apos 'eqc' $null

    Write-Host "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$amqp = AccountsWithUserRight SeIncreaseQuotaPrivilege
    # EN version
    # Checker $amqp 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"
    # FR version
    Checker $amqp 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE RÉSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'" -ForegroundColor Green
    [string]$alla = AccountsWithUserRight SeInteractiveLogonRight
    # EN version
    # Checker $alla 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $alla 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$bfd = AccountsWithUserRight SeBackupPrivilege
    # EN version
    # Checker $bfd 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $bfd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$cst = AccountsWithUserRight SeSystemtimePrivilege
    # EN version
    # Checker $cst 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE"
    # FR version
    Checker $cst 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$clt = AccountsWithUserRight SeTimeZonePrivilege
    # EN version
    # Checker $clt 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE"
    # FR version
    Checker $clt 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'" -ForegroundColor Green
    [string]$cp = AccountsWithUserRight SeCreatePagefilePrivilege
    # EN version
    # Checker $cp 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $cp 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'" -ForegroundColor Green
    [string]$cto = AccountsWithUserRight SeCreateTokenPrivilege
    # EN version
    # Checker $cto 'eqc' $null
    # FR version
    Checker $cto 'eqc' $null

    Write-Host "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Green
    [string]$cgp = AccountsWithUserRight SeCreateGlobalPrivilege
    # EN version
    # Checker $cgp 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE NT AUTHORITY\SERVICE"
    # FR version
    Checker $cgp 'eqc' "AUTORITE NT\SERVICE BUILTIN\Administrateurs AUTORITE NT\SERVICE RÉSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'" -ForegroundColor Green
    [string]$cpso = AccountsWithUserRight SeCreatePermanentPrivilege
    # EN version
    # Checker $cgp 'eqc' $null
    # FR version
    Checker $cpso 'eqc' $null

    Write-Host "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'" -ForegroundColor Green
    [string]$dpa = AccountsWithUserRight SeDebugPrivilege
    # EN version
    # Checker $cgp 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $dpa 'eqc' "BUILTIN\Administrateurs"
    
    Write-Host "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    [string]$dlbj = AccountsWithUserRight SeDenyBatchLogonRight
    # EN version
    # Checker $dlbj 'match' "Guests"
    # FR version
    Checker $dlbj 'match' "Invités"

    Write-Host "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'" -ForegroundColor Green
    [string]$dls = AccountsWithUserRight SeDenyServiceLogonRight
    # EN version
    # Checker $dls 'match' "Guests"
    # FR version
    Checker $dls 'match' "Invités"

    Write-Host "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'" -ForegroundColor Green
    [string]$dll = AccountsWithUserRight SeDenyInteractiveLogonRight
    # EN version
    # Checker $dll 'match' "Guests"
    # FR version
    Checker $dll 'match' "Invités"
}

AccountPolicies
LocalPolicies

# Not finished...
