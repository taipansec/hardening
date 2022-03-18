Function Pass {
    Write-Output 'The current setting meets the CIS requirements' `r

    [void]$true
}

Function Failed {
    Param (
        [Parameter(Mandatory=$true)][string]$field
    )
    
    Write-Host "Currently set to: " -NoNewline
    Write-Host $field -ForegroundColor Red
    Write-Output "The policy doesn't meet CIS the requirements" `r

    [void]$false
}

Function Checker {
    Param (
        [Parameter(Mandatory=$true)][string]$field,
        [Parameter(Mandatory=$true)][string]$op,
        [Parameter(Mandatory=$true)][string]$req
    )

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
    $localpolicies = (G -ErrorAction SilentlyContinue)

    Write-Host "################################################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER - User Rights Assignement" -ForegroundColor Yellow
    Write-Host "################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -ForegroundColor Green
    Checker $localpolicies.

}

AccountPolicies
LocalPolicies

# Not finished...
