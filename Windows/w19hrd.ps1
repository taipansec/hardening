function GetSidType([string] $sidtype, $username, $group) {
    if ($sidtype -eq "sid") {
        (Get-WmiObject -Class Win32_UserAccount -Filter "Name = '$username'").SID
    }
    elseif ($sidtype -eq "gid") {
        (Get-WmiObject -Class Win32_Group -Filter "Name = '$group'").SID
    }
    else {
        Write-Host "Wrong parameter" -ForegroundColor Red `r
    }
}

function Add-RightToGroup([string] $Group, $Right, $Options) {
    $tmp = New-TemporaryFile

    $TempConfigFile = "$tmp.inf"
    $TempDbFile = "$tmp.sdb"

    Write-Host "Getting current policy" -ForegroundColor Yellow `r
    secedit /export /cfg $TempConfigFile

    $gid = GetSidType -sidtype "gid" -group "$Group"

    $gids = (Select-String $TempConfigFile -Pattern "$Right").Line
    Write-Host "Actual config" $gids
    Write-Host "Applying new config..."

    $currentConfig = Get-Content -Encoding ascii $TempConfigFile

    switch ($Options) {
        "replace" {
            $rpl = $gids -replace '(= .*)', "= *$gid"
            $newConfig = $currentConfig -replace "^$Right .+", "$rpl"
        }
        "add" {
            $rpl = $gids+",*$gid"
            $newConfig = $currentConfig -replace "^$Right .+", "$rpl"
        }
        "new" {
            $rpl = "*$gid"
            $currentConfig[100] += "`r`n$Right = "+"*$gid"
            $newConfig = $currentConfig
        }
        Default { Write-Host "Wrong Option for Add-RightToGroup" -ForegroundColor Red; Break}
    }

    Set-Content -Path $TempConfigFile -Value $newConfig

    Write-Host "Importing new policy on temp database" -ForegroundColor White
    secedit /import /db $TempDbFile /overwrite /cfg $TempConfigFile /quiet

    Write-Host "Applying new policy to machine" -ForegroundColor White
    secedit /configure /db $TempDbFile /cfg $TempConfigFile

    Write-Host "Updating policy" -ForegroundColor White `r
    gpupdate /force

    Remove-Item $tmp* -ea 0
}

function Add-RightToUser([string] $Username, $Right) {
    $tmp = New-TemporaryFile

    $TempConfigFile = "$tmp.inf"
    $TempDbFile = "$tmp.sdb"

    Write-Host "Getting current policy" -ForegroundColor Yellow `r
    secedit /export /cfg $TempConfigFile

    $sid = GetSidType "sid" "$username"

    $currentConfig = Get-Content -Encoding ascii $TempConfigFile

    $newConfig = $currentConfig -replace "^$Right .+", "`$0,*$sid"

    Set-Content -Path $TempConfigFile -Encoding ascii -Value $newConfig

    Write-Host "Importing new policy on temp database" -ForegroundColor White
    secedit /import /cfg $TempConfigFile /db $TempDbFile

    Write-Host "Applying new policy to machine" -ForegroundColor White
    secedit /configure /db $TempDbFile /cfg $TempConfigFile

    Write-Host "Updating policy" -ForegroundColor White `r
    gpupdate /force

    Remove-Item $tmp* -ea 0
}

Function SetLocalPolicies {
    Write-Host "################################################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER - User Rights Assignement" -ForegroundColor Yellow
    Write-Host "################################################" -ForegroundColor Yellow `r`n

    Write-Host "Setting 'Allow log on locally' to 'Administrators'" -ForegroundColor Green
    Add-RightToGroup -Group 'Administrateurs' -Right 'SeInteractiveLogonRight' -Options "replace"

    Write-Host "Setting 'Back up files and directories' to 'Administrators'" -ForegroundColor Green
    Add-RightToGroup -Group 'Administrateurs' -Right 'SeBackupPrivilege' -Options "replace"

    Write-Host "Setting 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    Add-RightToGroup -Group 'Invités' -Right 'SeDenyBatchLogonRight' -Options "add"

    Write-Host "Setting 'Deny log on as a service' to include 'Guests'" -ForegroundColor Green
    Add-RightToGroup -Group 'Invités' -Right 'SeDenyServiceLogonRight' -Options "new"
}

Function SetAccountPolicies {
    param (
        [Parameter(Mandatory=$true)][String]$identity
    )

    Write-Host "##########################################" -ForegroundColor Yellow `r
    Write-Host "ACCOUNT POLICIES CHAPTER - Password Policy" -ForegroundColor Yellow
    Write-Host "##########################################" -ForegroundColor Yellow `r`n
    
    Write-Host "Setting Password History Count to 24" -ForegroundColor Green
    Set-ADDefaultDomainPasswordPolicy -Identity $identity -PasswordHistoryCount 24

    Write-Host "Setting Minimum password length to 14" -ForegroundColor Green
    Set-ADDefaultDomainPasswordPolicy -Identity $identity -MinPasswordLength 14
}

$identity = $args[0]

SetAccountPolicies $identity
SetLocalPolicies