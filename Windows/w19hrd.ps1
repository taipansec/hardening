$p = Get-Location
$tmp = $p.ToString()

$Global:ConfFile = "$tmp\temp.txt"
$Global:DBFile = "$tmp\temp.sdb"
$Global:newConfig = $null

function GetSidType([string] $sidtype, [string] $username, [string] $group) {
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

function GetSec() {
    secedit /export /cfg $Global:ConfFile
}

function SetConf() {
    Set-Content -Path $Global:ConfFile -Value $Global:newConfig
}

function Add-RightToGroup([string] $Group, [string] $Right, [string] $Options) {
    $gid = GetSidType -sidtype "gid" -group "$Group"

    $gids = (Select-String $Global:ConfFile -Pattern "$Right").Line
    Write-Host "Actual config" $gids
    Write-Host "Applying new config..." `r

    $currentConfig = Get-Content $Global:ConfFile

    switch ($Options) {
        "replace" {
            $rpl = $gids -replace '(= .*)', "= *$gid"
            $Global:newConfig = $currentConfig -replace "^$Right .+", "$rpl"
            SetConf
        }
        "add" {
            $rpl = $gids+",*$gid"
            $Global:newConfig = $currentConfig -replace "^$Right .+", "$rpl"
            SetConf
        }
        "new" {
            $rpl = "*$gid"
            $currentConfig[100] += "`r`n$Right = "+"*$gid"
            $Global:newConfig = $currentConfig
            SetConf
        }
        Default { Write-Host "Wrong Option for Add-RightToGroup" -ForegroundColor Red; Break}
    }
}

function Up-NewConf([string] $rmtmp) {
    Write-Host "Importing new policy on temp database" -ForegroundColor White
    secedit /import /db $Global:DBFile /overwrite /cfg $Global:ConfFile /quiet

    Write-Host "Applying new policy to machine" -ForegroundColor White
    secedit /configure /db $Global:DBFile /cfg $Global:ConfFile

    Write-Host "Updating policy" -ForegroundColor White `r
    gpupdate /force

    Remove-Item $rmtmp -ea 0
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
    Add-RightToGroup -Group 'Invités' -Right 'SeDenyBatchLogonRight' -Options "new"
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
$removable = $args[1]

Write-Host "Getting current policy" -ForegroundColor Yellow `r
GetSec
SetAccountPolicies $identity
SetLocalPolicies
Up-NewConf -rmtmp $removable