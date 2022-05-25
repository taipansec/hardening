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

function Set-Policy([string] $Group, [string] $Key, [string] $Options, [string] $Pattern) {
    $gid = GetSidType -sidtype "gid" -group "$Group"

    if ($Group) {
        $gids = (Select-String $Global:ConfFile -Pattern "$Key").Line
        Write-Host "Actual config" $gids
    }

    Write-Host "Applying new config..." `r

    $currentConfig = Get-Content $Global:ConfFile

    switch ($Options) {
        "replace" {
            $rpl = $gids -replace '(= .*)', "= *$gid"
            $Global:newConfig = $currentConfig -replace "^$Key .+", "$rpl"
            SetConf
        }
        "add" {
            $rpl = $gids+",*$gid"
            $Global:newConfig = $currentConfig -replace "^$Key .+", "$rpl"
            SetConf
        }
        "new" {
            $rpl = "*$gid"
            $currentConfig[120] += "`r`n$Key = "+"*$gid"
            $Global:newConfig = $currentConfig
            SetConf
        }
        "newreg" {
            $first = $true
            [String[]] $ConfModified = @()
            Foreach ($Line in $currentConfig) {
                $ConfModified += $Line
                if ( $Line.Trim() -match $Pattern ) {
                    if ($first) {
                        $ConfModified += $Key
                        $first = $false
                    }
                }
            }
            $Global:newConfig = $ConfModified
            SetConf
        }
        "replaceitem" {
            $Global:newConfig = $currentConfig -replace "^$Key", "$Pattern"
            SetConf
        }
        Default { Write-Host "Wrong Option for Set-Policy" -ForegroundColor Red; Break}
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
    Write-Host "######################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER" -ForegroundColor Yellow
    Write-Host "######################" -ForegroundColor Yellow `r`n

    Write-Host "Setting 'Allow log on locally' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeInteractiveLogonRight' -Options "replace"

    Write-Host "Setting 'Back up files and directories' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeBackupPrivilege' -Options "replace"

    Write-Host "Setting 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyBatchLogonRight' -Options "new"

    Write-Host "Setting 'Deny log on locally' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyInteractiveLogonRight' -Options "new"

    Write-Host "Setting 'Restore files and directories' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeRestorePrivilege' -Options "replace"

    Write-Host "Setting 'Shut down the system' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeShutdownPrivilege' -Options "replace"

    Write-Host "Setting 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=4,3" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'

    Write-Host "Setting 'Interactive logon: Don't display last signed-in' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\DontDisplayLastUsername=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUsername=4,1"

    Write-Host "Setting 'Interactive logon: Machine inactivity limit' to '900 or fewer second(s), but not 0'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'

    Write-Host "Setting 'Microsoft network Client: Digitally sign communications (always)' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1"

    Write-Host "Setting 'Microsoft network Server: Digitally sign communications (always)' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanManServer\\Parameters\\RequireSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1"

    Write-Host "Setting 'Microsoft network Server: Digitally sign communications (if client agrees)' 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanManServer\\Parameters\\EnableSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1"

    Write-Host "Setting 'Network access: Shares that can be accessed anonymously' to 'None'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,None" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\LanManServer\\Parameters\\)'

    Write-Host "Setting 'Network security: Allow Local System to use computer identity for NTLM' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\)'

    Write-Host "Setting 'Network security: Allow LocalSystem NULL session fallback' to 'Disabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AllowNullSessionFallback=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\MSV1_0\\)'

    Write-Host "Setting 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' to 'Disabled'" -ForegroundColor Green
    $keyexist = Test-Path "HKLM:\System\CurrentControlSet\Control\Lsa\PKU2U"
    if (!$keyexist) {
        New-Item –Path "HKLM:\System\CurrentControlSet\Control\Lsa\" –Name PKU2U
    }
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Control\Lsa\PKU2U\AllowOnlineID=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\MSV1_0\\)'

    Write-Host "Setting 'Network security: Configure encryption types allowed for Kerberos' to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'" -ForegroundColor Green
    $kerbkey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos"
    $paramkey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    If (!$kerbkey -and !$paramkey) {
        New-Item –Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" –Name Kerberos
        New-Item –Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\" –Name Parameters
    }
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes=4,2147483632" -Options "newreg" -Pattern '^MACHINE.*(\\Windows NT\\CurrentVersion\\Winlogon\\)'

    Write-Host "Setting 'Network security: Force logoff when logon hours expire' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "ForceLogoffWhenHourExpire =.*" -Options "replaceitem" -Pattern "ForceLogoffWhenHourExpire = 1"
    
    Write-Host "Setting 'Network security: Minimum session security for NTLM SSP based (including secure RPC) Clients' to 'Require NTLMv2 session security, Require 128-bit encryption'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\Control\\Lsa\\MSV1_0\\NTLMMinClientSec=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinClientSec=4,537395200"

    Write-Host "Setting 'Network security: Minimum session security for NTLM SSP based (including secure RPC) Servers' to 'Require NTLMv2 session security, Require 128-bit encryption'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\Control\\Lsa\\MSV1_0\\NTLMMinServerSec=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\NTLMMinServerSec=4,537395200"

    Write-Host "Setting 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'

    Write-Host "Setting 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent on the secure desktop'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2"

    Write-Host "Setting 'User Account Control: Behavior of the elevation prompt for standard users' to 'Automatically deny elevation requests'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0"

    Write-Host "Setting 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\EnableLUA=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1"

    Write-Host "Setting 'User Account Control: Switch to the secure desktop when prompting for elevation' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\PromptOnSecureDesktop=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop=4,1"


    Write-Host "##################" -ForegroundColor Yellow `r
    Write-Host "AD MEMBERS CHAPTER" -ForegroundColor Yellow
    Write-Host "##################" -ForegroundColor Yellow `r`n

    Write-Host "Setting 'Access this computer from the network' to 'Administrators, Authenticated Users'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeNetworkLogonRight' -Options "replace"
    Set-Policy -Group 'Utilisateurs authentifiés' -Key 'SeNetworkLogonRight' -Options "add"

    Write-Host "Setting 'Create symbolic links' to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'" -ForegroundColor Green
    Write-Host "Virtual Machines Object doesn't exist" -ForegroundColor Red

    Write-Host "Setting 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyNetworkLogonRight' -Options "new"
    Set-Policy -Group 'Compte local' -Key 'SeDenyNetworkLogonRight' -Options "add"
    Set-Policy -Group 'Compte local et membre du groupe Administrateurs' -Key 'SeDenyNetworkLogonRight' -Options "add"

    Write-Host "Setting 'Deny log on through Remote Desktop Services' to 'Guests, Local account'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyRemoteInteractiveLogonRight' -Options "new"
    Set-Policy -Group 'Compte local' -Key 'SeDenyRemoteInteractiveLogonRight' -Options "add"

    Write-Host "Setting 'Accounts: Administrator account status' to 'Disabled'" -ForegroundColor Green
    Set-Policy -Key "EnableAdminAccount =.*" -Options "replaceitem" -Pattern "EnableAdminAccount = 0"

    Write-Host "Setting 'Interactive logon: Require Domain Controller Authentication to unlock workstation' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Winlogon\\ForceUnlockLogon=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,1"

    Write-Host "Setting 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client' or higher" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,2" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\LanManServer\\)'

    Write-Host "Setting 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\Control\\Lsa\\RestrictAnonymous=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1"

    Write-Host "Setting 'Network access: Restrict clients allowed to make remote calls to SAM' to 'Administrators: Remote Access: Allow'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,O:BAG:BAD:(A;;RC;;;BA)" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\)'
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

# $identity = $args[0]
$removable = $args[1]

Write-Host "Getting current policy" -ForegroundColor Yellow `r
GetSec
# SetAccountPolicies $identity
SetLocalPolicies
Up-NewConf -rmtmp $removable