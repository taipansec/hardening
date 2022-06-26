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

function GetSec {
    secedit /export /cfg $Global:ConfFile
}

function SetConf {
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

function Up-NewConf {
    Write-Host "Importing new policy on temp database" -ForegroundColor White
    secedit /import /db $Global:DBFile /overwrite /cfg $Global:ConfFile /quiet

    Write-Host "Applying new policy to machine" -ForegroundColor White
    secedit /configure /db $Global:DBFile /cfg $Global:ConfFile

    Write-Host "Updating policy" -ForegroundColor White `r
    gpupdate /force
}

function Remove-tmp([string] $rmtmp) {
    Remove-Item $rmtmp -ea 0
}

function CIS-NetworkAccess {
    Write-Host "Setting 'Microsoft network Client: Digitally sign communications (always)' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanmanWorkstation\\Parameters\\RequireSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature=4,1"

    Write-Host "Setting 'Microsoft network Server: Digitally sign communications (always)' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanManServer\\Parameters\\RequireSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1"

    Write-Host "Setting 'Microsoft network Server: Digitally sign communications (if client agrees)' 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\LanManServer\\Parameters\\EnableSecuritySignature=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1"

    Write-Host "Setting 'Network access: Shares that can be accessed anonymously' to 'None'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares=7,None" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\LanManServer\\Parameters\\)'

    Write-Host "Setting 'Access this computer from the network' to 'Administrators, Authenticated Users'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeNetworkLogonRight' -Options "replace"
    Set-Policy -Group 'Utilisateurs authentifiés' -Key 'SeNetworkLogonRight' -Options "add"

    Write-Host "Setting 'Microsoft network server: Server SPN target name validation level' to 'Accept if provided by client' or higher" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\LanManServer\Parameters\SmbServerNameHardeningLevel=4,2" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\LanManServer\\)'

    Write-Host "Setting 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous=).*" -Options "replaceitem" -Pattern "MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous=4,1"

    Write-Host "Setting 'Network access: Restrict clients allowed to make remote calls to SAM' to 'Administrators: Remote Access: Allow'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Control\Lsa\RestrictRemoteSAM=1,O:BAG:BAD:(A;;RC;;;BA)" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentControlSet\\Control\\Lsa\\)'

    Write-Host "Setting 'Network access: Allow anonymous SID/Name translation' to 'disabled'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Control\Lsa\TurnOffAnonymousBlock=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentControlSet\\Control\\Lsa\\)'

    Write-Host "Setting ''Network access: Named Pipes that can be accessed anonymously' to 'null'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes=7," -Options "newreg" -Pattern '^MACHINE.*(\\Services\\LanManServer\\Parameters)'
}

function CIS-NetworkSecurity {
    Write-Host "Setting 'Network security: Allow Local System to use computer identity for NTLM' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Control\Lsa\UseMachineId=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\)'

    Write-Host "Setting 'Network security: Allow LocalSystem NULL session fallback' to 'Disabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0\AllowNullSessionFallback=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\Control\\Lsa\\MSV1_0\\)'

    Write-Host "Setting 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' to 'Disabled'" -ForegroundColor Green
    $pku2ukey = Test-Path "HKLM:\System\CurrentControlSet\Control\Lsa\PKU2U"
    if (!$pku2ukey) {
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
}

function CIS-SecurityOptions {
    Write-Host "Setting 'Interactive logon: Do not display last user name' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\DontDisplayLastUsername=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUsername=4,1"

    Write-Host "Setting 'Interactive logon: Machine inactivity limit' to '900 or fewer second(s), but not 0'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs=4,900" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'
}

function CIS-Accounts {
    Write-Host "Setting 'Accounts: Block Microsoft accounts' to 'Users can't add or log on with Microsoft accounts'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser=4,3" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'

    Write-Host "Setting 'User Account Control: Admin Approval Mode for the Built-in Administrator account' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Policies\\System\\)'

    Write-Host "Setting 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' to 'Prompt for consent on the secure desktop'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorAdmin=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin=4,2"

    Write-Host "Setting 'User Account Control: Behavior of the elevation prompt for standard users' to 'Automatically deny elevation requests'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\ConsentPromptBehaviorUser=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser=4,0"

    Write-Host "Setting 'User Account Control: Run all administrators in Admin Approval Mode' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\CurrentVersion\\Policies\\System\\EnableLUA=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA=4,1"

    Write-Host "Setting 'Accounts: Administrator account status' to 'Disabled'" -ForegroundColor Green
    Set-Policy -Key "EnableAdminAccount =.*" -Options "replaceitem" -Pattern "EnableAdminAccount = 0"
}

function CIS-SettingDCOnly {
    Write-Host "Setting 'Change the time zone' to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeTimeZonePrivilege' -Options "replace"
    Set-Policy -Group 'SERVICE LOCAL' -Key 'SeTimeZonePrivilege' -Options "add"

    Write-Host "Setting 'Add workstations to domain' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeMachineAccountPrivilege' -Options "replace"

    Write-Host "Setting 'Enable computer and user accounts to be trusted for delegation' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeEnableDelegationPrivilege' -Options "replace"

    Write-Host "Setting 'Impersonate a client after authentication' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeImpersonatePrivilege' -Options "replace"
}

function CIS-LogonSpecific {
    Write-Host "Setting 'Allow log on through Remote Desktop Services' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeRemoteInteractiveLogonRight' -Options "replace"

    Write-Host "Setting 'Deny access to this computer from the network' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyNetworkLogonRight' -Options "new"

    Write-Host "Setting 'Deny log on through Remote Desktop Services' to 'Guests, Local account'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyRemoteInteractiveLogonRight' -Options "new"

    Write-Host "Setting 'Allow log on locally' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeInteractiveLogonRight' -Options "replace"

    Write-Host "Setting 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyBatchLogonRight' -Options "new"

    Write-Host "Setting 'Deny log on as a service' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyServiceLogonRight' -Options "new"

    Write-Host "Setting 'Deny log on locally' to include 'Guests'" -ForegroundColor Green
    Set-Policy -Group 'Invités' -Key 'SeDenyInteractiveLogonRight' -Options "new"

    Write-Host "Setting 'Interactive logon: Require Domain Controller Authentication to unlock workstation' to 'Enabled'" -ForegroundColor Green
    Set-Policy -Key "MACHINE.*(\\Windows NT\\CurrentVersion\\Winlogon\\ForceUnlockLogon=).*" -Options "replaceitem" -Pattern "MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ForceUnlockLogon=4,1"

    Write-Host "Setting 'Interactive logon: Smart card removal behavior' to 'Lock Workstation or higher'" -ForegroundColor Green
    Set-Policy -Key '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption="1"' -Options "newreg" -Pattern '^MACHINE.*(\\CurrentVersion\\Winlogon\\)'
}

function CIS-DCSpecific {
    Write-Host "Setting 'Domain Controller: Allow server operators to schedule tasks' to 'disabled'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Control\Lsa\SubmitControl=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentControlSet\\Control\\Lsa\\)'

    Write-Host "Setting 'Domain controller: LDAP server channel binding token requirements' to 'Always'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\NTDS\\Parameters\\)'

    Write-Host "Setting 'Domain controller: LDAP server signing requirements' to 'Always'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,2" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\NTDS\\Parameters\\)'
    
    Write-Host "Setting 'Domain controller: Refuse machine account password changes' to 'disabled'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange=4,0" -Options "newreg" -Pattern '^MACHINE.*(\\Services\\Netlogon\\Parameters\\)'
}

function CIS-Firewall {
    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Firewall state' to 'On'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Inbound connections' to 'Block'" -ForegroundColor Green
    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Outbound connections' to 'Allow'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultInboundAction Block -DefaultOutboundAction Allow

    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Settings: Display a notification' to 'No'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -NotifyOnListen False

    Write-Host "Setting 'Windows Firewall: Public: Settings: Apply local firewall rules' to 'No'" -ForegroundColor Green
    Set-NetFirewallProfile -Public -AllowLocalFirewallRules False

    Write-Host "Setting 'Windows Firewall: Public: Settings: Apply local connection security rules' to 'No'" -ForegroundColor Green
    Set-NetFirewallProfile -Public -AllowLocalIPsecRules False

    Write-Host "Setting 'Windows Firewall: Domain: Logging: Name' to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain -LogFileName %SystemRoot%\System32\LogFiles\Firewall\domainfw.log

    Write-Host "Setting 'Windows Firewall: Private: Logging: Name' to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Private -LogFileName %SystemRoot%\System32\LogFiles\Firewall\privatefw.log

    Write-Host "Setting 'Windows Firewall: Public: Logging: Name' to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Public -LogFileName %SystemRoot%\System32\LogFiles\Firewall\publicfw.log

    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Logging: Size limit(KB)' to '16384 KB'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogMaxSizeKilobytes 16384

    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Logging: Log dropped packets' to 'Yes'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True

    Write-Host "Setting 'Windows Firewall: Domain,Private,Public: Logging: Log successful connections' to 'Yes'" -ForegroundColor Green
    Set-NetFirewallProfile -Profile Domain,Private,Public -LogAllowed True
}

function CIS-AuditLog {
    Write-Host "Setting 'Audit: Force audit policy subcategory settings to override audit policy category settings' to 'enabled'" -ForegroundColor Green
    Set-Policy -Key "\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy=4,1" -Options "newreg" -Pattern '^MACHINE.*(\\CurrentControlSet\\Control\\Lsa\\)'

    Write-Host "Setting 'Audit Credential Validation' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Validation des informations d'identification" /success:enable /failure:enable

    Write-Host "Setting 'Audit Kerberos Authentication Service' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Service d'authentification Kerberos" /success:enable /failure:enable

    Write-Host "Setting 'Audit Kerberos Service Ticket Operations' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Opérations de ticket du service Kerberos" /success:enable /failure:enable

    Write-Host "Setting 'Audit Application Group Management' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Gestion des groupes d'applications" /success:enable /failure:enable

    Write-Host "Setting 'Audit Computer Account Management' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Gestion des comptes d'ordinateur" /success:enable

    Write-Host "Setting 'Audit Distribution Group Management' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Gestion des groupes de distribution" /success:enable

    Write-Host "Setting 'Audit Other Account Management Events' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Autres événements de gestion des comptes" /success:enable

    Write-Host "Setting 'Audit Security Group Management' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Gestion des groupes de sécurité" /success:enable

    Write-Host "Setting 'Audit User Account Management' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Gestion des comptes d'utilisateur" /success:enable /failure:enable

    Write-Host "Setting 'Audit PNP Activity' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"événements Plug-and-Play" /success:enable

    Write-Host "Setting 'Audit Process Creation' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Création du processus" /success:enable

    Write-Host "Setting 'Audit Directory Service Access' to 'Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Accès au service d'annuaire" /failure:enable

    Write-Host "Setting 'Audit Directory Service Changes' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification du service d'annuaire" /success:enable

    Write-Host "Setting 'Audit Account Lockout' to 'Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Verrouillage du compte" /failure:enable

    Write-Host "Setting 'Audit Group Membership' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Appartenance à un groupe" /success:enable

    Write-Host "Setting 'Audit Logoff' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Fermer la session" /success:enable

    Write-Host "Setting 'Audit Logon' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Ouvrir la session" /success:enable /failure:enable

    Write-Host "Setting 'Audit Other Logon/Logoff Events' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Autres événements d'ouverture/fermeture de session" /success:enable /failure:enable

    Write-Host "Setting 'Audit Special Logon' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Ouverture de session spéciale" /success:enable

    Write-Host "Setting 'Audit Detailed File Share' to 'Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Partage de fichiers détaillé" /failure:enable

    Write-Host "Setting 'Audit File Share' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Partage de fichiers" /success:enable /failure:enable

    Write-Host "Setting 'Audit Other Object Access Events' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Autres événements d'accès à l'objet" /success:enable /failure:enable

    Write-Host "Setting 'Audit Removable Storage' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Stockage amovible" /success:enable /failure:enable

    Write-Host "Setting 'Audit Audit Policy Change' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification de la stratégie d'audit" /success:enable

    Write-Host "Setting 'Audit Authentication Policy Change' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification de la stratégie d'authentification" /success:enable

    Write-Host "Setting 'Audit Authorization Policy Change' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification de la stratégie d'autorisation" /success:enable

    Write-Host "Setting 'Audit MPSSVC Rule-Level Policy Change' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification de la stratégie de niveau règle MPSSVC" /success:enable /failure:enable

    Write-Host "Setting 'Audit Ohter Policy Change Events' to 'Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Autres événements de modification de stratégie" /failure:enable

    Write-Host "Setting 'Audit Sensitive Privilege Use' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Utilisation de privilèges sensibles" /success:enable /failure:enable

    Write-Host "Setting 'Audit IPsec Driver' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Pilote IPSEC" /success:enable /failure:enable

    Write-Host "Setting 'Audit Other System Events' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Autres événements système" /success:enable /failure:enable

    Write-Host "Setting 'Audit Security State Change' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Modification de l'état de la sécurité" /success:enable

    Write-Host "Setting 'Audit Security System Extension' to 'Success'" -ForegroundColor Green
    auditpol /set /subcategory:"Extension système de sécurité" /success:enable

    Write-Host "Setting 'Audit System Integrity' to 'Success and Failure'" -ForegroundColor Green
    auditpol /set /subcategory:"Intégrité du système" /success:enable /failure:enable
}

function CIS-GeneralPolicies {
    Write-Host "Setting 'Back up files and directories' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeBackupPrivilege' -Options "replace"

    Write-Host "Setting 'Restore files and directories' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeRestorePrivilege' -Options "replace"

    Write-Host "Setting 'Shut down the system' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Group 'Administrateurs' -Key 'SeShutdownPrivilege' -Options "replace"

    Write-Host "Setting 'Create symbolic links' to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'" -ForegroundColor Green
    Write-Host "Virtual Machines Object doesn't exist" -ForegroundColor Red

    Write-Host "Setting 'Devices: Allowed to format and eject removable media' to 'Administrators'" -ForegroundColor Green
    Set-Policy -Key '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateDASD=1,"0"' -Options "newreg" -Pattern '^MACHINE.*(\\Windows NT\\CurrentVersion\\Winlogon\\)'
}

function SetDomainAccountPolicies {
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

function Backup {
    $exist = Test-Path -Path ./actualconf.txt -PathType Leaf
    if ($exist -eq $true) {
        Write-Host "Backup file already exists" -ForegroundColor Yellow
        $rpl = Read-Host "Replace it? (y/n)"
        if ($rpl -eq "y") {
            secedit /export /cfg actualconf.txt
        } elseif ($rpl -eq "n") {
            exit 0
        }
    } elseif ($backup -eq "n") {
            exit 0
    } else {
        Write-Host "Backing up to actualconf.txt file" -ForegroundColor Yellow
        secedit /export /cfg actualconf.txt
        $conf = Test-Path -Path ./actualconf.txt -PathType Leaf
        if ($conf -eq $true) {
            Write-Host "Current configuration successfully saved" -ForegroundColor Green
        } elseif ($conf -eq $false) {
            Write-Host "Failed to backup actual config... Leaving"
            exit 1
        }
    }
}

function CIS-Help {
    Write-Host "USAGE: script -Options" `r`n
    Write-Host "Available options: script [-DomainAccountPolicies] [-GeneralConfig] [-Audit] [-Firewall] [-DCSecSpecific] [-Logon] [-DCSetting] [-Accounts] [-Security] [-NetworkSec] [-Network] [-All] [-Backup] [-Restore]" `r`n
    Write-Host "-DomainAccountPolicies" -ForegroundColor Yellow
    Write-Host "Bring change to the whole Domain and it's password rules specific- use wisely" `r`n
    Write-Host "-GeneralConfig" -ForegroundColor Yellow
    Write-Host "Safe option - no impact expected" `r`n
    Write-Host "-Audit" -ForegroundColor Yellow
    Write-Host "Apply Audit and log rules on the target" `r`n
    Write-Host "-Firewall" -ForegroundColor Yellow
    Write-Host "Apply Windows firewall rules on the target" `r`n
    Write-Host "-DCSecSpecific" -ForegroundColor Yellow
    Write-Host "Domain Controller rules within the Security Options chapter of the CIS" `r`n
    Write-Host "-Logon" -ForegroundColor Yellow
    Write-Host "Apply logon related rules" `r`n
    Write-Host "-DCSetting" -ForegroundColor Yellow
    Write-Host "Apply general DC specific rules" `r`n
    Write-Host "-Accounts" -ForegroundColor Yellow
    Write-Host "Apply accounts rules" `r`n
    Write-Host "-Security" -ForegroundColor Yellow
    Write-Host "Apply general security rules" `r`n
    Write-Host "-NetworkSec" -ForegroundColor Yellow
    Write-Host "Apply network security rules" `r`n
    Write-Host "-Network" -ForegroundColor Yellow
    Write-Host "Apply network rules" `r`n
    Write-Host "-All" -ForegroundColor Yellow
    Write-Host "Apply everything except whole Domain rules" `r`n
    Write-Host "-Backup" -ForegroundColor Yellow
    Write-Host "Backup the actual configuration and save it to actualconf.txt" `r`n
    Write-Host "-Restore" -ForegroundColor Yellow
    Write-Host "Rollback to the previous saved configuration" `r`n
}

function Selector([string] $option) {
    switch ($option) {
            "-Backup" {
                Backup
            }
            "-Restore" {
                Write-Host "Rollback to the previous configuration." -ForegroundColor Yellow
                $exist = Test-Path -Path ./actualconf.txt -PathType Leaf
                if ($exist -eq $true) {
                    secedit /validate .\actualconf.txt
                    secedit /import /db .\actualconf.db /overwrite /cfg .\actualconf.txt /quiet
                    secedit /configure /db .\actualconf.db /cfg .\actualconf.txt
                    gpupdate /force
                    Write-Host "Successfully rolled back. Leaving..." -ForegroundColor Green
                    exit 0
                } else { Write-Host "Failed to apply backup: actualconf.txt - No such file!"; exit 1}
            }
            "-DomainAccountPolicies" {
                $identity = Read-Host "Specify the domain identity:"
                SetDomainAccountPolicies $identity
            }
            "-GeneralConfig" {
                CIS-GeneralPolicies
            }
            "-Audit" {
                CIS-AuditLog
            }
            "-Firewall" {
                CIS-Firewall
            }
            "-DCSecSpecific" {
                CIS-DCSpecific
            }
            "-Logon" {
                CIS-LogonSpecific
            }
            "-DCSetting" {
                CIS-SettingDCOnly
            }
            "-Accounts" {
                CIS-Accounts
            }
            "-Security" {
                CIS-SecurityOptions
            }
            "-NetworkSec" {
                CIS-NetworkSecurity
            }
            "-Network" {
                CIS-NetworkAccess
            }
            "-All" {
                CIS-GeneralPolicies
                CIS-AuditLog
                CIS-Firewall
                CIS-DCSpecific
                CIS-LogonSpecific
                CIS-SettingDCOnly
                CIS-Accounts
                CIS-SecurityOptions
                CIS-NetworkSecurity
                CIS-NetworkAccess
            }
            "-Backup" {
                Backup
            }
            Default {
                Write-Host "No option specified!" -ForegroundColor Red
                CIS-Help
                exit 1
            }
        }
}

function Harden([string] $selector) {
    $shouldctn = Read-Host "Do you want to continue with system hardening? (y/n)"
        if ($shouldctn -eq "y") {
            Write-Host "Getting current policy" -ForegroundColor Yellow `r
            GetSec
            Selector $selector
            Up-NewConf
            $currentdir = Get-Location
            $removable = [string]$currentdir + "\temp.*"
            Write-Host "Removing temporary files..." -ForegroundColor Yellow
            Remove-tmp -rmtmp $removable
            Write-Host "Done" -ForegroundColor Green
        } else { Write-Host "Leaving..."; exit 0 }
}

if (!$args[0]) {
    CIS-Help
} else { Harden $args[0]}