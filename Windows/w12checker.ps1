# Some lines are from POSHSPEC 2.2.8 https://www.powershellgallery.com/packages/poshspec/2.2.8/Content/Public%5CSecurityOption.ps1.
Add-Type @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;
 
    public enum Rights
    {
        SeTrustedCredManAccessPrivilege, // Access Credential Manager as a trusted caller
        SeNetworkLogonRight, // Access this computer from the network
        SeTcbPrivilege, // Act as part of the operating system
        SeMachineAccountPrivilege, // Add workstations to domain
        SeIncreaseQuotaPrivilege, // Adjust memory quotas for a process
        SeInteractiveLogonRight, // Allow log on locally
        SeRemoteInteractiveLogonRight, // Allow log on through Remote Desktop Services
        SeBackupPrivilege, // Back up files and directories
        SeChangeNotifyPrivilege, // Bypass traverse checking
        SeSystemtimePrivilege, // Change the system time
        SeTimeZonePrivilege, // Change the time zone
        SeCreatePagefilePrivilege, // Create a pagefile
        SeCreateTokenPrivilege, // Create a token object
        SeCreateGlobalPrivilege, // Create global objects
        SeCreatePermanentPrivilege, // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege, // Create symbolic links
        SeDebugPrivilege, // Debug programs
        SeDenyNetworkLogonRight, // Deny access this computer from the network
        SeDenyBatchLogonRight, // Deny log on as a batch job
        SeDenyServiceLogonRight, // Deny log on as a service
        SeDenyInteractiveLogonRight, // Deny log on locally
        SeDenyRemoteInteractiveLogonRight, // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege, // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege, // Force shutdown from a remote system
        SeAuditPrivilege, // Generate security audits
        SeImpersonatePrivilege, // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege, // Increase a process working set
        SeIncreaseBasePriorityPrivilege, // Increase scheduling priority
        SeLoadDriverPrivilege, // Load and unload device drivers
        SeLockMemoryPrivilege, // Lock pages in memory
        SeBatchLogonRight, // Log on as a batch job
        SeServiceLogonRight, // Log on as a service
        SeSecurityPrivilege, // Manage auditing and security log
        SeRelabelPrivilege, // Modify an object label
        SeSystemEnvironmentPrivilege, // Modify firmware environment values
        SeManageVolumePrivilege, // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege, // Profile single process
        SeSystemProfilePrivilege, // Profile system performance
        SeUnsolicitedInputPrivilege, // "Read unsolicited input from a terminal device"
        SeUndockPrivilege, // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege, // Replace a process level token
        SeRestorePrivilege, // Restore files and directories
        SeShutdownPrivilege, // Shut down the system
        SeSyncAgentPrivilege, // Synchronize directory service data
        SeTakeOwnershipPrivilege // Take ownership of files or other objects
    }
 
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }
 
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }
 
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }
 
    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );
 
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );
 
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true), SuppressUnmanagedCodeSecurityAttribute]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );
 
        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);
 
        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);
 
        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }
 
    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;
 
        public Sid(string account)
        {
            sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier));
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);
 
            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }
 
        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }
 
    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;
 
        IntPtr lsaHandle;
 
        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }
 
            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }
 
        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;
 
            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null; // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }
 
        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;
 
            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));
 
                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null; // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }
 
        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }
 
        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
 
    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }
 
        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
 
        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );
 
            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();
 
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );
 
            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );
 
            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }
    }
}
'@


################# BANNER ##################
### https://github.com/stknohg/PSBanner ###
############# Modified Version ############

function Get-FontFamilies {
    return (New-Object "System.Drawing.Text.InstalledFontCollection").Families
}

function Write-Banner {
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ValueFromRemainingArguments = $true)]
        [psobject]$InputObject,
        [Alias("f")]
        [Parameter(Mandatory = $false)]
        [string]$FontName = "Consolas",
        [Alias("s")]
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100)]
        [int]$FontSize = 10,
        [Parameter(Mandatory = $false)]
        [switch]$Bold = $false,
        [Parameter(Mandatory = $false)]
        [switch]$Italic = $false,
        [Parameter(Mandatory = $false)]
        [switch]$Strikeout = $false,
        [Parameter(Mandatory = $false)]
        [switch]$Underline = $false,
        [Parameter(Mandatory = $false)]
        [switch]$Stream = $false
    )
    
    $installedFonts = Get-FontFamilies
    if ($installedFonts -notcontains $FontName) {
        throw "FontName `"$FontName`" is not installed."
    }

    try {
        $message = ""
        foreach ($object in $InputObject) {
            if ($message -ne "") {
                $message += " "
            }
            if (Get-Member -InputObject $object -MemberType Properties -Name Name) {
                $message += $object.Name
            } else {
                $message += $object.ToString()
            }
        }
        
        $fontStyle = [System.Drawing.FontStyle]::Regular
        if ($Bold) {
            $fontStyle += [System.Drawing.FontStyle]::Bold
        }
        if ($Italic) {
            $fontStyle += [System.Drawing.FontStyle]::Italic
        }
        if ($Strikeout) {
            $fontStyle += [System.Drawing.FontStyle]::Strikeout
        } 
        if ($Underline) {
            $fontStyle += [System.Drawing.FontStyle]::Underline
        } 
        $font = New-Object "System.Drawing.Font" -ArgumentList @($FontName, $FontSize, $fontStyle)
        
        $brush = New-Object "System.Drawing.SolidBrush" -ArgumentList @([System.Drawing.Color]::White)
        $format = New-Object "System.Drawing.StringFormat" -ArgumentList @([System.Drawing.StringFormat]::GenericTypographic)
        $bitmap = New-Object "System.Drawing.Bitmap" -ArgumentList @(1, 1)
        $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
        $measuredSize = $graphic.MeasureString($message, $font, (New-Object "System.Drawing.PointF" -ArgumentList @(0, 0)), $format)
        $bitmap = New-Object "System.Drawing.Bitmap" -ArgumentList @([int]$measuredSize.Width, [int]$measuredSize.Height)
        $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
        $graphic.DrawString($message, $font, $brush , 0, 0, $format)
        # for debug
        #$bitmap.Save("$env:TEMP\banner.png", [System.Drawing.Imaging.ImageFormat]::Png)

        $screenWidth = $Host.UI.RawUI.BufferSize.Width
        $trimWidth = $bitmap.Width
        if ($trimWidth -gt $screenWidth) {
            $trimWidth = $screenWidth
        }
        $line = ""
        for ($y = 0; $y -lt $bitmap.Height; $y++) {
            if ($Stream) {
                $line = ""
            }
            for ($x = 0; $x -lt $trimWidth; $x++) {
                $p = $bitmap.GetPixel($x, $y)
                if ($p.R -eq 0 -and $p.G -eq 0 -and $p.B -eq 0) {
                    $line += " "
                } else {
                    $line += "#"
                }
            }
            if ($Stream) {
                Write-Output $line
            } else {
                $line += [System.Environment]::NewLine
            }
        }
        if (-not $Stream) {
            Write-Output $line
        }
    } finally {
        $brush.Dispose()
        $format.Dispose()
        $font.Dispose()
        $graphic.Dispose()
        $bitmap.Dispose()
    }
}

###########################################

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
                See Add-Type section.
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

function SystemCheck {
    param(
        [Parameter(Mandatory=$true)][string]$chk
    )

    $null = secedit /export /cfg $env:temp/secexport.cfg
    $(Get-Content $env:temp/secexport.cfg | Select-String $chk).ToString().Split('=')[1].Trim()
}
 
function CheckSecurityOption {
    param(
        [Parameter(Mandatory=$true)][string]$regpath,
        [Parameter(Mandatory=$true)][string]$paramtotest
    )

    try {
        Get-ItemPropertyValue $regpath $paramtotest
    }
    catch {
        if ($locale -eq 'EN') {
            Write-Host "Can't retreive value from the registry" -ForegroundColor Red
        } else {
            Write-Host "La valeur n'est pas configurÃ©e dans la base de registre" -ForegroundColor Red
        }
    }
}

Function Pass {
    if ($locale -eq 'EN') {
        Write-Output 'The current setting meets the CIS requirements' `r
    } else {
        Write-Output 'La configuration actuelle répond aux critères de durcissement attendus' `r
    }

    [void]$true
}

Function Failed {
    Param (
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$field
    )
    
    if ($field -eq "") {
        if ($locale -eq 'EN') { 
            $field = "Empty setting"
        } else { $field = "Aucune valeur trouvée" }
    }
    
    if ($locale -eq 'EN') {
        Write-Host "Currently set to: " -NoNewline
        Write-Host $field -ForegroundColor Red
        Write-Output "The configuration doesn't meet CIS the requirements" `r
    } else {
        Write-Host "Configuration actuelle: " -NoNewline
        Write-Host $field -ForegroundColor Red
        Write-Output "La configuration ne répond pas aux critères de durcissement attendus" `r
    }

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
        "not" {
                if (-not ([string]::IsNullOrEmpty($field))) {
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

    Write-Host "1.1.2 (L1) Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'" -ForegroundColor Green
    $mpa = (Checker $PasswordPolicy.MaxPasswordAge.Days 'le' 365)
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

    Write-Host "1.2.2 (L1) Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'" -ForegroundColor Green
    $lt = (Checker $PasswordPolicy.LockoutThreshold 'le' 5)
    if ($lt -eq 'True') {
        Checker $PasswordPolicy.LockoutThreshold 'ne' 0
    } else { $lt }

    Write-Host "1.2.3 (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)'" -ForegroundColor Green
    Checker $PasswordPolicy.LockoutObservationWindow.Minutes 'ge' 15
}

Function LocalPoliciesEN {
    Write-Host "################################################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER - User Rights Assignement" -ForegroundColor Yellow
    Write-Host "################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -ForegroundColor Green
    [string]$acmtc = AccountsWithUserRight SeTrustedCredManAccessPrivilege
    Checker $acmtc 'eqc' $null
    
    Write-Host "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'" -ForegroundColor Green
    [string]$apos = AccountsWithUserRight SeTcbPrivilege
    Checker $apos 'eqc' $null

    Write-Host "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$amqp = AccountsWithUserRight SeIncreaseQuotaPrivilege
    Checker $amqp 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"

    Write-Host "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'" -ForegroundColor Green
    [string]$alla = AccountsWithUserRight SeInteractiveLogonRight
    Checker $alla 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$bfd = AccountsWithUserRight SeBackupPrivilege
    Checker $bfd 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$cst = AccountsWithUserRight SeSystemtimePrivilege
    Checker $cst 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE"

    Write-Host "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$clt = AccountsWithUserRight SeTimeZonePrivilege
    Checker $clt 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE"

    Write-Host "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'" -ForegroundColor Green
    [string]$cp = AccountsWithUserRight SeCreatePagefilePrivilege
    Checker $cp 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'" -ForegroundColor Green
    [string]$cto = AccountsWithUserRight SeCreateTokenPrivilege
    Checker $cto 'eqc' $null

    Write-Host "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Green
    [string]$cgp = AccountsWithUserRight SeCreateGlobalPrivilege
    Checker $cgp 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE NT AUTHORITY\SERVICE"

    Write-Host "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'" -ForegroundColor Green
    [string]$cpso = AccountsWithUserRight SeCreatePermanentPrivilege
    Checker $cpso 'eqc' $null

    Write-Host "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'" -ForegroundColor Green
    [string]$dpa = AccountsWithUserRight SeDebugPrivilege
    Checker $dpa 'eqc' "BUILTIN\Administrators"
    
    Write-Host "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    [string]$dlbj = AccountsWithUserRight SeDenyBatchLogonRight
    Checker $dlbj 'match' "Guests"

    Write-Host "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'" -ForegroundColor Green
    [string]$dls = AccountsWithUserRight SeDenyServiceLogonRight
    Checker $dls 'match' "Guests"

    Write-Host "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'" -ForegroundColor Green
    [string]$dll = AccountsWithUserRight SeDenyInteractiveLogonRight
    Checker $dll 'match' "Guests"

    Write-Host "2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'" -ForegroundColor Green
    [string]$fsrs = AccountsWithUserRight SeRemoteShutdownPrivilege
    Checker $fsrs 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$gsa = AccountsWithUserRight SeAuditPrivilege
    Checker $gsa 'eqc' "NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"

    Write-Host "2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'" -ForegroundColor Green
    [string]$isp = AccountsWithUserRight SeIncreaseBasePriorityPrivilege
    Checker $isp 'eqc' "Window Manager\Window Manager Group BUILTIN\Administrators"

    Write-Host "2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'" -ForegroundColor Green
    [string]$ludd = AccountsWithUserRight SeLoadDriverPrivilege
    Checker $ludd 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'" -ForegroundColor Green
    [string]$lpm = AccountsWithUserRight SeLockMemoryPrivilege
    Checker $lpm 'eqc' $null
    
    Write-Host "2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'" -ForegroundColor Green
    [string]$mol = AccountsWithUserRight SeRelabelPrivilege
    Checker $mol 'eqc' $null

    Write-Host "2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'" -ForegroundColor Green
    [string]$mfev = AccountsWithUserRight SeSystemEnvironmentPrivilege
    Checker $mfev 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" -ForegroundColor Green
    [string]$pvmt = AccountsWithUserRight SeManageVolumePrivilege
    Checker $pvmt 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'" -ForegroundColor Green
    [string]$psp = AccountsWithUserRight SeProfileSingleProcessPrivilege
    Checker $psp 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" -ForegroundColor Green
    [string]$psysp = AccountsWithUserRight SeSystemProfilePrivilege
    Checker $psysp 'eqc' "NT SERVICE\WdiServiceHost BUILTIN\Administrators"

    Write-Host "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$rplt = AccountsWithUserRight SeAssignPrimaryTokenPrivilege
    Checker $rplt 'eqc' "NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"

    Write-Host "2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$rfd = AccountsWithUserRight SeRestorePrivilege
    Checker $rfd 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'" -ForegroundColor Green
    [string]$sds = AccountsWithUserRight SeShutdownPrivilege
    Checker $sds 'eqc' "BUILTIN\Administrators"

    Write-Host "2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One'" -ForegroundColor Green
    [string]$sdsd = AccountsWithUserRight SeSyncAgentPrivilege
    Checker $sdsd 'eqc' $null

    Write-Host "2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'" -ForegroundColor Green
    [string]$town = AccountsWithUserRight SeTakeOwnershipPrivilege
    Checker $town 'eqc' "BUILTIN\Administrators"


    Write-Host "##########################################" -ForegroundColor Yellow `r
    Write-Host "LOCAL POLICIES CHAPTER - Security Options" -ForegroundColor Yellow
    Write-Host "##########################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'" -ForegroundColor Green
    [string]$secop1 = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "NoConnectedUser"
    Checker $secop1 'eq' 3

    Write-Host "2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'" -ForegroundColor Green
    [string]$secop2 = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "LimitBlankPasswordUse"
    Checker $secop2 'eq' 1

    Write-Host "2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'" -ForegroundColor Green
    Write-Host "Check manually" -ForegroundColor DarkRed
    Write-Host "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'" -ForegroundColor Green
    Write-Host "Check manually" -ForegroundColor DarkRed
}

Function LocalPoliciesFR {
    Write-Host "###############################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Droits utilisateurs" -ForegroundColor Yellow
    Write-Host "###############################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.1 (L1) Ensure 'Access Credential Manager as a trusted caller' is set to 'No One'" -ForegroundColor Green
    [string]$acmtc = AccountsWithUserRight SeTrustedCredManAccessPrivilege
    Checker $acmtc 'eqc' $null
    
    Write-Host "2.2.4 (L1) Ensure 'Act as part of the operating system' is set to 'No One'" -ForegroundColor Green
    [string]$apos = AccountsWithUserRight SeTcbPrivilege
    Checker $apos 'eqc' $null

    Write-Host "2.2.6 (L1) Ensure 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$amqp = AccountsWithUserRight SeIncreaseQuotaPrivilege
    Checker $amqp 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.7 (L1) Ensure 'Allow log on locally' is set to 'Administrators'" -ForegroundColor Green
    [string]$alla = AccountsWithUserRight SeInteractiveLogonRight
    Checker $alla 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.10 (L1) Ensure 'Back up files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$bfd = AccountsWithUserRight SeBackupPrivilege
    Checker $bfd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.11 (L1) Ensure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$cst = AccountsWithUserRight SeSystemtimePrivilege
    Checker $cst 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.12 (L1) Ensure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'" -ForegroundColor Green
    [string]$clt = AccountsWithUserRight SeTimeZonePrivilege
    Checker $clt 'eqc' "BUILTIN\Administrateurs AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.13 (L1) Ensure 'Create a pagefile' is set to 'Administrators'" -ForegroundColor Green
    [string]$cp = AccountsWithUserRight SeCreatePagefilePrivilege
    Checker $cp 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.14 (L1) Ensure 'Create a token object' is set to 'No One'" -ForegroundColor Green
    [string]$cto = AccountsWithUserRight SeCreateTokenPrivilege
    Checker $cto 'eqc' $null

    Write-Host "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Green
    [string]$cgp = AccountsWithUserRight SeCreateGlobalPrivilege
    Checker $cgp 'eqc' "AUTORITE NT\SERVICE BUILTIN\Administrateurs AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'" -ForegroundColor Green
    [string]$cpso = AccountsWithUserRight SeCreatePermanentPrivilege
    Checker $cpso 'eqc' $null

    Write-Host "2.2.19 (L1) Ensure 'Debug programs' is set to 'Administrators'" -ForegroundColor Green
    [string]$dpa = AccountsWithUserRight SeDebugPrivilege
    Checker $dpa 'eqc' "BUILTIN\Administrateurs"
    
    Write-Host "2.2.22 (L1) Ensure 'Deny log on as a batch job' to include 'Guests'" -ForegroundColor Green
    [string]$dlbj = AccountsWithUserRight SeDenyBatchLogonRight
    Checker $dlbj 'match' "Invités"

    Write-Host "2.2.23 (L1) Ensure 'Deny log on as a service' to include 'Guests'" -ForegroundColor Green
    [string]$dls = AccountsWithUserRight SeDenyServiceLogonRight
    Checker $dls 'match' "Invités"

    Write-Host "2.2.24 (L1) Ensure 'Deny log on locally' to include 'Guests'" -ForegroundColor Green
    [string]$dll = AccountsWithUserRight SeDenyInteractiveLogonRight
    Checker $dll 'match' "Invités"

    Write-Host "2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'" -ForegroundColor Green
    [string]$fsrs = AccountsWithUserRight SeRemoteShutdownPrivilege
    Checker $fsrs 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$gsa = AccountsWithUserRight SeAuditPrivilege
    Checker $gsa 'eqc' "AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators'" -ForegroundColor Green
    [string]$isp = AccountsWithUserRight SeIncreaseBasePriorityPrivilege
    Checker $isp 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'" -ForegroundColor Green
    [string]$ludd = AccountsWithUserRight SeLoadDriverPrivilege
    Checker $ludd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'" -ForegroundColor Green
    [string]$lpm = AccountsWithUserRight SeLockMemoryPrivilege
    Checker $lpm 'eqc' $null
    
    Write-Host "2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'" -ForegroundColor Green
    [string]$mol = AccountsWithUserRight SeRelabelPrivilege
    Checker $mol 'eqc' $null

    Write-Host "2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'" -ForegroundColor Green
    [string]$mfev = AccountsWithUserRight SeSystemEnvironmentPrivilege
    Checker $mfev 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" -ForegroundColor Green
    [string]$pvmt = AccountsWithUserRight SeManageVolumePrivilege
    Checker $pvmt 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'" -ForegroundColor Green
    [string]$psp = AccountsWithUserRight SeProfileSingleProcessPrivilege
    Checker $psp 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" -ForegroundColor Green
    [string]$psysp = AccountsWithUserRight SeSystemProfilePrivilege
    Checker $psysp 'eqc' "NT SERVICE\WdiServiceHost BUILTIN\Administrateurs"

    Write-Host "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$rplt = AccountsWithUserRight SeAssignPrimaryTokenPrivilege
    Checker $rplt 'eqc' "AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$rfd = AccountsWithUserRight SeRestorePrivilege
    Checker $rfd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'" -ForegroundColor Green
    [string]$sds = AccountsWithUserRight SeShutdownPrivilege
    Checker $sds 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One'" -ForegroundColor Green
    [string]$sdsd = AccountsWithUserRight SeSyncAgentPrivilege
    Checker $sdsd 'eqc' $null

    Write-Host "2.2.48 (L1) Ensure 'Take ownership of files or other objects' is set to 'Administrators'" -ForegroundColor Green
    [string]$town = AccountsWithUserRight SeTakeOwnershipPrivilege
    Checker $town 'eqc' "BUILTIN\Administrateurs"


    Write-Host "###############################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Options de Sécurité" -ForegroundColor Yellow
    Write-Host "###############################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.1.2 (L1) Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'" -ForegroundColor Green
    [string]$secop1 = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "NoConnectedUser"
    Checker $secop1 'eq' 3

    Write-Host "2.3.1.4 (L1) Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'" -ForegroundColor Green
    [string]$secop2 = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "LimitBlankPasswordUse"
    Checker $secop2 'eq' 1

    Write-Host "2.3.1.5 (L1) Configure 'Accounts: Rename administrator account'" -ForegroundColor Green
    Write-Host "Vérification manuelle nécessaire" -ForegroundColor DarkRed
    Write-Host "2.3.1.6 (L1) Configure 'Accounts: Rename guest account'" -ForegroundColor Green
    Write-Host "Vérification manuelle nécessaire" -ForegroundColor DarkRed `r`n


    Write-Host "#############################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Membre du domaine" -ForegroundColor Yellow
    Write-Host "#############################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.6.1 (L1) Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'" -ForegroundColor Green
    [string]$digenc = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireSignOrSeal"
    Checker $digenc 'eq' 1

    Write-Host "2.3.6.2 (L1) Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'" -ForegroundColor Green
    [string]$digencp = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "SealSecureChannel"
    Checker $digencp 'eq' 1

    Write-Host "2.3.6.3 (L1) Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'" -ForegroundColor Green
    [string]$digencs = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "SignSecureChannel"
    Checker $digencs 'eq' 1

    Write-Host "2.3.6.4 (L1) Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'" -ForegroundColor Green
    [string]$disap = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "DisablePasswordChange"
    Checker $disap 'eq' 0

    Write-Host "2.3.6.5 (L1) Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'" -ForegroundColor Green
    [string]$maxp = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "MaximumPasswordAge"
    $dmres = (Checker $maxp 'le' 30)
    if ($dmres -eq 'True') {
        Checker $maxp 'ne' 0
    } else { $dmres }

    Write-Host "2.3.6.6 (L1) Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'" -ForegroundColor Green
    [string]$stkey = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "RequireStrongKey"
    Checker $stkey 'eq' 1


    Write-Host "###############################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Session Intéractive" -ForegroundColor Yellow
    Write-Host "###############################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.7.1 (L1) Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'" -ForegroundColor Green
    [string]$ilcad = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "DontDisplayLastUserName"
    Checker $ilcad 'eq' 1

    Write-Host "2.3.7.2 (L1) Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'" -ForegroundColor Green
    [string]$ilcad = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "disablecad"
    Checker $ilcad 'eq' 0
    
    Write-Host "2.3.7.3 (L1) Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'" -ForegroundColor Green
    [string]$ilmil = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "InactivityTimeoutSecs"
    $res = (Checker $ilmil 'le' 900)
    if ($res -eq 'True') {
        Checker $ilmil 'ne' 0
    } else { $res }

    Write-Host "2.3.7.4 (L1) Configure 'Interactive logon: Message text for users attempting to log on'" -ForegroundColor Green
    Write-Host "VÃ©rification manuelle nÃ©cessaire" -ForegroundColor DarkRed
    Write-Host "2.3.7.5 (L1) Configure 'Interactive logon: Message title for users attempting to log on'" -ForegroundColor Green
    Write-Host "VÃ©rification manuelle nÃ©cessaire" -ForegroundColor DarkRed `r`n

    Write-Host "2.3.7.7 (L1) Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'" -ForegroundColor Green
    [string]$ilpup = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "PasswordExpiryWarning"
    Checker $ilpup 'ge' 5


    Write-Host "###########################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Microsoft Network Client (en relation avec SMB)" -ForegroundColor Yellow
    Write-Host "###########################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.8.1 (L1) Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'" -ForegroundColor Green
    [string]$dsc = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "RequireSecuritySignature"
    Checker $dsc 'eq' 1

    Write-Host "2.3.8.2 (L1) Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'" -ForegroundColor Green
    [string]$dscs = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "EnableSecuritySignature"
    Checker $dscs 'eq' 1

    Write-Host "2.3.8.3 (L1) Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'" -ForegroundColor Green
    [string]$dscs = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" "EnablePlainTextPassword"
    Checker $dscs 'eq' 0


    Write-Host "###########################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Microsoft Network Server (en relation avec SMB)" -ForegroundColor Yellow
    Write-Host "###########################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.9.1 (L1) Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'" -ForegroundColor Green
    [string]$autodc = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "autodisconnect"
    Checker $autodc 'le' 15

    Write-Host "2.3.9.2 (L1) Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'" -ForegroundColor Green
    [string]$dsca = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "RequireSecuritySignature"
    Checker $dsca 'eq' 1

    Write-Host "2.3.9.3 (L1) Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'" -ForegroundColor Green
    [string]$dscc = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableSecuritySignature"
    Checker $dscc 'eq' 1

    Write-Host "2.3.9.4 (L1) Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'" -ForegroundColor Green
    [string]$dcl = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "EnableForcedLogOff"
    Checker $dcl 'eq' 1


    Write-Host "#########################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - AccÃ¨s RÃ©seaux" -ForegroundColor Yellow
    Write-Host "#########################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.10.1 (L1) Ensure 'Network access: Allow anonymous SID/Name translation' is set to 'Disabled'" -ForegroundColor Green
    $nano = SystemCheck "LSAAnonymousNameLookup"
    Checker $nano 'eq' 0

    Write-Host "2.3.10.5 (L1) Ensure 'Network access: Let Everyone permissions apply to anonymous users' is set to 'Disabled'" -ForegroundColor Green
    [string]$naep = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "EveryoneIncludesAnonymous"
    Checker $naep 'eq' 0

    Write-Host "2.3.10.8 (L1) Configure 'Network access: Remotely accessible registry paths' is configured" -ForegroundColor Green
    [string]$nare = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" "Machine"
    Checker $nare 'not' $null

    Write-Host "2.3.10.9 (L1) Configure 'Network access: Remotely accessible registry paths and sub-paths' is configured" -ForegroundColor Green
    [string]$narep = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\" "Machine"
    Checker $narep 'not' $null

    Write-Host "2.3.10.10 (L1) Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'" -ForegroundColor Green
    [string]$nara = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "RestrictNullSessAccess"
    Checker $nara 'eq' 1

    Write-Host "2.3.10.12 (L1) Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'" -ForegroundColor Green
    [string]$nas = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionShares"
    Checker $nas 'eqc' 'None'

    Write-Host "2.3.10.13 (L1) Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'" -ForegroundColor Green
    [string]$nass = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "ForceGuest"
    Checker $nass 'eq' 0


    Write-Host "############################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Sécurité Réseaux" -ForegroundColor Yellow
    Write-Host "############################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.11.1 (L1) Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'" -ForegroundColor Green
    [string]$nsls = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "UseMachineId"
    Checker $nsls 'eq' 1

    Write-Host "2.3.11.2 (L1) Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'" -ForegroundColor Green
    [string]$nsnull = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\" "allownullsessionfallback"
    Checker $nsnull 'eq' 0

    Write-Host "2.3.11.3 (L1) Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'" -ForegroundColor Green
    [string]$nspku2u = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\pku2u\" "AllowOnlineID"
    Checker $nspku2u 'eq' 0

    Write-Host "2.3.11.4 (L1) Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'" -ForegroundColor Green
    [string]$nsenc = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" "SupportedEncryptionTypes"
    # Need to be rechecked
    Write-Host "Path not found" -ForegroundColor Red

    Write-Host "2.3.11.5 (L1) Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'" -ForegroundColor Green
    [string]$nslan = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "NoLMHash"
    Checker $nslan 'eq' 1

    Write-Host "2.3.11.6 (L1) Ensure 'Network security: Force logoff when logon hours expire' is set to 'Enabled'" -ForegroundColor Green
    $nslog = SystemCheck "ForceLogoffWhenHourExpire"
    Checker $nslog 'eq' 1

    Write-Host "2.3.11.7 (L1) Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'" -ForegroundColor Green
    [string]$nsauth = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "LmCompatibilityLevel"
    Checker $nsauth 'eq' 5

    Write-Host "2.3.11.8 (L1) Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher" -ForegroundColor Green
    [string]$nsldap = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LDAP\" "LDAPClientIntegrity"
    Checker $nsldap 'eq' 1

    Write-Host "2.3.11.9 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'" -ForegroundColor Green
    [string]$nscli = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinClientSec"
    Checker $nscli 'eq' 537395200

    Write-Host "2.3.11.10 (L1) Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'" -ForegroundColor Green
    [string]$nssrv = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0\" "NTLMMinServerSec"
    Checker $nssrv 'eq' 537395200


    Write-Host "############################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Controle de compte d'utilisateur" -ForegroundColor Yellow
    Write-Host "############################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.17.1 (L1) Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacadm = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "FilterAdministratorToken"
    Checker $uacadm 'eq' 1

    Write-Host "2.3.17.2 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'" -ForegroundColor Green
    [string]$uacprt = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorAdmin"
    Checker $uacprt 'eq' 2

    Write-Host "2.3.17.3 (L1) Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'" -ForegroundColor Green
    [string]$uacprtu = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "ConsentPromptBehaviorUser"
    Checker $uacprtu 'eq' 0

    Write-Host "2.3.17.4 (L1) Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacdap = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableInstallerDetection"
    Checker $uacdap 'eq' 1

    Write-Host "2.3.17.5 (L1) Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacui = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableSecureUIAPaths"
    Checker $uacui 'eq' 1

    Write-Host "2.3.17.6 (L1) Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacadm = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableLUA"
    Checker $uacadm 'eq' 1

    Write-Host "2.3.17.7 (L1) Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacsw = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "PromptOnSecureDesktop"
    Checker $uacsw 'eq' 1

    Write-Host "2.3.17.8 (L1) Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'" -ForegroundColor Green
    [string]$uacvf = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\" "EnableVirtualization"
    Checker $uacvf 'eq' 1
}

Function DCPolicies {
    Write-Host "########################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Droits utilisateurs  - CONTROLEUR DE DOMAINE" -ForegroundColor Yellow
    Write-Host "########################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.2 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users, ENTERPRISE DOMAIN CONTROLLERS'" -ForegroundColor Green
    [string]$acna = AccountsWithUserRight SeNetworkLogonRight
    Checker $acna 'eqc' "BUILTIN\Administrateurs AUTORITE NT\Utilisateurs authentifiés Contrôleurs de domaine d'entreprise"
    
    Write-Host "2.2.5 (L1) Ensure 'Add workstations to domain' is set to 'Administrators'" -ForegroundColor Green
    [string]$awd = AccountsWithUserRight SeMachineAccountPrivilege
    Checker $awd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.8 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators'" -ForegroundColor Green
    [string]$alrd = AccountsWithUserRight SeRemoteInteractiveLogonRight
    Checker $alrd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.17 (L1) Ensure 'Create symbolic links' is set to 'Administrators'" -ForegroundColor Green
    [string]$csl = AccountsWithUserRight SeCreateSymbolicLinkPrivilege
    Checker $csl 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.20 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests'" -ForegroundColor Green
    [string]$dag = AccountsWithUserRight SeDenyNetworkLogonRight
    Checker $dag 'match' "Invités"

    Write-Host "2.2.25 (L1) Ensure 'Deny log on through Remote Desktop Services' to include 'Guests'" -ForegroundColor Green
    [string]$dlg = AccountsWithUserRight SeDenyRemoteInteractiveLogonRight
    Checker $dlg 'match' "Invités"

    Write-Host "2.2.27 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'Administrators'" -ForegroundColor Green
    [string]$deleg = AccountsWithUserRight SeEnableDelegationPrivilege
    Checker $deleg 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.31 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Green
    [string]$imp = AccountsWithUserRight SeImpersonatePrivilege
    Checker $imp 'eqc' "AUTORITE NT\SERVICE BUILTIN\Administrateurs AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.36 (L2) Ensure 'Log on as a batch job' is set to 'Administrators'" -ForegroundColor Green
    [string]$batch = AccountsWithUserRight SeBatchLogonRight 
    Checker $batch 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.37 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators' and (when Exchange is running in the environment) 'Exchange Servers'" -ForegroundColor Green
    [string]$mas = AccountsWithUserRight SeSecurityPrivilege 
    Checker $mas 'eqc' "BUILTIN\Administrateurs"

    Write-Host "#####################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Options de sécurité CONTROLEUR DE DOMAINE" -ForegroundColor Yellow
    Write-Host "#####################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.5.1 (L1) Ensure 'Domain controller: Allow server operators to schedule tasks' is set to 'Disabled'" -ForegroundColor Green
    [string]$secsrvt = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "SubmitControl"
    Checker $secsrvt 'eq' 0

    Write-Host "2.3.5.2 (L1) Ensure 'Domain controller: Allow vulnerable Netlogon secure channel connections' is set to 'Not Configured'" -ForegroundColor Green
    [string]$vuln = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "vulnerablechannelallowlist"
    Checker $vuln 'eq' $null

    Write-Host "2.3.5.3 (L1) Ensure 'Domain controller: LDAP server channel binding token requirements' is set to 'Always'" -ForegroundColor Green
    [string]$ldapb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" "LdapEnforceChannelBinding"
    Checker $ldapb 'eq' 1

    Write-Host "2.3.5.4 (L1) Ensure 'Domain controller: LDAP server signing requirements' is set to 'Require signing'" -ForegroundColor Green
    [string]$ldaps = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters\" "LDAPServerIntegrity"
    Checker $ldaps 'eq' 2

    Write-Host "2.3.5.5 (L1) Ensure 'Domain controller: Refuse machine account password changes' is set to 'Disabled'" -ForegroundColor Green
    [string]$ldaps = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters\" "RefusePasswordChange"
    Checker $ldaps 'eq' 0

    Write-Host "##############################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Acces réseau CONTROLEUR DE DOMAINE" -ForegroundColor Yellow
    Write-Host "##############################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.10.6 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'" -ForegroundColor Green
    [string]$ldaps = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionPipes"
    Checker $ldaps 'eq' $null
}

function MBPolicies {
    Write-Host "####################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Droits utilisateurs  - MEMBRE DU DOMAINE" -ForegroundColor Yellow
    Write-Host "####################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.2.3 (L1) Ensure 'Access this computer from the network' is set to 'Administrators, Authenticated Users'" -ForegroundColor Green
    [string]$acnamb = AccountsWithUserRight SeNetworkLogonRight
    Checker $acnamb 'eqc' "BUILTIN\Administrateurs AUTORITE NT\Utilisateurs authentifiés"

    Write-Host "2.2.9 (L1) Ensure 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'" -ForegroundColor Green
    [string]$almb = AccountsWithUserRight SeRemoteInteractiveLogonRight
    Checker $almb 'eqc' "BUILTIN\Utilisateurs du Bureau à distance BUILTIN\Administrateurs"

    Write-Host "2.2.18 (L1) Ensure 'Create symbolic links' is set to 'Administrators, NT VIRTUAL MACHINE\Virtual Machines'" -ForegroundColor Green
    [string]$cslmb = AccountsWithUserRight SeCreateSymbolicLinkPrivilege
    Checker $cslmb 'eqc' "BUILTIN\Administrateurs NT VIRTUAL MACHINE\Machines virtuelles"

    Write-Host "2.2.21 (L1) Ensure 'Deny access to this computer from the network' to include 'Guests, Local account and member of Administrators group'" -ForegroundColor Green
    [string]$danmb = AccountsWithUserRight SeDenyNetworkLogonRight
    Checker $danmb 'match' "(Invités) (compte local) (membre des groupes Administrateurs)"

    Write-Host "2.2.26 (L1) Ensure 'Deny log on through Remote Desktop Services' is set to 'Guests, Local account'" -ForegroundColor Green
    [string]$dlgmb = AccountsWithUserRight SeDenyRemoteInteractiveLogonRight
    Checker $dlgmb 'match' "(Invités) (compte local)"

    Write-Host "2.2.28 (L1) Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'" -ForegroundColor Green
    [string]$delegmb = AccountsWithUserRight SeEnableDelegationPrivilege
    Checker $delegmb 'eqc' $null

    Write-Host "2.2.32 (L1) Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE' and (when the Web Server (IIS) Role with Web Services Role Service is installed) 'IIS_IUSRS'" -ForegroundColor Green
    [string]$impmb = AccountsWithUserRight SeImpersonatePrivilege
    Checker $impmb 'eqc' "AUTORITE NT\SERVICE BUILTIN\Administrateurs AUTORITE NT\SERVICE RéSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.38 (L1) Ensure 'Manage auditing and security log' is set to 'Administrators'" -ForegroundColor Green
    [string]$masmb = AccountsWithUserRight SeSecurityPrivilege 
    Checker $masmb 'eqc' "BUILTIN\Administrateurs"

    Write-Host "#################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Options de sécurité MEMBRE DU DOMAINE" -ForegroundColor Yellow
    Write-Host "#################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.1.1 (L1) Ensure 'Accounts: Administrator account status' is set to 'Disabled'" -ForegroundColor Green
    $adasmb = SystemCheck "EnableAdminAccount"
    Checker $adasmb 'eq' 0

    Write-Host "2.3.1.3 (L1) Ensure 'Accounts: Guest account status' is set to 'Disabled'" -ForegroundColor Green
    $gasmb = SystemCheck "EnableGuestAccount"
    Checker $gasmb 'eq' 0

    Write-Host "#################################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Session intéractive MEMBRE DU DOMAINE" -ForegroundColor Yellow
    Write-Host "#################################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.7.8 (L1) Ensure 'Interactive logon: Require Domain Controller Authentication to unlock workstation' is set to 'Enabled'" -ForegroundColor Green
    [string]$ilmb = CheckSecurityOption  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" "ForceUnlockLogon"
    Checker $ilmb 'eq' 1

    Write-Host "############################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Serveur Réseau MEMBRE DU DOMAINE" -ForegroundColor Yellow
    Write-Host "############################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.9.5 (L1) Ensure 'Microsoft network server: Server SPN target name validation level' is set to 'Accept if provided by client' or higher" -ForegroundColor Green
    [string]$spnmb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "SmbServerNameHardeningLevel"
    Checker $spnmb 'eq' 1

    Write-Host "##########################################################" -ForegroundColor Yellow `r
    Write-Host "CHAPITRE : LOCAL POLICIES - Acces réseau MEMBRE DU DOMAINE" -ForegroundColor Yellow
    Write-Host "##########################################################" -ForegroundColor Yellow `r`n

    Write-Host "2.3.10.2 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts' is set to 'Enabled'" -ForegroundColor Green
    [string]$sammb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "RestrictAnonymousSAM"
    Checker $sammb 'eq' 1

    Write-Host "2.3.10.3 (L1) Ensure 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is set to 'Enabled'" -ForegroundColor Green
    [string]$samshmb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "RestrictAnonymous"
    Checker $samshmb 'eq' 1

    Write-Host "2.3.10.7 (L1) Configure 'Network access: Named Pipes that can be accessed anonymously'" -ForegroundColor Green
    [string]$pipmb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters\" "NullSessionPipes"
    Checker $piphmb 'eq' $null

    Write-Host "2.3.10.11 (L1) Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'" -ForegroundColor Green
    [string]$samalmb = CheckSecurityOption  "HKLM:\System\CurrentControlSet\Control\Lsa\" "RestrictRemoteSAM"
    Checker $samalmb 'eq' "Administrators: Remote Access: Allow"
}


################# MAIN #################

Write-Banner "WinSRV 2012 Policy Checker" -Bold -Italic -Underline

$locale = $args[0]
$servertype = $args[1]

if ($locale -eq 'fr' -And $servertype -eq 'dc') {
    AccountPolicies
    LocalPoliciesFR
    DCPolicies
} elseif ($locale -eq 'fr' -And $servertype -eq 'mb') {
    AccountPolicies
    LocalPoliciesFR
    MBPolicies
    } else { Write-Host "Wrong locale or server type..." -ForegroundColor Red; Write-Host "[USAGE]: " $MyInvocation.MyCommand " {FR/EN} {DC/MB}"; exit 1 }

if ($locale -eq 'en' -And $servertype -eq 'dc') {
    AccountPolicies
    LocalPoliciesEN
    DCPoliciesEN
} elseif ($locale -eq 'en' -And $servertype -eq 'mb') {
    AccountPolicies
    LocalPoliciesFR
    MBPolicies
} else { Write-Host "Wrong locale or server type..." -ForegroundColor Red; Write-Host "[USAGE]: " $MyInvocation.MyCommand " {FR/EN} {DC/MB}"; exit 1 }