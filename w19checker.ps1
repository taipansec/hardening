# only the code necessary for verifying them.
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
    [string]$acmtc = AccountsWithUserRight SeTrustedCredManAccessPrivilege
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
    Checker $cto 'eqc' $null

    Write-Host "2.2.15 (L1) Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Green
    [string]$cgp = AccountsWithUserRight SeCreateGlobalPrivilege
    # EN version
    # Checker $cgp 'eqc' "BUILTIN\Administrators NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE NT AUTHORITY\SERVICE"
    # FR version
    Checker $cgp 'eqc' "AUTORITE NT\SERVICE BUILTIN\Administrateurs AUTORITE NT\SERVICE RÉSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.16 (L1) Ensure 'Create permanent shared objects' is set to 'No One'" -ForegroundColor Green
    [string]$cpso = AccountsWithUserRight SeCreatePermanentPrivilege
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

    Write-Host "2.2.29 (L1) Ensure 'Force shutdown from a remote system' is set to 'Administrators'" -ForegroundColor Green
    [string]$fsrs = AccountsWithUserRight SeRemoteShutdownPrivilege
    # EN version
    # Checker $fsrs 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $fsrs 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.30 (L1) Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$gsa = AccountsWithUserRight SeAuditPrivilege
    # EN version
    # Checker $gsa 'eqc' "NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"
    # FR version
    Checker $gsa 'eqc' "AUTORITE NT\SERVICE RÉSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.33 (L1) Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'" -ForegroundColor Green
    [string]$isp = AccountsWithUserRight SeIncreaseBasePriorityPrivilege
    # EN version
    # Checker $isp 'eqc' "Window Manager\Window Manager Group BUILTIN\Administrators"
    # FR version
    Checker $isp 'eqc' "Window Manager\Window Manager Group BUILTIN\Administrateurs"

    Write-Host "2.2.34 (L1) Ensure 'Load and unload device drivers' is set to 'Administrators'" -ForegroundColor Green
    [string]$ludd = AccountsWithUserRight SeLoadDriverPrivilege
    # EN version
    # Checker $ludd 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $ludd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.35 (L1) Ensure 'Lock pages in memory' is set to 'No One'" -ForegroundColor Green
    [string]$lpm = AccountsWithUserRight SeLockMemoryPrivilege
    Checker $lpm 'eqc' $null
    
    Write-Host "2.2.39 (L1) Ensure 'Modify an object label' is set to 'No One'" -ForegroundColor Green
    [string]$mol = AccountsWithUserRight SeRelabelPrivilege
    Checker $mol 'eqc' $null

    Write-Host "2.2.40 (L1) Ensure 'Modify firmware environment values' is set to 'Administrators'" -ForegroundColor Green
    [string]$mfev = AccountsWithUserRight SeSystemEnvironmentPrivilege
    # EN version
    # Checker $mfev 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $mfev 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.41 (L1) Ensure 'Perform volume maintenance tasks' is set to 'Administrators'" -ForegroundColor Green
    [string]$pvmt = AccountsWithUserRight SeManageVolumePrivilege
    # EN version
    # Checker $pvmt 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $pvmt 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.42 (L1) Ensure 'Profile single process' is set to 'Administrators'" -ForegroundColor Green
    [string]$psp = AccountsWithUserRight SeProfileSingleProcessPrivilege
    # EN version
    # Checker $psp 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $psp 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.43 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'" -ForegroundColor Green
    [string]$psysp = AccountsWithUserRight SeSystemProfilePrivilege
    # EN version
    # Checker $psysp 'eqc' "NT SERVICE\WdiServiceHost BUILTIN\Administrators"
    # FR version
    Checker $psysp 'eqc' "NT SERVICE\WdiServiceHost BUILTIN\Administrateurs"

    Write-Host "2.2.44 (L1) Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'" -ForegroundColor Green
    [string]$rplt = AccountsWithUserRight SeAssignPrimaryTokenPrivilege
    # EN version
    # Checker $rplt 'eqc' "NT AUTHORITY\LOCAL SERVICE NT AUTHORITY\NETWORK SERVICE"
    # FR version
    Checker $rplt 'eqc' "AUTORITE NT\SERVICE RÉSEAU AUTORITE NT\SERVICE LOCAL"

    Write-Host "2.2.45 (L1) Ensure 'Restore files and directories' is set to 'Administrators'" -ForegroundColor Green
    [string]$rfd = AccountsWithUserRight SeRestorePrivilege
    # EN version
    # Checker $rfd 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $rfd 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.46 (L1) Ensure 'Shut down the system' is set to 'Administrators'" -ForegroundColor Green
    [string]$sds = AccountsWithUserRight SeShutdownPrivilege
    # EN version
    # Checker $sds 'eqc' "BUILTIN\Administrators"
    # FR version
    Checker $sds 'eqc' "BUILTIN\Administrateurs"

    Write-Host "2.2.47 (L1) Ensure 'Synchronize directory service data' is set to 'No One'" -ForegroundColor Green
    [string]$sdsd = AccountsWithUserRight SeSyncAgentPrivilege
    Checker $sdsd 'eqc' $null
}

AccountPolicies
LocalPolicies

# Not finished...
