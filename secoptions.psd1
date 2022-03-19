@{
    "Accounts_Block_Microsoft_accounts" = @{
        Value   = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser"
        Section = 'Registry Values'
        Option  = @{
            "This policy is disabled" = '4,0'
            "Users cant add Microsoft accounts" = '4,1'
            "Users cant add or log on with Microsoft accounts" = '4,3'
        }
    }

    "Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only" = @{
        Value   = "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse"
        Section = 'Registry Values'
        Option  = @{
            Enabled  = '4,1'
            Disabled = '4,0'
        }
    }

    "Accounts_Rename_administrator_account" = @{
        Value   = 'NewAdministratorName'
        Section = 'System Access'
        Option  = @{
            String = ''
        }
    }

    "Accounts_Rename_guest_account" = @{
        Value   = 'NewGuestName'
        Section = 'System Access'
        Option  = @{
            String = ''
        }
    }
}