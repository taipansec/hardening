@{
    "Comptes_bloquer_les_comptes_Microsoft" = @{
        Value   = "MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\NoConnectedUser"
        Section = 'Registry Values'
        Option  = @{
            "Cette stratégie est désactivée" = '4,0'
            "Les utilisateurs ne peuvent pas ajouter de comptes Microsoft" = '4,1'
            "Les utilisateurs ne peuvent pas ajouter ou se connecter avec des comptes Microsoft" = '4,3'
        }
    }

    "Comptes_restreindre_l’utilisation_de_mots_de_passe_vides_par_le_compte_local_à_l’ouverture_de_session_console" = @{
        Value   = "MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse"
        Section = 'Registry Values'
        Option  = @{
            Enabled  = '4,1'
            Disabled = '4,0'
        }
    }

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
}