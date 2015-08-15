$EmailMessage = @()
$To = 'helpdesk@domain.com'
$From = 'noreply@domain.com'
$PSEmailServer = 'mail.domain.com'

$FileWitness1 = "\\FS01\_Witness\Witness_do_not_edit.txt"
$FileWitness2 = "\\FS01\ZWitness\Witness_do_not_edit.txt"
$HashWitness = '6207702E2B0291F1E5A3ECF54B25EE294B23C14C3F8F58B00E520BD3598AF81'

$CurrentHash1 = Get-FileHash $FileWitness1
$CurrentHash2 = Get-FileHash $FileWitness2

If ($HashWitness -ne $CurrentHash1 -or $CurrentHash2) {

    $AuditLog = Get-EventLog -LogName Security -InstanceId 4659,4663 -After (Get-Date).AddMinutes(-1) | Where-Object { $_.ReplacementStrings[6] -eq $FileWitness1 -or $FileWitness2}

    If ($AuditLog -eq $null) {

        $EmailMessage += "Could not find the user who modified the files. Please perform manual operations to verify if there is something wrong."
        Send-MailMessage -To $To -From $From -Subject 'Warning: Possible CryptoLocker, no user found' -Body $EmailMessage
    }
    Else {
        
        Try {

            Get-ADUser $Name | Disable-ADAccount
            $EmailMessage += "$Name's account has been disabled as they tried to modify the `"$Folder`" folder/directory."

        }
        Catch {

            $EmailMessage += "Could not find user $Name, or something went wrong trying to disable their account."

        }
        
        Try {

            $WorkstationIP = (net session | Select-String $Name).Line.Substring(2,21).Trim()
            $WorkstationName = (Resolve-DnsName $WorkstationIP).NameHost

            Restart-Computer -ComputerName $WorkstationName -Force
            $EmailMessage += "User $Name's computer $WorkstationName on $WorkstationIP has been disconnected to close all active sessions"

        }
        Catch {

            $EmailMessage += "Could not find $Name's computer. Active sessions could not be closed."

        }
    
        Send-MailMessage -To $To -From $From -Subject 'Warning: Possible CryptoLocker' -Body "$EmailMessage"

    }

}
