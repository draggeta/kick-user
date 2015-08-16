Import-Module ActiveDirectory

#Set the email message and settings
$EmailMessage = @()
$To = 'helpdesk@domain.com'
$From = 'noreply@domain.com'
$Port = '587'
$PSEmailServer = 'mail.domain.com'
$Username = 'relay@domain.com'
#$Password = 'P@$$w0rd!'
$PasswordFile = 'C:\Scripts\PwdRelay.txt'
#$Credential = $Password | ConvertTo-SecureString -AsPlainText -Force 
$Credential = Get-Content $PasswordFile | ConvertTo-SecureString  


#Set the file properties to check
$FileWitnessPath = "C:\Share\*"
$FileWitness1 = "C:\Share\_Witness\Witness_do_not_edit.txt"
$FileWitness2 = "C:\Share\ZWitness\Witness_do_not_edit.txt"
$HashWitness = '6207702E2B0291F1E5A3ECF54B25EE294B23C14C3F8F58B00E520BD3598AF81'


#Calculate the hashes of the files as they currently are and if incorrect/absent, start to feel uneasy
Try {$CurrentHash1 = Get-FileHash $FileWitness1}
Catch { $EmailMessage += "$FileWitness1 has been renamed or deleted."}
Try {$CurrentHash2 = Get-FileHash $FileWitness2}
Catch { $EmailMessage += "$FileWitness1 has been renamed or deleted."}


#Check if the hashes match the reference hash, if they don't start to freak out
If ($HashWitness -ne $CurrentHash1 -or $HashWitness -ne $CurrentHash2) {

    #Get the logs that were created recently and match the $FileWitnessPath
    $AuditLog = Get-EventLog -LogName Security -InstanceId 4659,4663 -After (Get-Date).AddMinutes(-2) | 
    Where-Object { $_.ReplacementStrings[6] -like $FileWitnessPath} | 
    Select-Object @{Name='Name';Expression={$_.ReplacementStrings[1]}},@{Name='Folder';Expression={$_.ReplacementStrings[6]}}
    
    #If no logs were found, send an email detailing the weirdness of it all
    If ($AuditLog -eq $Null) {

        $EmailMessage += "Could not find the user or computer who modified the files. Please check to verify if there is something wrong. `n"
        Send-MailMessage -To $To -From $From -Subject 'Warning: Possible CryptoLocker, no user found' -Body "$EmailMessage" -Port $Port -UseSsl -Credential $Credential
    }
    #Otherwise start getting serious about kicking people
    Else {
        
        $AuditLog | ForEach-Object {
            
            $Name = $_.Name
            $Folder = $_.Folder

            #Try to disable the users' accounts who appear in the logs
            Try {

                Get-ADUser $Name | Disable-ADAccount
                $EmailMessage += "User $Name's account has been disabled as they tried to modify the `"$Folder`" folder/directory."

            }
            Catch {

                $EmailMessage += "Could not find user $Name, or something went wrong trying to disable their account."

            }
            #Try restarting/halting their computer, release it's IP or whatever else you fancy
            Try {

                $WorkstationIP = (net session | Select-String $Name).Line.Substring(2,21).Trim()
                $WorkstationName = (Resolve-DnsName $WorkstationIP).NameHost
                #$WorkstationName = (nslookup $Name | Select-String 'name').Line.Substring(9).Trim()

                Restart-Computer -ComputerName $WorkstationName -Force
                $EmailMessage += "Their computer $WorkstationName on $WorkstationIP has been restarted to close all active sessions `n"

            }
            Catch {

                $EmailMessage += "Could not find their computer. Active sessions could not be closed. `n"

            }

        }
        #Send an email detailing the hard work you performed (or tried to)
        Send-MailMessage -To $To -From $From -Subject 'Warning: Possible CryptoLocker' -Body "$EmailMessage" -Port $Port -UseSsl -Credential $Credential

    }

}


