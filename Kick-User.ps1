<#
.SYNOPSIS
    Activates when an audited file gets edited and disables the user's account and computer
.DESCRIPTION
    The Kick-User.ps1 script gets activated by a file audit event. This means that you need to attach a task to the specific events you want it to trigger on. It compares the known hash of a file with the current hash after activation. 
    If the hashes don't match, the user will be extracted from the logs and the computername from the active sessions. Lastly, the user account will be activated and the workstation will be restarted/shutdown or whatever you want.
    
    Due to the way the workstation is detected, you need to run this script on the server you are auditing. If you want to forward the events to a central server, you may need to use PowerShell remoting to query the sessions.
    
    Regarding the script:
     - ReplacementStrings are the values you can pull from the Event Viewer. 1 is the username, 6 is the folder.
     - InstanceID's 4659 is delete, ID 4663 is modify. Change these to suit your environment if needed.
     - The DNS and SMB cmdlets work only on Windows Server 2012/Windows 8 and newer. If this script is run on an older OS, use the net session and nslookup commands. 
     
    Editable variables:
     - To:              The email address to send the emails to
     - From:            The email address to send the emails from, can be the same as above
     - Username:        Not needed if using an anonymous relay. The username that is allowed to send emails as the from address. Can be the same user or a user with 'send as' rights.
     - Password:        Not needed if using an anonymous relay. The password that goes with the username. Can be embedded, or used with a hashed password stored as a file
     - SecPassword:     Not needed if using an anonymous relay. The password variable as a secure string.
     - Credential:      Not needed if using an anonymous relay. The combined object of the username and password variable.

     - FileWitnessX:    The files that will be monitored.
     - Hashwitness:     The hash of the witness file(s). This can be calculated with the Get-FileHash command.
.INPUTS
    None. You cannot pipe objects to Kick-User.ps1
.OUTPUTS
    None. Kick-User only outputs to an email
.NOTES
    Author:   Tony Fortes Ramos
    Created:  August 11, 2015
    Modified: August 18, 2015
.LINK
    Send-MailMessage
    Get-FileHash
    Get-EventLog
#>

Import-Module ActiveDirectory

#Set the email message and settings
$EmailMessage = @()
$To = 'helpdesk@domain.com'
$From = 'noreply@domain.com'
$Port = '587'
$PSEmailServer = 'mail.domain.com'
$Username = 'relay@domain.com'
#$Password = 'P@$$w0rd!'
$Password = 'C:\Scripts\PwdRelay.txt'
#$SecPassword = $Password | ConvertTo-SecureString -AsPlainText -Force 
$SecPassword = Get-Content $Password | ConvertTo-SecureString
$Credential = New-Object System.Management.Automation.PSCredential ($Username,$SecPassword)  

#Set the file properties to check
$FileWitness1 = "C:\Share\_Witness\Witness_do_not_edit.docx"
$FileWitness2 = "C:\Share\ZWitness\Witness_do_not_edit.docx"
$HashWitness = '59748E9A9A4DAB08C2AADD1CF28C3C4A7B06FAF4A81D1468F48FE97D310F2765'

#Calculate the hashes of the files as they currently are and if incorrect/absent, start to sweat
Try { $CurrentHash1 = Get-FileHash $FileWitness1 }
Catch { $EmailMessage += "$FileWitness1 has been renamed or deleted." }
Try { $CurrentHash2 = Get-FileHash $FileWitness2 }
Catch { $EmailMessage += "$FileWitness2 has been renamed or deleted." }

#Check if the hashes match the reference hash, if they don't start to freak out
If ($HashWitness -ne $CurrentHash1 -or $HashWitness -ne $CurrentHash2) {

    #Get the logs that were created recently and match the $FileWitnessPath
    $AuditLog = Get-EventLog -LogName Security -InstanceId 4659,4663 -After (Get-Date).AddMinutes(-2) | 
    Where-Object { ($_.ReplacementStrings[6] -like $FileWitness1) -or ($_.ReplacementStrings[6] -like $FileWitness2) } | 
    Select-Object @{ Name='Name';Expression={ $_.ReplacementStrings[1] } }, @{ Name='Folder';Expression={ $_.ReplacementStrings[6] } } -Unique

    
    #If no logs were found, send an email detailing the weirdness of it all
    If ($AuditLog -eq $Null) {

        $EmailMessage += "Could not find the user or computer who modified the files. Please check to verify if there is something wrong. `n"
        
    }
    #Otherwise start getting serious about kicking people
    Else {
        
        $AuditLog | ForEach-Object {
            
            $Name = $_.Name
            $Folder = $_.Folder

            #Try to disable the users' accounts who appear in the logs
            Try {

                Get-ADUser $Name | Disable-ADAccount
                $EmailMessage += "User $Name's account has been disabled as they tried to modify the `"$Folder`" folder/file. `n"

            }
            Catch {

                $EmailMessage += "Could not find user $Name, or something went wrong trying to disable their account. `n"

            }

            #Try restarting/halting their computer, release its IP or whatever else you fancy
            Try {

                $WorkstationIP = (Get-SmbSession | Where-Object { $_.ClientUserName -like "*$Name" }).ClientComputerName
                #$WorkstationIP = (net session | Select-String $Name).Line.Substring(2,21).Trim()
                $WorkstationName = (Resolve-DnsName $WorkstationIP).NameHost
                #$WorkstationName = (nslookup $WorkstationIP | Select-String 'name').Line.Substring(9).Trim()

                #net session \\$WorkstationIP /delete
                Close-SmbSession -ClientComputerName $WorkstationIP -Force
                Stop-Computer -ComputerName $WorkstationName -Force
                $EmailMessage += "Their computer $WorkstationName on $WorkstationIP has been shut down to close all active sessions `n"

            }
            Catch {

                $EmailMessage += "Could not find their computer. Active sessions could not be closed. `n"

            }

        }
        
    }

    #Send an email detailing the hard work you performed (or tried to)
    Send-MailMessage -To $To -From $From -Subject 'Warning: Possible CryptoLocker' -Body "$EmailMessage" -Port $Port -UseSsl -Credential $Credential

}