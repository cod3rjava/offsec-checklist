

#	WinPrevEsc

##	User Enumeration

>	User Enumeration
>	Groups Enumeration [If unusual group is available for you, must check]	
>	USer Enumeration on Domain
>	Group Enumeration on domain

##	Network Information

>	check unusual open ports
>	UDP ports
>	ipconfig / 


##	Running Process [TASKLIST]

##	Directory Enumeration

>	Program Files / Program Files x86 / Users home dir [Check recurse dir /s /a ] / inetpub / 	[Installed Apps]
>	Schedule task / `.bat` [dir /s /a *.bat] from C directory

>	link [sysmlink] file [ippsec]-[]

##	LAPS ENabled : For Password mining

##	If we can `Modify Any Service` [change-bin-path] [don't run nc.exe]
>	service start / stop
>	service is running as LocalSystem
>	AutoStart
>	ShutDown Prev

```
>	icalcs
>	sc.exe
>   accesscheck
>	accepteula
>   Get-Acl
```

##	Unquoated service path
>	service start / stop
>	service is running as LocalSystem
>	AutoStart / Or if we able to make it AutoStart
>	ShutDown Prev

##		DLL Hijacking

##		AlwaysInstallElevated 

##	 	Insecure GUI Apps 

##	Startup Apps / Registry Startup



##	Password Mining
>	Win Logon creds
>	Registry password 
>	SAM system backup, [REPAIR/BACKUP]
>	DPAPI Creds
>	Passwords of saved wifi
>	saved RDP Connections
>	Recent run commands / Powershell history
>	Remote Desktop Credentials Manager passwords?
>	Grep commands for finding password

##	Check Patch History


##  UAC bypass
>   fodhelper
>   sigcheck.exe


##  Antivirus Evasion
>   Shelter

##	Kernal Exploit

##	Tools

>   PowerUp.ps1
>   PowerView.ps1
>   WinPeas.exe
>   Windows-Prevs-Checker [Pentester-Monkey]
>   JAWS
>   Windows Exploit Suggeste
>   Seatbelt
>   Watson
>   psexec
>   Chisel.exe
>   PLINK.exe
