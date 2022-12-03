#   Pre Enumeration

##  DNS Enumeration

##  Domain Enumeration

##  LDAP Enumeration

##  RPC ENumeration

##  SMB Enumeration

##  Kerberos Enumeration

##  impacket-GetAdUsers.py

##  impacket-GetNPUsers

##  impacket-GetUserSPNs.py

##	BruteForce

>   impacket-rpcdump -p 135 $IP
>   impacket-samrdump 10.129.96.60


#   Post Enumeration [PrevEsc]

##  Domain Enumeration

##  User Enumeration /domain 

>   net logged on user

##  Group Enumeration / Nested Group Enumeration

##	WinPrevEsc


##  Password Dump
>   mimikatz
>   sam/system
>   crunch
>   finding more passwords in files []

##  Find SPNs

##  Password Reuse / PTH / Password Spraying [RDP,SMB,LDAP,FTP,SSH,WEB]

##  Pivoting / Two Level Pivoting / Port Forwarding / Tunnling

