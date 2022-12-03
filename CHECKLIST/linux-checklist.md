
##  sudo -l [if you have the password]

##  sudo LD_PRELOAD vuln

##	User Enumeration

>	User Enumeration
>	Groups Enumeration [If unusual group is available for you, must check]	


##	Network Information

>	check unusual open ports
>	UDP ports
>	ifconfig / netstat


##	Running Process `[-tasklist, ps -aux]`


##	Directory Enumeration

>   /home, /opt, /var, /srv, /etc, /mnt [check-for-any-unusual-location/different-user-directory]
>   /var/www/html, /var/mail, /var/backups, /var/opt

##  File Enumeration

>   /etc/passwd, /etc/shadow, /etc/group, /etc/groups, id_rsa, 
>   .bashrc, .bash_history, .profile, .viminfo, .zsh_history,.zshrc
>   .bak, .secret, 


##  SUID / SGID

##	Apache Startup PE

##  Sudo - Environment Variables [preload.c]

##  Cron Jobs - File Permissions 

##  Insecure File Permission

##	Password Mining

##  Service Exploit
>   mysql exploit
>   check

>   Grep commands for finding password



##  Kernal Exploit
>   cross compiling [https://forums.offensive-security.com/showthread.php?48259-Fix-for-incompatibility-with-older-versions-of-gcc-Kali-2022-3]
>   cross compile in kali with 32bit static commands

##	Tools
>   linpeas
>   pspy
>   chisel
>   linux-prev-check [pentest-monkey]
>   LinEnum.sh