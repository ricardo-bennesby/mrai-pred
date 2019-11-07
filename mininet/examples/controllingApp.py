import time
import socket
import sys

host = '192.168.1.120'
port = 2000
backlog = 5
size = 1024

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host,port))
s.listen(backlog)

while 1:
    #time.sleep(1)
    client, address = s.accept()
    messages = [ client.recv(size) ]
    if messages:
	message = ''.join(messages)

    print message
	
    #sys.stdout.write( message )
    sys.stdout.flush()
  
