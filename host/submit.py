import sys
from socket import *
from os import path
from configparser import ConfigParser


if len(sys.argv) <= 1:
	print("\nNot enought argument\nUsage example:submit.py c:\\malware.exe")
	exit(1)
	
submit_file = sys.argv[1]

if not path.exists(submit_file):
	print("\nSample file [%s] not found" % sys.argv[1])
	exit(1)



submit_file = open(submit_file,"rb")
sample = submit_file.read()
submit_file.close()
##################################################

c = ConfigParser()
c.read('config/conf.txt')
remote_submit_ip = c['mal-trap-helper']['guest_ip']
remote_submit_port = c['mal-trap-helper']['submit_port']
try:
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((remote_submit_ip,int(remote_submit_port)))
	s.sendall(sample)
	s.close()
	print("\n[OK] File successfully uploaded")
except:
	print("\nException found cannot submit file")