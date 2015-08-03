from socket import *
from os import system
from configparser import ConfigParser
from time import asctime,sleep
from vbox import vi
from threading import Thread

#############################################################
c = ConfigParser()
c.read('config/conf.txt')
my_ip = c['mal-trap-helper']['host_ip']
event_handler_port = c['mal-trap-helper']['event_handler_port']
report_port = c['mal-trap-helper']['report_port']
#############################################################


#################################################################
print("-" * 50)
print("[*] Malware-Trap-Helper v0.1")
print("[*] http://www.cert.gov.az")
print("[*] malware_lab@cert.gov.az")
print("[*] Time:",asctime())
print("[*] Start on Interface",my_ip)
print("-" * 50)
#################################################################



def report_receive():
	#Thread function receive report file
	print("[report_receive] Thread:Start Thread OK")
	report = open("report/report.zip","wb")
	s = socket(AF_INET,SOCK_STREAM)
	s.bind((my_ip,int(report_port)))
	s.listen(1)

	conn,addr = s.accept()
	print("[report_receive] Connection established:",addr)
	while 1:
		data = conn.recv(1024)
		if not data:break
		report.write(data)
		while 1:
			data = conn.recv(1024)
			if not data:break
			report.write(data)

	report.close()		
	conn.close()
	s.close()




#VirtualBox
#Restore Snapshot
V = vi()
V.snapres()
#Start virtualMachine
V.startvm()



s = socket(AF_INET,SOCK_STREAM)
s.bind((my_ip,int(event_handler_port)))
s.listen(1)

while 1:
	conn,addr = s.accept()
	
	data = conn.recv(1024)
	if not data or data == b'success':
		print("\n[#] File analysis complete")
		sleep(5)
		break
	if data == b'start report':
		thread = Thread(None,report_receive)
		thread.start()
	print("[time[%s]] [message[%s]]" % (asctime(),data))
	
	
conn.close()	
s.close()
system("pause")