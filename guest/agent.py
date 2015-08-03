from lib.av import antivirus
from lib.inf import stat
from lib.trapping import trap
from lib.zip import zip
from lib.pe import PE
from lib.process import process
from lib.ssdeep import fuzzy
from configparser import ConfigParser
from lib.executer import Exec
import os
from time import sleep
from socket import *
import ctypes


###################################################################
c = ConfigParser()
c.read('config/conf.txt')
my_ip = c['mal-trap-helper']['agent_ip']
host_ip = c['mal-trap-helper']['host_ip']
submit_port = c['mal-trap-helper']['submit_port']
clamscanlog = c['mal-trap-helper']['clamscanlog']
avirascanlog = c['mal-trap-helper']['avirascanlog']
pe_parse_log = c['mal-trap-helper']['pe_parse_log']
remote_event_handler_port = c['mal-trap-helper']['event_handler_port']
capture_bat_log = c['mal-trap-helper']['capture_bat_log']
windump_log = c['mal-trap-helper']['windump_log']
remote_report_port = c['mal-trap-helper']['report_port']
####################################################################
#Globals
caphProcess,capPID = None,None
nethProcess,netPID = None,None
malhProcess,malPID = None,None


def reportsend():
	#Bu funksiya analiz bitdikden sonra zereli haqqinda alinan butun informasiyani server terefine gonderir
	try:
		report_file = open("report.zip","rb")
		data = report_file.read()
		report_file.close()
		s = socket(AF_INET,SOCK_STREAM)
		s.connect((host_ip,int(remote_report_port)))
		s.sendall(data)
		s.close()
		return 0
	except:
		return 1



def event(message):
	#Bu funksiya server terefe analiz sistemin islemesi haqqinda butun informasiyani gonderir.
	"""This is function is kanal notifier"""
	s = socket(AF_INET,SOCK_STREAM)
	s.connect((host_ip,int(remote_event_handler_port)))
	s.sendall(message.encode('ascii',errors='ignore'))
	s.close()



	
def Z():
	#Bu funksiya analiz bitdikden sonra yigilmish informasiyani tek bir zip faylin icine yigir ve report send funksiyasini cagirir.
	z = zip("c:\\logs")
	if z.Gather() == 0:
		event("[ZIP] Log files successfully zipped")
		sleep(2)
		event("start report")
		sleep(5)
		rs = reportsend()
		if rs == 0:
			event("[Report] Report file send is OK")
		else:
			event("[Report] Report exception found")
		event("success")
		exit(1)
	else:
		event("[ZIP] Log files zipping problem found")
		event("success")
		exit(1)
	

def Antivirus():
	#Bu funksiyani zereli ilk gonderdiyi zaman Antivirus filterinden kecirir.
	#Eger zereli antiviruslar terefinden qeyde alinarsa analize ehtiyac duyulmur ve sistem avtomatik olaraq dayandirirlir.
	##Start Antivirus engine scanning
	A = antivirus("c:\\malware.exe")
	if A.clamav(clamscanlog) == 0:
		event("[Antivirus] ClamScan OK")
	else:
		event("[Antivirus] ClamScan problem found")
	if A.avira(avirascanlog) == 0:
		event("[Antivirus] AviraScan OK")
	else:
		event("[Antivirus] AviraScan problem found")
		
	#Test file for detected or else
	if not os.path.exists("c:\\malware.exe"):
		event("[Antivirus] File detected")
		event("success")
		exit(1)
	else:
		event("[Antivirus] File not detected")
		
		
def GetStat():
	#Bu funksiya zereli haqqinda infomasiyani elde edir.
	#Bu informasiyaya faylin md5 summasi,sha1 summasi,ssdeep summasi ve faylin olcusu daxildir.
	statfile = open("c:\\logs\\stat.log","w")
	ssdeep_sum = fuzzy("c:\\malware.exe").hash()
	if ssdeep_sum == 1:
		event("[ssdeep] fuzzy_hash problem found")
		ssdeep_sum = ""
	else:
		event("[ssdeep] fuzzy_hash successfully")
	md5,sha1,filesize = stat().getstat("c:\\malware.exe")
	statfile.write("md5=%s\nsha1=%s\nssdeep=%s\nfilesize=%d (byte)" % (md5,sha1,ssdeep_sum,int(filesize)))
	statfile.close()
	event("[STAT] FILESTAT(md5,sha1,ssdeep,filesize) successfully")
	
	
def PeParse():
	#Bu funksiya Zereli fayli PE dump edir ve neticeleri loglasdirir.
	#Iliin versiyada Direktoryalarin analizi ve dumpi edilmir gelecekde buda temin edilecek.
	p = PE("c:\\malware.exe",pe_parse_log).parse()
	if p == 1:
		event("[PE] PeParse cannot open sample executable")
		event("success")
		exit(1)
	elif p == 2:
		event("[PE] PeParse cannot write dump file")
		event("success")
		exit(1)
	else:
		event("[PE] PeParse successfully")
		
		
def Trapping():
	#Bu funksiya zererlinin izlenmesi ucun lazimi 3rd proqram teminatlarini ishe salir ve lazimi sazlamalari heyata kecirir.
	global caphProcess
	global capPID
	global nethProcess
	global netPID
	
	
	##Initialize process module
	p = process()
	#Start trapping modules

	################################
	Trap = trap()
	cap = Trap.capturebat(capture_bat_log)
	net = Trap.windump(windump_log)
	if cap == 1:
		event("[Trapping] Trapping cannot create process CaptureBat")
		event("success")
		exit(1)
	else:
		caphProcess,capPID = cap
		event("[Trapping] CaptureBat start successfully. (ProcessID=%d)" % (int(capPID)))

	if net == 1:
		event("[Trapping] Trapping cannot create process windump")
		if p.kill(caphProcess) == 0:
			event("[Process] CaptureBat process terminated")
		else:
			event("[Process] Cannot terminate CaptureBat process")
		event("success")
		exit(1)
	else:
		nethProcess,netPID = net
		event("[Trapping] Trapping windump start successfully. (ProcessID=%d)" % (int(netPID)))
		
		
		
def Ex():
	p = process()
	#Execute malware sample and snapshot modules
	Ex = Exec("c:\\malware.exe").execute()
	if Ex == 1:
		event("[Executer] Executer cannot execute sample program")
		if p.kill(capPID) == 0:
			event("[Process] CaptureBat process terminated")
		else:
			event("[Process] Cannot terminate CaptureBat process")
		if p.kill(netPID) == 0:
			event("[Process] windump process terminated")
		else:
			event("[Process] Cannot terminate windump process")
		event("success")
		exit(1)
	################################################################################	
	else:
		malhProcess,malPID = Ex
		event("[Executer] Executer CreateProcess with sample program is executed (PID = %s)" % int(malPID))
		sleep(1)
		Modules = p.mod(malPID)
		#################################################################
		if Modules == 1 or Modules == 2:
			event("[Process] Cannot extract malware process modules error code=%d" % (Modules))
			# if p.kill(capPID) == 0:
				# event("[Process] CaptureBat process terminated")
			# else:
				# event("[Process] Cannot terminate CaptureBat process")
			# if p.kill(netPID) == 0:
				# event("[Process] windump process terminated")
			# else:
				# event("[Process] Cannot terminate windump process")
		#########################################################################################
		else:
			mf = open("c:\\logs\\mods.log","w")
			for m in Modules:
				mf.write(repr(m) + '\n')
			mf.close()
			event("[Process] Malware Process modules extracting completed")
		event("[agent] WaitForSingleObject is called")
		wait = ctypes.windll.kernel32.WaitForSingleObject(malhProcess,150000)
		####################################################################
		if wait == 0x00000000:
			event("[Agent] Process self terminated")
			if p.kill(capPID) == 0 and p.kill(netPID) == 0:
				event("[Process] CaptureBat and windump process terminated")
				Z()
			else:
				event("[Process] Cannot terminate windump and CaptureBat process")
				event("success")
				exit(1)
		#################################################################		
		elif wait == 0x00000102:
			event("[Agent] The time-out interval elapsed")
			if p.kill(capPID) == 0 and p.kill(netPID) == 0:
				event("[Process] CaptureBat and windump process terminated")
				Z()
			else:
				event("[Process] Cannot terminate windump and CaptureBat process")
				event("success")
				exit(1)
		################################################################
		else:
			event("[Agent] WaitFailed")
			if p.kill(capPID) == 0 and p.kill(netPID) == 0:
				event("[Process] CaptureBat and windump process terminated")
				Z()
			else:
				event("[Process] Cannot terminate windump and CaptureBat process")
				event("success")
				exit(1)
				
				
	
def main():
	#Test log directory found
	if not os.path.exists("c:\\logs"):
		os.mkdir("c:\\logs")


	#Create template malware executable
	malware = open("c:\\malware.exe","wb")

		
	s = socket(AF_INET,SOCK_STREAM)
	s.bind((my_ip,int(submit_port)))
	s.listen(1)

	conn,addr = s.accept()

	while 1:
		data = conn.recv(1024)
		if not data:break
		malware.write(data)
		while 1:
			data = conn.recv(1024)
			if not data:break
			malware.write(data)

	malware.close()		
	conn.close()
	s.close()

	if os.path.exists("c:\\malware.exe"):
		event("[OK] File received")
	else:
		event("File cannot upload")
		event("success")
		exit(1)
	sleep(2)	
	Antivirus()
	GetStat()
	PeParse()
	Trapping()
	Ex()
	event("success")
	
	
	
main()