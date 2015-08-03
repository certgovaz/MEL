from ctypes import *
from os import path

class antivirus:
	def __init__(self,FILENAME):
		self.file = FILENAME
		self.INFINITE = 0xFFFFFFFF
		
		class PROCESS_INFORMATION(Structure):
			_fields_ = [ ('hProcess',c_void_p), ('hThread',c_void_p), ('dwProcessId',c_ulong), ('dwThreadId',c_ulong) ]
		
			
		class STARTUPINFO(Structure):
			_fields_ = [('cb',c_ulong),
						('lpReserved',c_char_p),
						('lpDesktop',c_char_p),
						('lpTitle',c_char_p),
						('dwX',c_ulong),
						('dwY',c_ulong),
						('dwXSize',c_ulong),
						('dwYSize',c_ulong),
						('dwXCountChars',c_ulong),
						('dwYCountChars',c_ulong),
						('dwFillAttribytes',c_ulong),
						('dwFlags',c_ulong),
						('ShowWindow',c_ushort),
						('cbReserved2',c_ushort),
						('hStdInput',c_void_p),
						('hStdOutput',c_void_p),
						('hStdError',c_void_p)
						]
		
		self.pi = PROCESS_INFORMATION()		
		self.si = STARTUPINFO()
		self.si.cb = sizeof(STARTUPINFO)
		
		
	def clamav(self,LOGFILE):
		log = LOGFILE
		si = self.si
		pi = self.pi
		
		
		kernel32 = windll.kernel32
		clampath = "C:\\Program Files\\ClamWin\\bin\\clamscan.exe"
		clamdatabase = "C:\\Documents and Settings\\All Users\\.clamwin\\db"
		
		cmdline = "%s --quiet --database=\"%s\" --log=\"%s\" --remove %s" % (clampath,clamdatabase,log,self.file)
		
		status = kernel32.CreateProcessW(None,
									cmdline,
									None,
									None,
									False,
									0,
									None,
									None,
									byref(si),
									byref(pi))
		
		if status == 0:
			return 1
		else:
			kernel32.WaitForSingleObject(pi.hProcess,self.INFINITE)
			return 0
				
				
				
	def avira(self,LOGFILE):
		
		log = LOGFILE
		si = self.si
		pi = self.pi
		
		kernel32 = windll.kernel32
		avirapath = "C:\\Program Files\\Avira\\scancl.exe"
		cmdline = "%s --quiet --log=\"%s\" --defaultaction=delete %s" % (avirapath,log,self.file)
		
		status = kernel32.CreateProcessW(None,
							cmdline,
							None,
							None,
							False,
							0,
							None,
							None,
							byref(si),
							byref(pi))
		
		if status == 0:
			return 1
		else:
			kernel32.WaitForSingleObject(pi.hProcess, self.INFINITE)
			return 0