from ctypes import *



class trap(object):
	def __init__(self):
		self.create_no_window = 0x08000000 								#Process creation flags
		self.__windump = "C:\\Program Files\\windump\\windump.exe"			#windump
		self.__CaptureBat = "C:\\Program Files\\Capture\\CaptureBat.exe"	#CaptureBat
		
		
		
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
		
		
	def capturebat(self,lopath = None):
	
		kernel32 = windll.kernel32						#Link to kernel32 Library
		cmdline = "%s -l %s" % (self.__CaptureBat,lopath)
		
		
		pi = self.pi		#PROCESS_INFORMATION_STRUCTURE
		si = self.si		#STARTUPINFO_STRUCTURE
		
		
		status = kernel32.CreateProcessW(None,
									cmdline,
									None,
									None,
									False,
									self.create_no_window,
									None,
									None,
									byref(si),
									byref(pi))
		if status == 0:
			return 1											#Cannot create process
		else:
			return (pi.hProcess,pi.dwProcessId)
			
			
			
	def windump(self, logpath):
		kernel32 = windll.kernel32						#Link to kernel32 Library
		
		
		cmdline = "%s -w %s" %  (self.__windump,logpath)
		
		
		pi = self.pi		#PROCESS_INFORMATION_STRUCTURE
		si = self.si		#STARTUPINFO_STRUCTURE
		
		status = kernel32.CreateProcessW(None,
									cmdline,
									None,
									None,
									False,
									self.create_no_window,
									None,
									None,
									byref(si),
									byref(pi))
									
		if status == 0:
			return 1												#Cannot create process
		else:
			return (pi.hProcess, pi.dwProcessId)