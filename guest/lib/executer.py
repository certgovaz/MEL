from ctypes import *



class Exec(object):
	def __init__(self,samplepath):
		
		
		self.sample_path = samplepath
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
		
		
	def execute(self):
	
		kernel32 = windll.kernel32						#Link to kernel32 Library
		
		
		pi = self.pi		#PROCESS_INFORMATION_STRUCTURE
		si = self.si		#STARTUPINFO_STRUCTURE
		
		
		status = kernel32.CreateProcessW(None,
									self.sample_path,
									None,
									None,
									False,
									0,
									None,
									None,
									byref(si),
									byref(pi))
		if status == 0:
			return 1											#Cannot create process
		else:
			return (pi.hProcess,pi.dwProcessId)