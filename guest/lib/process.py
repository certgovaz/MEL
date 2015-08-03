from ctypes import *



class process(object):
	def __init__(self):
		self.TH32CS_SNAPMODULE = 0x00000008
		self.INVALID_HANDLE_VALUE = (-1)
		self.MAX_MODULE_NAME32 = 255
		self.MAX_PATH = 260
		
		class MODULEENTRY32(Structure):
			_fields_ = [('dwSize',c_ulong),
						('th32ModuleID',c_ulong),
						('th32ProcessID',c_ulong),
						('Reserved',c_ulong * 2),
						('modBaseAddr',c_ulong),
						('modBaseSize',c_ulong),
						('hModule',c_void_p),
						('szModule',c_wchar * (self.MAX_MODULE_NAME32 + 1)),
						('szExePath',c_wchar * (self.MAX_PATH))]
		
		self.mod32 = MODULEENTRY32()
		self.mod32.dwSize = sizeof(MODULEENTRY32)
		
		
	def mod(self,dwPID):
		ret = []
		pid = int(dwPID)
		
		kernel32 = windll.kernel32		#Link to kernel32 Library
		mod32 = self.mod32			#MODULEENTRY32
		
		hSnapshot = kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPMODULE,
												pid)
		
		if hSnapshot == self.INVALID_HANDLE_VALUE:
			return 1													#CreateToolhelp32Snapshot cannot create snapshot
		
		status = kernel32.Module32FirstW(hSnapshot, byref(mod32))
		
		if status == False:
			kernel32.CloseHandle(hSnapshot)
			return 2													#Module32FirstW call error
			
		while status != 0:
			ret.append((mod32.szModule, mod32.szExePath, hex(mod32.modBaseAddr), mod32.modBaseSize))
			status = kernel32.Module32NextW(hSnapshot, byref(mod32))
			
		kernel32.CloseHandle(hSnapshot)
		return ret
		
	

	
	def kill(self,dwPID):
		
		pid = int(dwPID)
		
		kernel32 = windll.kernel32		#Link to kernel32 Library
		PROCESS_TERMINATE = 0x0001
		
		hProcess = kernel32.OpenProcess(PROCESS_TERMINATE,		#Access right
									False,
									pid)
		
		if hProcess == None:
			return 1										#Cannot open process with OpenProcess
		status = kernel32.TerminateProcess(hProcess,1)
		if status == 0:
			kernel32.CloseHandle(hProcess)
			return 2										#Cannot terminate process
		else:
			kernel32.CloseHandle(hProcess)
			return 0
			
			
			
	def handles(self):
		pass