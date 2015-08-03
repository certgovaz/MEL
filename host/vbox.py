from ctypes import *
import os
import sys
from configparser import ConfigParser

class vi(object):
	def __init__(self):
		self.WAIT_FAILED = 0xFFFFFFFF
		self.WAIT_TIMEOUT = 0x00000102
		self.WAIT_OBJECT_0 = 0x00000000
		
		self.virtualbox = None
		if sys.getwindowsversion().major == 6:
			self.virtualbox = os.environ['VBOX_MSI_INSTALL_PATH'] + 'VBoxManage.exe'
		else:
			self.virtualbox = os.environ['VBOX_INSTALL_PATH'] + 'VBoxManage.exe'
			
			
		c = ConfigParser()
		c.read('config/conf.txt')
		self.machine = c['mal-trap-helper']['machine_name']
		self.snapshot = c['mal-trap-helper']['snapshot_name']
		
		class PROCESS_INFORMATION(Structure):
			_fields_ = [('hProcess',c_ulong),
						('hThread',c_ulong),
						('dwProcessId',c_ulong),
						('dwThreadId',c_ulong)]
						
		class STARTUPINFO(Structure):
			_fields_ = [('cb',c_ulong),
						('lpReserved1',c_wchar_p * 3),
						('dwReserved1',c_ulong * 8),
						('wReserved1',c_ushort * 2),
						('lpReserved2',POINTER(c_byte)),
						('hReserved1',c_void_p * 3)]
		
		
		self.pi = PROCESS_INFORMATION()
		self.si = STARTUPINFO()
		self.si.cb = sizeof(STARTUPINFO)
		
	def startvm(self):
		kernel32 = windll.kernel32
		
		si = self.si
		pi = self.pi
		
		
		cmdline = "%s startvm \"%s\"" % (self.virtualbox,self.machine)
		status = kernel32.CreateProcessW(None,
									cmdline,
									None,
									None,
									False,
									0x00000008,
									None,
									None,
									byref(si),
									byref(pi))
									
		if status == 1:
			wait = kernel32.WaitForSingleObject(pi.hProcess,15000)
			if wait == self.WAIT_OBJECT_0:
				return 0
			elif wait == self.WAIT_TIMEOUT:
				return 2
			else:
				return 1
		else:
			return 1
			
			
	def snapres(self):
		kernel32 = windll.kernel32
		
		si = self.si
		pi = self.pi
		
		cmdline = "%s snapshot \"%s\" restore \"%s\"" % (self.virtualbox,self.machine,self.snapshot)
		
		status = kernel32.CreateProcessW(None,
									cmdline,
									None,
									None,
									False,
									0x00000008,
									None,
									None,
									byref(si),
									byref(pi))
		if status == 1:
			wait = kernel32.WaitForSingleObject(pi.hProcess,15000)
			if wait == self.WAIT_OBJECT_0:
				return 0
			elif wait == self.WAIT_TIMEOUT:
				return 2
			else:
				return 1
		else:
			return 1