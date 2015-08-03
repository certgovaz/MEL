from ctypes import *


class fuzzy:
	def __init__(self,filename):
		self.file = filename.encode()
		self.FUZZY_MAX_RESULT = (2 * 64 + 20)
		
		
	def hash(self):
		
		ssdeep = cdll.fuzzy			#Link to ssdeep Library
		
		
		fuzzy_buffer = c_buffer(self.FUZZY_MAX_RESULT)
		status = ssdeep.fuzzy_hash_filename(c_char_p(self.file), byref(fuzzy_buffer))
		if status == 0:
			return fuzzy_buffer.value.decode()
		else:
			return 1