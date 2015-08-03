import os
from hashlib import md5,sha1
from time import localtime


class stat(object):
	def __init__(self):
		pass
		
		
		
	def getstat(self,FILENAME):
		file = FILENAME
		try:
			st = os.stat(file)
		except FileNotFoundError:
			return 1					#os.stat method error
		try:
			f = open(file,"rb")
			bData = f.read()
			f.close()
		except FileNotFoundError:
			return 2					#Cannot open sample file
			
			
		_md5 = md5(bData).hexdigest()
		_sha1 = sha1(bData).hexdigest()
		
		if _sha1 != None and _md5 != None:
			return (
					_md5,						#File md5 sum
					_sha1,						#File sha1 sum
					# localtime(st.st_ctime),		#File create time
					# localtime(st.st_atime),		#File access time
					# localtime(st.st_mtime),		#File modified time
					st.st_size					#File size
					);
					
	
	# def pipes(self):
		
		# pipes = ""
		# ppath = r"\\.\Pipe"
		# for kanal in os.listdir(ppath):
			# pipes += "%s\\%s\n" % (ppath,kanal)
			
		# return pipes