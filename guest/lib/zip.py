from zipfile import ZipFile
from os import listdir as ls


class zip:
	def __init__(self, Directory):
		self.dir = Directory + r"\\"
		self.ZipObject = None
		try:
			self.ZipObject = ZipFile("report.zip","w")
		except:
			self.ZipObject = None
		
		
	def Gather(self):
		if self.ZipObject == None:
			return 1				#ZipFileObject is NULL
		try:
			for files in ls(self.dir):
				self.ZipObject.write(self.dir + files)
		except:
			return 2				#ZipObject cannot add files to archive
		
		self.ZipObject.close()		#Close ZipObject
		return 0