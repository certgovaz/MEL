from ctypes import *
from struct import *
from enum import Enum
import sys



class PE:
	def __init__(self,FILENAME,LOGFILE = None):
		self.file = FILENAME
		self.log = LOGFILE

	def parse(self):
		
		#initialize
		
		f = open(self.log,"w")
		log = f.write
		
		
		
		__most_section_name = [".rsrc",".code",".bss",".rdata",".tls",".idata",".text",".data",".reloc",".edata",".didata"]
		
		class directories(Enum):	
			IMAGE_EXPORT = 0
			IMAGE_IMPORT = 1
			IMAGE_RESOURCE = 2
			IMAGE_EXCEPTION = 3
			IMAGE_SECURITY  = 4
			IMAGE_BASERELOC = 5
			IMAGE_DEBUG  = 6
			IMAGE_COPYRIGHT = 7
			IMAGE_GLOBALPTR = 8
			IMAGE_TLS = 9
			IMAGE_LOADCONFIG = 10
			IMAGE_BOUND_IMPORT = 11
			IMAGE_IAT = 12
			IMAGE_DELAYIMPORT = 13
			IMAGE_COM = 14
			IMAGE_RESERVED = 15
			
			
			
		class IMAGE_DOS_HEADER(Structure):
			_fields_ = [('e_magic',c_ubyte * 2),
						('e_cblp',c_ubyte * 2),
						('e_cp',c_ubyte * 2),
						('e_crlc',c_ubyte * 2),
						('e_cparhdr',c_ubyte * 2),
						('e_minalloc',c_ubyte * 2),
						('e_maxalloc',c_ubyte * 2),
						('e_ss',c_ubyte * 2),
						('e_sp',c_ubyte * 2),
						('e_csum',c_ubyte * 2),
						('e_ip',c_ubyte * 2),
						('e_cs',c_ubyte * 2),
						('e_lfarlc',c_ubyte * 2),
						('e_ovno',c_ubyte * 2),
						('e_res',c_ubyte * 2 * 4),
						('e_oemid',c_ubyte * 2),
						('e_oeminfo',c_ubyte * 2),
						('e_res2',c_ubyte * 2 * 10),
						('e_lfanew',c_ubyte * 4)]
						
		
		class IMAGE_FILE_HEADER(Structure):
			_fields_ = [('Machine',c_ubyte * 2),
						('NumberOfSection',c_ubyte * 2),
						('TimeDateStamp',c_ubyte * 4),
						('PointerToSymbolTable',c_ubyte * 4),
						('NumberOfSymbols',c_ubyte * 4),
						('SizeOfOptionalHeader',c_ubyte * 2),
						('Characteristics',c_ubyte * 2)]
		
		
		class IMAGE_DATA_DIRECTORY(Structure):
			_fields_ = [('VirtualAddress',c_ubyte * 4),
						('isize',c_ubyte * 4)]
		
		
		
		
		class IMAGE_OPTIONAL_HEADER(Structure):
			_fields_ = [('Magic',c_ubyte * 2),
						('MajorLinkerVersion',c_ubyte),
						('MinorLinkerVersion',c_ubyte),
						('SizeOfCode',c_ubyte * 4),
						('SizeOfInitializedData',c_ubyte * 4),
						('SizeOfUninitializedData',c_ubyte * 4),
						('AddressOfEntryPoint',c_ubyte * 4),
						('BaseOfCode',c_ubyte * 4),
						('BaseOfData',c_ubyte * 4),
						('ImageBase',c_ubyte * 4),
						('SectionAligment',c_ubyte * 4),
						('FileAlignment',c_ubyte * 4),
						('MajorOperatingSystemVersion',c_ubyte * 2),
						('MinorOperatingSystemVersion',c_ubyte * 2),
						('MajorImageVersion',c_ubyte * 2),
						('MinorImageVersion',c_ubyte * 2),
						('MajorSubsystemVersion',c_ubyte * 2),
						('MinorSubsystemVersion',c_ubyte * 2),
						('Win32VersionValue',c_ubyte * 4),
						('SizeOfImage',c_ubyte * 4),
						('SizeOfHeader',c_ubyte * 4),
						('Cheksum',c_ubyte * 4),
						('Subsystem',c_ubyte * 2),
						('DllCharacteristics',c_ubyte * 2),
						('SizeOfStackReserve',c_ubyte * 4),
						('SizeOfStackCommit',c_ubyte * 4),
						('SizeOfHeapReserve',c_ubyte * 4),
						('SizeOfHeapCommit',c_ubyte * 4),
						('LoaderFlags',c_ubyte * 4),
						('NumberOfRVAandSize',c_ubyte * 4),
						('DataDirectory',IMAGE_DATA_DIRECTORY * 16)]
		
		
		class IMAGE_NT_HEADER(Structure):
			_fields_ = [('Signature',c_ubyte * 4),
						('File_Header',IMAGE_FILE_HEADER),
						('Optional_Header',IMAGE_OPTIONAL_HEADER)]
		
		class MISC(Union):
			_fields_ = [('PhysicalAddress',c_ubyte * 4),
						('VirtualSize',c_ubyte * 4)]
		
		
		
		class IMAGE_SECTION_HEADER(Structure):
			_fields_ = [('Name',c_byte * 8),
						('Misc',MISC),
						('VirtualAddress',c_ubyte * 4),
						('SizeOfRawData',c_ubyte * 4),
						('PointerToRawData',c_ubyte * 4),
						('PointerToRelocations',c_ubyte * 4),
						('PointerToLineNumbers',c_ubyte * 4),
						('NumberOfRelocations',c_ubyte * 2),
						('NumberOfLinenumbers',c_ubyte * 2),
						('Characteristics',c_ubyte * 4)]



		try:
			pp = open(self.file,"rb")	#Open file binary mode
			dump = pp.read()
			pp.close()
		except FileNotFoundError:
			return 1				#Cannot open sample executable
			
		
		try:
			log("-" * 50 + "PE_HEADER" + "-" * 50)
			dos_header = cast(dump[:sizeof(IMAGE_DOS_HEADER)],POINTER(IMAGE_DOS_HEADER)).contents
			e_magic, = unpack("<H",dos_header.e_magic)
			lfanew, = unpack("<L",dos_header.e_lfanew)
			log("\ne_magic:%X\nlfanew:%X\n" % (e_magic,lfanew))

			
			
			log("-" * 50 + "NT_HEADER" + "-" * 50)
			nt_header = cast(dump[lfanew:lfanew + sizeof(IMAGE_NT_HEADER)],POINTER(IMAGE_NT_HEADER)).contents
			signature, = unpack("<L",nt_header.Signature)
			Machine, = unpack("<H",nt_header.File_Header.Machine)
			NumberOfSection, = unpack("<H",nt_header.File_Header.NumberOfSection)
			TimeDateStamp, = unpack("<L",nt_header.File_Header.TimeDateStamp)
			PointerToSymbolTable, = unpack("<L",nt_header.File_Header.PointerToSymbolTable)
			NumberOfSymbols, = unpack("<L",nt_header.File_Header.NumberOfSymbols)
			SizeOfOptionalHeader, = unpack("<H",nt_header.File_Header.SizeOfOptionalHeader)
			Characteristics, = unpack("<H",nt_header.File_Header.Characteristics)
			
			log("\nSignature:%X\nMachine:%X\nNumberOfSection:%X\nTimeDateStamp:%X\nSizeOfOptionalHeader:%X\nCharacteristics:%X\n" % 
														(signature,Machine,NumberOfSection,TimeDateStamp,SizeOfOptionalHeader,Characteristics))
			
			
			log("-" * 50 + "OPTIONAL_HEADER" + "-" * 44)
			OptionalMagic, = unpack("<H",nt_header.Optional_Header.Magic)
			MajorLinkerVersion = nt_header.Optional_Header.MajorLinkerVersion
			MinorLinkerVersion = nt_header.Optional_Header.MinorLinkerVersion
			SizeOfCode, = unpack("<L",nt_header.Optional_Header.SizeOfCode)
			AddressOfEntryPoint, = unpack("<L",nt_header.Optional_Header.AddressOfEntryPoint)
			ImageBase, = unpack("<L",nt_header.Optional_Header.ImageBase)
			BaseOfCode, = unpack("<L",nt_header.Optional_Header.BaseOfCode)
			BaseOfData, = unpack("<L",nt_header.Optional_Header.BaseOfData)
			SizeOfImage, = unpack("<L",nt_header.Optional_Header.SizeOfImage)
			SizeOfHeader, = unpack("<L",nt_header.Optional_Header.SizeOfHeader)
			Cheksum, = unpack("<L",nt_header.Optional_Header.Cheksum)
			Subsystem, = unpack("<H",nt_header.Optional_Header.Subsystem)
			DllCharacteristics, = unpack("<H",nt_header.Optional_Header.DllCharacteristics)
			LoaderFlags, = unpack("<L",nt_header.Optional_Header.LoaderFlags)
			NumberOfRVAandSize, = unpack("<L",nt_header.Optional_Header.NumberOfRVAandSize)
			
			log("\nMagic:%X\nMajorLinkerVer:%X\nMinorLinkerVer:%X\nSizeOfCode:%X\nAddressOfEntryPoint:%X\nImageBase:%X\nBaseOfCode:%X\nBaseOfData:%X\nSizeOfImage:%X\nSizeOfHeaders:%X\n" \
			"Cheksum:%X\nSubsystem:%X\nDllCharacteristics:%X\nLoaderFlags:%X\nNumberOfRVAandSize:%X\n" % 
			(OptionalMagic,MajorLinkerVersion,MinorLinkerVersion,SizeOfCode,AddressOfEntryPoint,ImageBase,BaseOfCode,BaseOfData,SizeOfImage,SizeOfHeader,Cheksum,Subsystem,DllCharacteristics,LoaderFlags,NumberOfRVAandSize))
			
			log("-" * 50 + "DIRECTORY" + "-" * 50)
			
			for j in range(16):
				va, = unpack("<L",nt_header.Optional_Header.DataDirectory[j].VirtualAddress)
				sz, = unpack("<L",nt_header.Optional_Header.DataDirectory[j].isize)
				log("\n(%s$RVA,SIZE) = (%X,%X)" % (directories(j).name,va,sz))
			
			log("\n")
			last = lfanew + sizeof(IMAGE_NT_HEADER)
			
			section_count = NumberOfSection
			section_header  = cast(dump[last:last+sizeof(IMAGE_SECTION_HEADER) * section_count],POINTER(IMAGE_SECTION_HEADER * section_count)).contents
			log("-" * 50 + "SECTION_HEADER" + "-" * 45)

			
			
			for k in range(section_count):
				Name = b"".join(unpack("<8c",section_header[k].Name)).decode()
				Name = Name.strip('\0') + "(Malformed)" if Name.strip("\0") not in __most_section_name else Name.strip('\0')
				VirtualSize, = unpack("<L",section_header[k].Misc.VirtualSize)
				VirtualAddress, = unpack("<L",section_header[k].VirtualAddress)
				RawSize, = unpack("<L",section_header[k].SizeOfRawData)
				RawAddress, = unpack("<L",section_header[k].PointerToRawData)
				RelocAddress, = unpack("<L",section_header[k].PointerToRelocations)
				LineNumbers, = unpack("<L",section_header[k].PointerToLineNumbers)
				RelocationNumber, = unpack("<H",section_header[k].NumberOfRelocations)
				NumberOfLinenumbers, = unpack("<H",section_header[k].NumberOfLinenumbers)
				Characteristics, = unpack("<L",section_header[k].Characteristics)
				log("\nName:%s\nVirtualSize:%X\nVirtualAddress:%X\nRawSize:%X\nRawAddress:%X\nRelocAddress:%X\nLineNumbers:%X\nRelocationNumber:%X\nNumberOfLinenumbers:%X\nCharacteristics:%X\n" 
				% (Name,VirtualSize,VirtualAddress,RawSize,RawAddress,RelocAddress,LineNumbers,RelocationNumber,NumberOfLinenumbers,Characteristics))
				log("=" * 30)
				
			f.close()
			return 0
		except:
			f.close()
			return 2				#Cannot write dump file