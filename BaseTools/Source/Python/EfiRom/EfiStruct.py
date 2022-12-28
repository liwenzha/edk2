# @file
#  Some structure definitions used in EfiRom.
#
#  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##



from ctypes import *
from struct import *
from PeCoff import *

def SIGNATURE_16(A,B):
    return A | (B << 8)

def SIGNATURE_32(A,B,C,D):
    return SIGNATURE_16 (A, B) | SIGNATURE_16 (C, D) << 16
    
MAX_OPTION_ROM_SIZE = 1024 * 1024 * 16
PCI_EXPANSION_ROM_HEADER_SIGNATURE = 0xaa55
PCI_DATA_STRUCTURE_SIGNATURE = SIGNATURE_32 (ord('P'), ord('C'), ord('I'), ord('R'))
INDICATOR_LAST = 0x80 
PCI_CODE_TYPE_EFI_IMAGE = 0x03
MAX_PATH = 200
FILE_FLAG_COMPRESS = 0x04
EFI_PCI_EXPANSION_ROM_HEADER_EFISIGNATURE = 0x0EF1
EFI_PCI_EXPANSION_ROM_HEADER_COMPRESSED = 0x0001
EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES = 16
EFI_IMAGE_DOS_SIGNATURE = 0x5A4D
EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
DEFAULT_OUTPUT_EXTENSION = ".rom"





#Use this linked list structure to keep track of all the filenames
#specified on the command line.
class FILE_LIST(Structure):
    def __init__(self):
        self.Next = None
        
    _pack_ = 1
    _fields_ =[
        #('Next',FILE_LIST),
        ('FileName',c_char),
        ('FileFlags',c_uint32),
        ('ClassCode',c_uint32),
        ('CodeRevision',c_uint16)
    ]


#Use this to track our command-line options

class OPTIONS(Structure):
    _pack_ = 1
    _fields_ =[
        ('OutFileName',c_char),
        ('NoLast',c_int8),
        ('ClassCode',c_uint16),
        ('PciRevision',c_uint16),
        ('VendId',c_uint16),
        ('DevIdList',ARRAY(c_uint16,100)),
        ('DevIdCount',c_uint32),
        ('VendIdValid',c_uint8),
        ('Verbose',c_uint8),
        ('Quiet',c_uint8),
        ('Debug',c_uint8),
        ('Pci23',c_uint8),
        ('Pci30',c_uint8),
        ('DumpOption',c_uint8),
        ('FileList',FILE_LIST)
    ]

    

class PCI_EXPANSION_ROM_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint16),        #0xaa55
        ('Reserved',ARRAY(c_uint,0X16)),
        ('PcirOffset',c_uint16)
    ]
    

class PCI_DATA_STRUCTURE(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint32),        #PCIR
        ('VendorId',c_uint16),
        ('DeviceId',c_uint16),
        ('Reserved0',c_uint16),
        ('Length',c_uint16),
        ('Revision',c_uint8),
        ('ClassCode',ARRAY(c_uint8,3)),
        ('ImageLength',c_uint16),
        ('CodeRevision',c_uint16),
        ('CodeType',c_uint8),
        ('Indicator',c_uint8),
        ('Reserved1',c_uint16)
    ]
    
    
class PCI_3_0_DATA_STRUCTURE(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint32),        #PCIR
        ('VendorId',c_uint16),
        ('DeviceId',c_uint16),
        ('DeviceListOffset',c_uint16),
        ('Length',c_uint16),
        ('Revision',c_uint8),
        ('ClassCode',ARRAY(c_uint8,3)),
        ('ImageLength',c_uint16),
        ('CodeRevision',c_uint16),
        ('CodeType',c_uint8),
        ('Indicator',c_uint8),
        ('MaxRuntimeImageLength',c_uint16),
        ('ConfigUtilityCodeHeaderOffset',c_uint16),
        ('DMTFCLPEntryPointOffset',c_uint16)
    ]
    
    
class EFI_PCI_EXPANSION_ROM_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint16),             #0xaa55
        ('InitializationSize',c_uint16),
        ('EfiSignature',c_uint32),          #0x0EF1
        ('EfiSubsystem',c_uint16),
        ('EfiMachineType',c_uint16),
        ('CompressionType',c_uint16),
        ('Reserved',ARRAY(c_uint8,8)),
        ('EfiImageHeaderOffset',c_uint16),
        ('PcirOffset',c_uint16)
    ]
    
    
class EFI_IMAGE_DOS_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('e_magic',c_uint16),             #Magic number
        ('e_cblp',c_uint16),              #Bytes on last page of file
        ('e_cp',c_uint16),                #Pages in file
        ('e_crlc',c_uint16),              #Relocations
        ('e_cparhdr',c_uint16),           #Size of header in paragraphs
        ('e_minalloc',c_uint16),          #Minimum extra paragraphs needed
        ('e_maxalloc',c_uint16),          #Maximum extra paragraphs needed
        ('e_ss',c_uint16),                #Initial (relative) SS value
        ('e_sp',c_uint16),                #Initial SP value
        ('e_csum',c_uint16),              #Checksum
        ('e_ip',c_uint16),                #Initial IP value
        ('e_cs',c_uint16),                #Initial (relative) CS value
        ('e_lfarlc',c_uint16),            #File address of relocation table
        ('e_ovno',c_uint16),              #Overlay number
        ('e_res',ARRAY(c_uint16,4)),      #Reserved words
        ('e_oemid',c_uint16),             #OEM identifier (for e_oeminfo)
        ('e_oeminfo',c_uint16),            #OEM information; e_oemid specific
        ('e_res2',ARRAY(c_uint16,10)),    #Reserved words
        ('e_lfanew',c_uint)            #OEM information; e_oemid specific
    ]


class EFI_IMAGE_FILE_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('Machine',c_uint16),             
        ('NumberOfSections',c_uint16),
        ('TimeDateStamp',c_uint32),
        ('PointerToSymbolTable',c_uint32),
        ('NumberOfSymbols',c_uint32),
        ('SizeOfOptionalHeader',c_uint16),
        ('Characteristics',c_uint16),
    ]  



class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ = [
        ('VirtualAddress',c_uint32),
        ('Size',c_uint32),
    ]
    
    
class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _pack_ = 1
    _fileds_=[
        #Standard fields.
        ('Magic',c_uint16),
        ('MajorLinkerVersion',c_uint8),
        ('MinorLinkerVersion',c_uint8),
        ('SizeOfCode',c_uint32),
        ('SizeOfInitializedData',c_uint32),
        ('SizeOfUninitializedData',c_uint32),
        ('AddressOfEntryPoint',c_uint32),
        ('BaseOfCode',c_uint32),
        ('BaseOfData',c_uint32),
        
        #NT additional fields.
        ('ImageBase',c_uint32),
        ('SectionAlignment',c_uint32),
        ('FileAlignment',c_uint32),
        ('MajorOperatingSystemVersion',c_uint16),
        ('MinorOperatingSystemVersion',c_uint16),
        ('MajorImageVersion',c_uint16),
        ('MinorImageVersion',c_uint16),
        ('MajorSubsystemVersion',c_uint16),
        ('MinorSubsystemVersion',c_uint16),
        ('Win32VersionValue',c_uint32),
        ('SizeOfImage',c_uint32),
        ('SizeOfHeaders',c_uint32),
        ('CheckSum',c_uint32),
        ('Subsystem',c_uint16),
        ('DllCharacteristics',c_uint16),
        ('SizeOfStackReserve',c_uint32),
        ('SizeOfStackCommit',c_uint32),
        ('SizeOfHeapReserve',c_uint32),
        ('SizeOfHeapCommit',c_uint32),
        ('LoaderFlags',c_uint32),
        ('NumberOfRvaAndSizes',c_uint32),
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES)),
    ]
    
    
class EFI_IMAGE_OPTIONAL_HEADER64(Structure):
    _pack_ = 1
    _fileds_=[
        #Standard fields.
        ('Magic',c_uint16),
        ('MajorLinkerVersion',c_uint8),
        ('MinorLinkerVersion',c_uint8),
        ('SizeOfCode',c_uint32),
        ('SizeOfInitializedData',c_uint32),
        ('SizeOfUninitializedData',c_uint32),
        ('AddressOfEntryPoint',c_uint32),
        ('BaseOfCode',c_uint32),

        
        #NT additional fields.
        ('ImageBase',c_uint64),
        ('SectionAlignment',c_uint32),
        ('FileAlignment',c_uint32),
        ('MajorOperatingSystemVersion',c_uint16),
        ('MinorOperatingSystemVersion',c_uint16),
        ('MajorImageVersion',c_uint16),
        ('MinorImageVersion',c_uint16),
        ('MajorSubsystemVersion',c_uint16),
        ('MinorSubsystemVersion',c_uint16),
        ('Win32VersionValue',c_uint32),
        ('SizeOfImage',c_uint32),
        ('SizeOfHeaders',c_uint32),
        ('CheckSum',c_uint32),
        ('Subsystem',c_uint16),
        ('DllCharacteristics',c_uint16),
        ('SizeOfStackReserve',c_uint64),
        ('SizeOfStackCommit',c_uint64),
        ('SizeOfHeapReserve',c_uint64),
        ('SizeOfHeapCommit',c_uint64),
        ('LoaderFlags',c_uint32),
        ('NumberOfRvaAndSizes',c_uint32),
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES)),
    ]


class EFI_IMAGE_NT_HEADERS32(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint32),             
        ('FileHeader',EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',EFI_IMAGE_OPTIONAL_HEADER32),          
    ]
    
    
class EFI_IMAGE_NT_HEADERS64(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint32),             
        ('FileHeader',EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',EFI_IMAGE_OPTIONAL_HEADER64),          
    ]
    

class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ =[
        ('VirtualAddress',c_uint32),             
        ('Size',c_uint32)
    ]  
        

class EFI_TE_IMAGE_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('Signature',c_uint16),             #signature for TE format = "VZ"
        ('Machine',c_uint16),               #from the original file header
        ('NumberOfSections',c_uint8),       #from the original file header
        ('Subsystem',c_uint8),              #from original optional header
        ('StrippedSize',c_uint16),          #how many bytes we removed from the header
        ('AddressOfEntryPoint',c_uint32),   #offset to entry point -- from original optional header  
        ('BaseOfCode',c_uint32),            #from original image -- required for ITP debug
        ('ImageBase',c_uint64),             #from original file header
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,2)),  #only base relocation and debug directory
    ]


class EFI_IMAGE_OPTIONAL_HEADER_UNION(Union):
    _pack_ = 1
    _fields_ =[
        ('Pe32',EFI_IMAGE_NT_HEADERS32),             
        ('Pe32Plus',EFI_IMAGE_NT_HEADERS64),
        ('Te',EFI_TE_IMAGE_HEADER),          
    ]


class STRING_LOOKUP(Structure):
    _pack_ = 1
    _fields_ = [
        ('Value',c_uint16),
        ('Name',c_wchar_p)
    ]
    

mMachineTypes = [
    STRING_LOOKUP(EFI_IMAGE_MACHINE_IA32, 'IA32'),
    STRING_LOOKUP(EFI_IMAGE_MACHINE_X64, 'X64'),
    STRING_LOOKUP(EFI_IMAGE_MACHINE_EBC, 'EBC'),
    STRING_LOOKUP(EFI_IMAGE_MACHINE_ARMT, 'ARM'),
    STRING_LOOKUP(EFI_IMAGE_MACHINE_AARCH64, 'AA64'),
    STRING_LOOKUP(0, None)
]

mSubsystemTypes =[
    STRING_LOOKUP(EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION, "EFI application"),
    STRING_LOOKUP(EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER, "EFI boot service driver"),
    STRING_LOOKUP(EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER, "EFI runtime driver"),
    STRING_LOOKUP(0, None)
]