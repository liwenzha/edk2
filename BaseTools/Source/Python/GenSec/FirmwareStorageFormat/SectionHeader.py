## @file
# This file is used to define the Section Header C Struct.
#
# Copyright (c) 2021-, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from struct import *
from ctypes import *
from FirmwareStorageFormat.Common import *

EFI_COMMON_SECTION_HEADER_LEN = 4
EFI_COMMON_SECTION_HEADER2_LEN = 8
PHYSICAL_ADDRESS = c_uint64

class EFI_COMMON_SECTION_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('Size',                     ARRAY(c_uint8, 3)),
        ('Type',                     c_uint8),
    ]

    @property
    def SECTION_SIZE(self) -> int:
        return self.Size[0] | self.Size[1] << 8 | self.Size[2] << 16
    
    #@property
    def SET_SECTION_SIZE(self,size):
        self.Size[0] = size & 0xff
        self.Size[1] = (size & 0xff00) >> 8
        self.Size[2] = (size & 0xff0000) >>16

    def Common_Header_Size(self) -> int:
        return 4

class EFI_COMMON_SECTION_HEADER2(Structure):
    _pack_ = 1
    _fields_ = [
        ('Size',                     ARRAY(c_uint8, 3)),
        ('Type',                     c_uint8),
        ('ExtendedSize',             c_uint32),
    ]

    @property
    def SECTION_SIZE(self) -> int:
        return self.ExtendedSize

    def Common_Header_Size(self) -> int:
        return 8

class EFI_COMPRESSION_SECTION(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader', EFI_COMMON_SECTION_HEADER),
        ('UncompressedLength',       c_uint32),
        ('CompressionType',          c_uint8),
    ]

    def ExtHeaderSize(self) -> int:
        return 5
    
class EFI_COMPRESSION_SECTION2(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader', EFI_COMMON_SECTION_HEADER2),
        ('UncompressedLength',    c_uint32),
        ('CompressionType',       c_uint8),
    ]
    
    def ExtHeaderSize(self) -> int:
        return 5


class EFI_GUID(Structure):
    _pack_ = 1
    _fields_ = [('Data1',c_uint32),
                ('Data2',c_uint16),
                ('Data3',c_uint16),
                ('Data4',ARRAY(c_uint8,8))
            ]


class EFI_GUID_DEFINED_SECTION(Structure):
    _pack_ = 1
    _fields_ =[('CommonHeader',EFI_COMMON_SECTION_HEADER),
               ('SectionDefinitionGuid',EFI_GUID),
               ('DataOffset',c_uint16),
               ('Attributes',c_uint16)
               ]
    
    
class EFI_GUID_DEFINED_SECTION2(Structure):
    _pack_ = 1
    _fields_ =[('CommonHeader',EFI_COMMON_SECTION_HEADER2),
               ('SectionDefinitionGuid',EFI_GUID),
               ('DataOffset',c_uint16),
               ('Attributes',c_uint16)
               ]

class CRC32_SECTION_HEADER(Structure):
    _pack_ = 1
    _fields_ = [('GuidSectionHeader',EFI_GUID_DEFINED_SECTION),
                ('CRC32Checksum',c_uint32)]
    
    
class CRC32_SECTION_HEADER2(Structure):
    _pack_ = 1
    _fields_ = [('GuidSectionHeader',EFI_GUID_DEFINED_SECTION2),
                ('CRC32Checksum',c_uint32)]


class EFI_FREEFORM_SUBTYPE_GUID_SECTION(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader',EFI_COMMON_SECTION_HEADER),
        ('SubTypeGuid',              EFI_GUID)
    ]

    def ExtHeaderSize(self) -> int:
        return 16


class EFI_FREEFORM_SUBTYPE_GUID_SECTION2(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader',EFI_COMMON_SECTION_HEADER2),
        ('SubTypeGuid',              EFI_GUID)
    ]

class EFI_GUID_DEFINED_SECTION(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader', EFI_COMMON_SECTION_HEADER),
        ('SectionDefinitionGuid',    EFI_GUID),
        ('DataOffset',               c_uint16),
        ('Attributes',               c_uint16)
    ]

    def ExtHeaderSize(self) -> int:
        return 20
    
class EFI_GUID_DEFINED_SECTION2(Structure):
    _pack_ = 1
    _fields_ = [
        ('CommonHeader', EFI_COMMON_SECTION_HEADER2),
        ('SectionDefinitionGuid',    GUID),
        ('DataOffset',               c_uint16),
        ('Attributes',               c_uint16)
    ]

    def ExtHeaderSize(self) -> int:
        return 36
    
class EFI_IMAGE_DATA_DIRECTORY(Structure):
    _pack_ = 1
    _fields_ =[
        ('VirtualAddress',c_uint32),
        ('Size',c_uint32)
    ]
    
class EFI_TE_IMAGE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('Signature',c_uint16),
        ('Machine',c_uint16),
        ('NumberOfSections',c_uint8),
        ('Subsystem',c_uint8),
        ('StrippedSize',c_uint16),
        ('AddressOfEntryPoint',c_uint32),
        ('BaseOfCode',c_uint32),
        ('ImageBase',c_uint64),
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,2)),
    ]
    
    def ExtHeaderSize(self) -> int:
        return 40


class PE_COFF_LOADER_READ_FILE(Structure):
    _pack_=  1
    _fields_ =[('FileOffset',c_uint64),
               ('ReadSize',c_uint64),
               ('FileHandle',c_void_p),
               ('Buffer',c_void_p)]


class PE_COFF_LOADER_IMAGE_CONTEXT(Structure):
    _pack_ = 1
    _field_ = [('ImageAddress',PHYSICAL_ADDRESS),
               ('ImageSize',c_uint64),
               ('DestinationAddress',PHYSICAL_ADDRESS),
               ('EntryPoint',PHYSICAL_ADDRESS),
               ('ImageRead',PE_COFF_LOADER_READ_FILE),
               ('Handle',c_void_p),
               ('FixupData',c_void_p),
               ('SectionAlignment',c_uint32),
               ('PeCoffHeaderOffset',c_uint32),
               ('DebugDirectoryEntryRva',c_uint32),
               ('CodeView',c_void_p),
               ('PdbPointer',c_char),
               ('SizeOfHeaders',c_uint64),
               ('ImageCodeMemoryType',c_uint32),
               ('ImageDataMemoryType',c_uint32),
               ('ImageError',c_uint32),
               ('FixupDataSize',c_uint64),
               ('Machine',c_uint16),
               ('ImageType',c_uint16),
               ('RelocationsStripped',c_bool),
               ('IsTeImage',c_bool)]


class EFI_IMAGE_FILE_HEADER(Structure):
    _pack_ = 1
    _fields_ =[
        ('Machine',c_uint16),
        ('NumberOfSections',c_uint16),
        ('TimeDateStamp',c_uint32),
        ('PointerToSymbolTable',c_uint32),
        ('NumberOfSymbols',c_uint32),
        ('SizeOfOptionalHeader',c_uint16),
        ('Characteristics',c_uint16)
    ]


EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES = 16
class EFI_IMAGE_OPTIONAL_HEADER32(Structure):
    _pack_ = 1
    _fields_ =[
        #Standard fields
        ('Magic',c_uint16),
        ('MajorLinkerVersion',c_uint8),
        ('MinorLinkerVersion',c_uint8),
        ('SizeOfCode',c_uint32),
        ('SizeOfInitializedData',c_uint32),
        ('SizeOfUninitializedData',c_uint32),
        ('AddressOfEntryPoint',c_uint32),
        ('BaseOfCode',c_uint32),
        ('BaseOfData',c_uint32),
        
        #NT additional fields
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
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES))
    ]


class EFI_IMAGE_OPTIONAL_HEADER64(Structure):
    _pack_ = 1
    _fields_ = [
        #Standard fields
        ('Magic',c_uint16),
        ('MajorLinkerVersion',c_uint8),
        ('MinorLinkerVersion',c_uint8),
        ('SizeOfCode',c_uint32),
        ('SizeOfInitializedData',c_uint32),
        ('SizeOfUninitializedData',c_uint32),
        ('AddressOfEntryPoint',c_uint32),
        ('BaseOfCode',c_uint32),
        
        #NT additional fields
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
        ('DataDirectory',ARRAY(EFI_IMAGE_DATA_DIRECTORY,EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES))
    ]


class EFI_IMAGE_NT_HEADERS32(Structure):
    _pack_ =1
    _fields_= [
        ('Signature',c_uint32),
        ('FileHeader',EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',EFI_IMAGE_OPTIONAL_HEADER32)
    ]


class EFI_IMAGE_NT_HEADERS64(Structure):
    _pack_ =1
    _fields_= [
        ('Signature',c_uint32),
        ('FileHeader',EFI_IMAGE_FILE_HEADER),
        ('OptionalHeader',EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class EFI_IMAGE_OPTIONAL_HEADER_UNION(Union):
    _pack_ = 1
    _fields_ =[
        ('Pe32',EFI_IMAGE_NT_HEADERS32),
        ('Pe32Plus',EFI_IMAGE_NT_HEADERS64),
        ('Te',EFI_TE_IMAGE_HEADER)
    ]


class EFI_IMAGE_DOS_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('e_magic',c_uint16),
        ('e_cblp',c_uint16),
        ('e_cp',c_uint16),
        ('e_crlc',c_uint16),
        ('e_cparhdr',c_uint16),
        ('e_minalloc',c_uint16),
        ('e_maxalloc',c_uint16),
        ('e_ss',c_uint16),
        ('e_sp',c_uint16),
        ('e_csum',c_uint16),
        ('e_ip',c_uint16),
        ('e_cs',c_uint16),
        ('e_lfarlc',c_uint16),
        ('e_ovno',c_uint16),
        ('e_res',ARRAY(c_uint16,4)),
        ('e_oemid',c_uint16),
        ('e_oeminfo',c_uint16),
        ('e_res2',ARRAY(c_uint16,10)),
        ('e_lfanew',c_uint32)
        
    ]
    

class EFI_IMAGE_OPTIONAL_HEADER_POINTER(Union):
    _pack_ = 1
    _fields_= [
        ('Header',c_void_p),
        ('Optional32',EFI_IMAGE_OPTIONAL_HEADER32),
        ('Optional64',EFI_IMAGE_OPTIONAL_HEADER64)
    ]


class Misc(Union):
    _pack_ = 1
    _fields_ = [
        ('PhysicalAddress',c_uint32),
        ('VirtualSize',c_uint32)
    ] 


EFI_IMAGE_SIZEOF_SHORT_NAME = 8
class EFI_IMAGE_SECTION_HEADER(Structure):
     _pack_ = 1
     _fields_ = [
         ('Name',ARRAY(c_uint8,EFI_IMAGE_SIZEOF_SHORT_NAME)),
         ('Misc',Misc),
         ('VirtualAddress',c_uint32),
         ('SizeOfRawData',c_uint32),
         ('PointerToRawData',c_uint32),
         ('PointerToRelocations',c_uint32),
         ('PointerToLinenumbers',c_uint32),
         ('NumberOfRelocations',c_uint16),
         ('NumberOfLinenumbers',c_uint16),
         ('Characteristics',c_uint32)
     ]


class EFI_IMAGE_DEBUG_DIRECTORY_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('Characteristics',c_uint32),
        ('TimeDateStamp',c_uint32),
        ('MajorVersion',c_uint16),
        ('MinorVersion',c_uint16),
        ('Type',c_uint32),
        ('SizeOfData',c_uint32),
        ('RVA',c_uint32),
        ('FileOffset',c_uint32)
    ]



def SET_EFI_VERSION_SECTION(nums:int):
    class EFI_VERSION_SECTION(Structure):
        _pack_ = 1
        _fields_ = [
            ('CommonHeader',EFI_COMMON_SECTION_HEADER),
            ('BuildNumber',c_uint16),
            ('VersionString',ARRAY(c_uint16,nums))
        ]
        def __init__(self,nums):
            self.CommonHeader = EFI_COMMON_SECTION_HEADER()
    return EFI_VERSION_SECTION(nums)


def SET_EFI_USER_INTERFACE_SECTION(nums:int):
    class EFI_USER_INTERFACE_SECTION(Structure):
        _pack_ = 1
        _fields_ = [
            ('CommonHeader',EFI_COMMON_SECTION_HEADER),
            ('FileNameString',ARRAY(c_uint16,nums))
        ]
        def __init__(self,nums):
            self.CommonHeader = EFI_COMMON_SECTION_HEADER()
    return EFI_USER_INTERFACE_SECTION(nums)


def Get_USER_INTERFACE_Header(nums: int):
    class EFI_SECTION_USER_INTERFACE(Structure):
        _pack_ = 1
        _fields_ = [
            ('FileNameString',       ARRAY(c_uint16, nums)),
        ]

        def ExtHeaderSize(self) -> int:
            return 2 * nums

        def GetUiString(self) -> str:
            UiString = ''
            for i in range(nums):
                if self.FileNameString[i]:
                    UiString += chr(self.FileNameString[i])
            return UiString

    return EFI_SECTION_USER_INTERFACE

def Get_VERSION_Header(nums: int):
    class EFI_SECTION_VERSION(Structure):
        _pack_ = 1
        _fields_ = [
            ('BuildNumber',          c_uint16),
            ('VersionString',        ARRAY(c_uint16, nums)),
        ]

        def ExtHeaderSize(self) -> int:
            return 2 * (nums+1)

        def GetVersionString(self) -> str:
            VersionString = ''
            for i in range(nums):
                if self.VersionString[i]:
                    VersionString += chr(self.VersionString[i])
            return VersionString

    return EFI_SECTION_VERSION
