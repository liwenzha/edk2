# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

#


#from re import M
#import re
from FirmwareStorageFormat.SectionHeader import *
import logging
#import sys
import GenCrc32
import argparse
from Compress import *

EFI_GUIDED_SECTION_PROCESSING_REQUIRED = 0x01
EFI_STANDARD_COMPRESSION = 0x01
EFI_GUIDED_SECTION_AUTH_STATUS_VALID = 0x02 

EFI_SECTION_ALL = 0x00
EFI_SECTION_COMPRESSION = 0x01
EFI_SECTION_GUID_DEFINED = 0x02
EFI_SECTION_PE32 = 0x10
EFI_SECTION_PIC = 0x11
EFI_SECTION_TE = 0x12
EFI_SECTION_DXE_DEPEX = 0x13
EFI_SECTION_VERSION = 0x14
EFI_SECTION_USER_INTERFACE = 0x15
EFI_SECTION_COMPATIBILITY16 = 0x16
EFI_SECTION_FIRMWARE_VOLUME_IMAGE = 0x17
EFI_SECTION_FREEFORM_SUBTYPE_GUID = 0x18
EFI_SECTION_RAW = 0x19
EFI_SECTION_PEI_DEPEX = 0x1B
EFI_SECTION_SMM_DEPEX = 0x1C

EFI_TE_IMAGE_HEADER_SIGNATURE = 0x5A56 
IMAGE_ERROR_SUCCESS = 0


mCompressionTypeName={ "PI_NONE", "PI_STD" }

mGUIDedSectionAttribue={"NONE", "PROCESSING_REQUIRED", "AUTH_STATUS_VALID"}

mAlignName={"1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
  "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
  "512K", "1M", "2M", "4M", "8M", "16M"}


STATUS_SUCCESS = 0
STATUS_WARNING = 1
STATUS_ERROR   = 2
EFI_GUIDED_SECTION_NONE=0x80
MAX_SECTION_SIZE = 0x1000000

EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
EFI_ABORTED = 0x8000000000000000 | (21)
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_INVALID_PARAMETER = 0x8000000000000000 | (2)
EFI_NOT_FOUND = 0x8000000000000000 | (14)
RETURN_INVALID_PARAMETER = 0x8000000000000000 | (2)
RETURN_UNSUPPORTED = 0x8000000000000000 | (3)

EFI_SUCCESS = 0
RETURN_SUCCESS = 0
IMAGE_ERROR_IMAGE_READ = 1
EFI_IMAGE_DOS_SIGNATURE = 0x5A4D
EFI_IMAGE_NT_SIGNATURE = 0x00004550

EFI_NOT_COMPRESSED = 0x00


EFI_IMAGE_MACHINE_IA32 = 0x014c
EFI_IMAGE_MACHINE_X64 = 0x8664
EFI_IMAGE_MACHINE_ARMT = 0x01c2
EFI_IMAGE_MACHINE_EBC = 0x0EBC
EFI_IMAGE_MACHINE_AARCH64 = 0xAA64
EFI_IMAGE_MACHINE_LOONGARCH64 = 0x6264
EFI_IMAGE_MACHINE_RISCV64 = 0x5064

IMAGE_FILE_MACHINE_ARM = 0x01c0
EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b
EFI_IMAGE_FILE_RELOCS_STRIPPED = 0x0001
EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER = 13

EFI_IMAGE_DIRECTORY_ENTRY_DEBUG = 6
EFI_IMAGE_DEBUG_TYPE_CODEVIEW = 2



def EFI_ERROR(A):
    if A < 0:
        return True
    else:
        return False


def RETURN_ERROR(A):
    if A < 0:
        return True
    else:
        return False
    
    
#Retrieves the PE or TE Header from a PE/COFF or te image
def PeCoffLoaderGetPeHeader(ImageContext:PE_COFF_LOADER_IMAGE_CONTEXT,PeHdr:EFI_IMAGE_OPTIONAL_HEADER_UNION,TeHdr:EFI_TE_IMAGE_HEADER):
    DosHdr = EFI_IMAGE_DOS_HEADER()
    ImageContext.IsTeImage = False
    
    #Read the DOS image header
    Size = sizeof(EFI_IMAGE_DOS_HEADER)
    Status = ImageContext.ImageRead(ImageContext.Handle,0,Size,DosHdr)
    if RETURN_ERROR (Status):
        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
        return Status
    
    ImageContext.PeCoffHeaderOffset = 0
    if DosHdr.e_magic is EFI_IMAGE_DOS_SIGNATURE:
        #DOS image header is present ,so read the PE header after the DOS image header
        ImageContext.PeCoffHeaderOffset = DosHdr.e_lfanew
        
    #Get the PE/COFF Header pointer
    PeHdr =  EFI_IMAGE_OPTIONAL_HEADER_UNION(ImageContext.Handle + ImageContext.PeCoffHeaderOffset)
    if PeHdr.Pe32.Signature is not EFI_IMAGE_NT_SIGNATURE:
        #Check the PE/COFF Header Signature.If not,then try to get a TE header
        TeHdr = EFI_TE_IMAGE_HEADER(PeHdr)
        if TeHdr.Signature is not EFI_TE_IMAGE_HEADER_SIGNATURE:
            return RETURN_UNSUPPORTED
        ImageContext.IsTeImage = True
    
    return RETURN_SUCCESS


#Checks the PE or TE header of a PE/COFF or TE image to determine if it supported
def PeCoffLoaderCheckImageType(ImageContext:PE_COFF_LOADER_IMAGE_CONTEXT,PeHdr:EFI_IMAGE_OPTIONAL_HEADER_UNION,TeHdr:EFI_TE_IMAGE_HEADER):
    #See if the machine type is supported
    #We supported a native machine type(IA-32/Itanium-based)
    if ImageContext.IsTeImage is False:
        ImageContext.Machine = PeHdr.Pe32.FileHeader.Machine
    else:
        ImageContext.Machine = TeHdr.Machine
        
    if ImageContext.Machine != EFI_IMAGE_MACHINE_IA32 and ImageContext.Machine != EFI_IMAGE_MACHINE_X64\
        and ImageContext.Machine != EFI_IMAGE_MACHINE_ARMT and ImageContext.Machine != EFI_IMAGE_MACHINE_EBC\
            and ImageContext.Machine != EFI_IMAGE_MACHINE_AARCH64 and ImageContext.Machine != EFI_IMAGE_MACHINE_RISCV64\
                and ImageContext.Machine != EFI_IMAGE_MACHINE_LOONGARCH64:
                    if ImageContext.Machine == IMAGE_FILE_MACHINE_ARM:
                        ImageContext.Machine = EFI_IMAGE_MACHINE_ARMT
                        if ImageContext.IsTeImage == False:
                            PeHdr.Pe32.FileHeader.Machine = ImageContext.Machine
                        else:
                            TeHdr.Machine = ImageContext.Machine
                    else:
                        return RETURN_UNSUPPORTED
    if ImageContext.IsTeImage == False:
        ImageContext.ImageType = PeHdr.Pe32.OptionalHeader.Subsystem
    else:
        ImageContext.ImageType = TeHdr.Subsystem
    if ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\
        and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
            return RETURN_UNSUPPORTED
    return RETURN_SUCCESS


#Retrieves information on a PE/COFF image
def PeCoffLoaderGetImageInfo(ImageContext:PE_COFF_LOADER_IMAGE_CONTEXT) -> int:
    PeHdr = EFI_IMAGE_OPTIONAL_HEADER_UNION()
    TeHdr = EFI_TE_IMAGE_HEADER()
    DebugDirectoryEntry = EFI_IMAGE_DATA_DIRECTORY()
    
    if ImageContext is None:
        return RETURN_INVALID_PARAMETER
    
    #Assume success
    ImageContext.ImageError = IMAGE_ERROR_SUCCESS
    Status = PeCoffLoaderGetPeHeader(ImageContext,PeHdr,TeHdr)
    if RETURN_ERROR(Status):
        return Status
    
    #Verify machine type
    Status = PeCoffLoaderCheckImageType(ImageContext,PeHdr,TeHdr)
    if RETURN_ERROR(Status):
        return Status
    OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER()
    OptionHeader.Header = PeHdr.OptionalHeader
    
    #Retrieve the base address of the image
    if ImageContext.IsTeImage is 0:
        if PeHdr.Pe32.OptionalHeader.Magic is EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImageContext.ImageAddress = OptionHeader.Optional32.ImageBase
        else:
            ImageContext.ImageAddress = OptionHeader.Optional64.ImageBase
    else:
        ImageContext.ImageAddress = TeHdr.ImageBase + TeHdr.StrippedSize - sizeof (EFI_TE_IMAGE_HEADER)

    #Initialize the alternate destination address to 0 indicating that it
    #should not be used.
    ImageContext.DestinationAddress = 0
    
    #Initialize the codeview pointer.
    ImageContext.CodeView = None
    ImageContext.PdbPointer = None
    
    if (ImageContext.IsTeImage is 0) and (PeHdr.Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) is not 0:
        ImageContext.RelocationsStripped = True
    elif ImageContext.IsTeImage is not 0 and TeHdr.DataDirectory[0].Size is 0 and TeHdr.DataDirectory[0].VirtualAddress is 0:
        ImageContext.RelocationsStripped = True
    else:
        ImageContext.RelocationsStripped = False
        
    if ImageContext.IsTeImage is 0:
        if PeHdr.Pe32.OptionalHeader.Magic is EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImageContext.ImageSize = OptionHeader.Optional32.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional32.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional32.SizeOfHeaders
            
            if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = OptionHeader.Optional32.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
        else:
            ImageContext.ImageSize = OptionHeader.Optional64.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional64.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional64.SizeOfHeaders
            
            if OptionHeader.Optional64.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = OptionHeader.Optional64.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG]
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
                
        if DebugDirectoryEntryRva is 0:
            DebugDirectoryEntryFileOffset = 0
            SectionHeaderOffset = ImageContext.PeCoffHeaderOffset +\
                                    sizeof(c_uint32) +\
                                    sizeof(EFI_IMAGE_FILE_HEADER)+\
                                    PeHdr.Pe32.FileHeader.SizeOfOptionalHeader
            for Index in range(PeHdr.Pe32.FileHeader.NumberOfSections):
                Size = sizeof(EFI_IMAGE_SECTION_HEADER)
                SectionHeader = EFI_IMAGE_SECTION_HEADER()
                Status = ImageContext.ImageRead(ImageContext.Handle,SectionHeaderOffset,
                                                Size,SectionHeader)
                if RETURN_ERROR(Status):
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    return Status
                
                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData
                    break
                SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER)
                
            if DebugDirectoryEntryFileOffset is 0:
                for Index in range(0,DebugDirectoryEntry.Size,sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)):
                    Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY()
                    Status = ImageContext.ImageRead(ImageContext.Handle,DebugDirectoryEntryFileOffset + Index,
                                                    Size,DebugEntry)
                    if RETURN_ERROR(Status):
                        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                        return Status
                    
                    if DebugEntry.Type is EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                        ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index
                        if DebugEntry.RVA is 0 and DebugEntry.FileOffset is not 0:
                            ImageContext.ImageSize += DebugEntry.SizeOfData
                        return RETURN_SUCCESS
    else:
        ImageContext.ImageSize = 0
        ImageContext.SectionAlignment = 4096
        ImageContext.SizeOfHeaders = sizeof(EFI_TE_IMAGE_HEADER) + TeHdr.BaseOfCode - TeHdr.StrippedSize
        
        DebugDirectoryEntry = TeHdr.DataDirectory[1]
        DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
        SectionHeaderOffset = sizeof (EFI_TE_IMAGE_HEADER)
        
        DebugDirectoryEntryFileOffset= 0
        
        for Index in range(TeHdr.NumberOfSections):
            Size = sizeof (EFI_IMAGE_SECTION_HEADER)
            Status = ImageContext.ImageRead(ImageContext.Handle,SectionHeaderOffset,Size,SectionHeader)
            if RETURN_ERROR (Status):
                ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                return Status
            
            if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva -\
                    SectionHeader.VirtualAddress + SectionHeader.PointerToRawData\
                        + sizeof (EFI_TE_IMAGE_HEADER) -TeHdr.StrippedSize
                if Index <TeHdr.NumberOfSections - 1:
                    SectionHeaderOffset += (TeHdr.NumberOfSections - 1 - Index) * sizeof (EFI_IMAGE_SECTION_HEADER)
                    Index = TeHdr.NumberOfSections - 1
                    continue
            if Index + 1 is TeHdr.NumberOfSections:
                ImageContext.ImageSize = SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize +\
                    ImageContext.SectionAlignment - 1 & ~ (ImageContext.SectionAlignment - 1)
            SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER)
        
        if DebugDirectoryEntryFileOffset is not 0:
            for Index in range(0,DebugDirectoryEntry.Size,sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)):
                Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
                Status = ImageContext.ImageRead(ImageContext.Handle,DebugDirectoryEntryFileOffset,
                                                Size,DebugEntry)
                if RETURN_ERROR (Status):
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    return Status
                
                if DebugEntry.Type is EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                    ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index
                    return RETURN_SUCCESS
    return RETURN_SUCCESS


#Compares to GUIDs
def CompareGuid(Guid1:EFI_GUID,Guid2:EFI_GUID):
    #Compares 32 bits at a time
        # g1 = c_int32(Guid1)
        # g2 = c_int32(Guid2)
        # r = g1[0] - g2[0]
        # r |= g1[1] - g2[1]
        # r |= g1[2] - g2[2]
        # r |= g1[3] - g2[3]
        # return r
    if Guid1 == Guid2:
        return 0
    else:
        return 1
    
    
mZeroGuid = EFI_GUID({0x0, 0x0, 0x0, {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}})
mEfiCrc32SectionGuid = EFI_GUID({0xFC1BCDB0, 0x7D31, 0x49aa, {0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83}})


parser=argparse.ArgumentParser(description="Create Firmware File Section files  per PI Spec")
parser.add_argument("-o","--outputfile",dest="output",help="File is the SectionFile to be created.")
parser.add_argument("-s","--sectiontype",dest="SectionType",help="SectionType defined in PI spec is one type of\
                    EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED,EFI_SECTION_PE32, \
                    EFI_SECTION_PIC, EFI_SECTION_TE,EFI_SECTION_DXE_DEPEX, EFI_SECTION_COMPATIBILITY16,\
                    EFI_SECTION_USER_INTERFACE, EFI_SECTION_VERSION,EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW,\
                    EFI_SECTION_FREEFORM_SUBTYPE_GUID,EFI_SECTION_PEI_DEPEX, EFI_SECTION_SMM_DEPEX. if -s option is not given,\
                    EFI_SECTION_ALL is default section type.")
parser.add_argument("-c","--compress",dest="Type",help="Compress method type can be PI_NONE or PI_STD.\
                    if -c option is not given, PI_STD is default type.")
parser.add_argument("-g","--vendor",dest="GuidValue",help="GuidValue is one specific vendor guid value.\
                    Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
parser.add_argument("-l","--HeaderLength",dest="GuidHeaderLength",help="GuidHeaderLength is the size of header of guided data")
parser.add_argument("-r","--attributes",dest="GuidAttr",help="GuidAttr is guid section attributes, which may be\
                    PROCESSING_REQUIRED, AUTH_STATUS_VALID and NONE.\
                    if -r option is not given, default PROCESSING_REQUIRED")
parser.add_argument("-n","--name",dest="String",help="String is a NULL terminated string used in Ui section.")
parser.add_argument("-j","--buildnumber",dest="Number",help=" Number is an integer value between 0 and 65535\
                    used in Ver section.")
parser.add_argument("--sectionalign",dest="SectionAlign",help="SectionAlign points to section alignment, which support\
                    the alignment scope 0~16M. If SectionAlign is specified\
                    as 0, tool get alignment value from SectionFile. It is\
                    specified in same order that the section file is input.")
parser.add_argument("--dummy",dest="dummyfile",help="compare dummyfile with input_file to decide whether\
                    need to set PROCESSING_REQUIRED attribute.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version",dest="version",help="Show program's version number and exit.")
parser.add_argument("-h","--help",dest="help",help="Show this help message and exit.")


#Write ascii string as unicode string format to FILE
def Ascii2UnicodeString(String:str,UniString:str) -> None:
    for ch,ch1 in zip(String,UniString):
        if ch!='\0':
            ch1 = ch & 0xffff
    ch1 ='\0'
    
  
#Generate a leaf section of type other than EFI_SECTION_VERSION
#and EFI_SECTION_USER_INTERFACE. Input file must be well formed.
#The function won't validate the input file's contents. For
#common leaf sections, the input file may be a binary file.
#The utility will add section header to the file.
def GenSectionCommonLeafSection(InputFileName:str,InputFileNum:int,SectionType:int,OutFileBuffer = b'') -> int:    
    
    logger=logging.getLogger('GenSec')

    if InputFileNum > 1:
        logger.error("Invalid parameter,more than one input file specified")
        return STATUS_ERROR
    elif InputFileNum < 1:
        logger.error("Invalid parameter,no input file specified")
        return STATUS_ERROR
        
    #Open input file and get its size 
    with open (InputFileName,"rb") as InFile:
        if InFile == None:
            logger.error("Error opening file %s",InputFileName)
            return STATUS_ERROR
        status = STATUS_ERROR
        Data=InFile.read()
    
    InputFileLength = len(Data)
    CommonSect = EFI_COMMON_SECTION_HEADER()
    HeaderLength = sizeof(EFI_COMMON_SECTION_HEADER)
    TotalLength = InputFileLength + HeaderLength
    
    #Size must fit in 3 bytes,or change its header type
    if TotalLength >= MAX_SECTION_SIZE:
        CommonSect = EFI_COMMON_SECTION_HEADER2()
        HeaderLength = sizeof(EFI_COMMON_SECTION_HEADER2)
        TotalLength = HeaderLength + InputFileLength
        CommonSect.Size[0] = 0xff
        CommonSect.Size[1] = 0xff
        CommonSect.Size[2] = 0xff
        CommonSect.ExtendedSize = TotalLength
    else:
        CommonSect.SET_SECTION_SIZE(TotalLength)
    CommonSect.Type = SectionType
        
    #Write result into outputfile
    # with open(OutFileBuffer, 'wb') as OutFile:
    #     OutFile.write(struct2stream(CommonSect)) + OutFile.write(Data)
    OutFileBuffer = struct2stream(CommonSect) + Data
    status = STATUS_SUCCESS
    return status


#Converts Align String to align value (1~16M).
def StringtoAlignment(AlignBuffer:str, AlignNumber:int) -> int:

    #Check AlignBuffer
    if AlignBuffer == None:
        return EFI_INVALID_PARAMETER

    for Index in range(len(mAlignName)):
        if AlignBuffer == mAlignName [Index]:
            AlignNumber = 1 << Index
            return EFI_SUCCESS
    return EFI_INVALID_PARAMETER

   
#Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileName:str,InputFileAlign:int,InputFileNum:int,BufferLength:int,
                        FileBuffer=b'',)-> int:
    
    logger=logging.getLogger('GenSec')

    if InputFileNum < 1:
        logger.error("Invalid parameter, must specify at least one input file")
    if BufferLength == None:
        logger.error("Invalid parameter, BufferLength can't be NULL")

    Size = 0
    Offset = 0 
    TeOffset = 0

    #Go through array of file names and copy their contents
    for Index in range(InputFileNum):
        #Make sure section ends on a DWORD boundary
        while Size & 0x03 != 0:
            if FileBuffer != None and Size < BufferLength:
                FileBuffer[Size] = 0
            Size += 1
            
        #Open file and read contents 
        with open(InputFileName[Index],'rb') as InFile:
            if InFile == None:
                logger.error("Error opening file")
                return EFI_ABORTED
            Data = InFile.read()
        FileSize = len(Data)
    
        #Adjust section buffer when section alignment is required.
        if InputFileAlign != None:
            
            #Check this section is Te/Pe section, and Calculate the numbers of Te/Pe section.
            TeOffset = 0
            
            #The section might be EFI_COMMON_SECTION_HEADER2
            #But only Type needs to be checked
            if FileSize >= MAX_SECTION_SIZE:
                HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER2)
            else:
                HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER)
                
            TempSectHeader = EFI_COMMON_SECTION_HEADER2(Data[0:HeaderSize])
            
            if TempSectHeader.Type == EFI_SECTION_TE:
                #Header = EFI_TE_IMAGE_HEADER()
                TeHeaderSize = sizeof(EFI_TE_IMAGE_HEADER)
                TeHeader = EFI_TE_IMAGE_HEADER(Data[0:TeHeaderSize])
                if TeHeader.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
                    TeOffset = TeHeader.StrippedSize - sizeof(TeHeader)

            elif TempSectHeader.Type == EFI_SECTION_GUID_DEFINED:
                if FileSize >= MAX_SECTION_SIZE:

                    GuidSectHeader2 = EFI_GUID_DEFINED_SECTION2(Data[0:sizeof(EFI_GUID_DEFINED_SECTION2)])
                    if GuidSectHeader2.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED == 0:
                        HeaderSize = GuidSectHeader2.DataOffset
                else:
                    
                    GuidSectHeader = EFI_GUID_DEFINED_SECTION(Data[0:sizeof(GuidSectHeader)])
                    if GuidSectHeader.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED == 0:
                        HeaderSize = GuidSectHeader.DataOffset
        
            #Revert TeOffset to the converse value relative to Alignment
            #This is to assure the original PeImage Header at Alignment.         
            if TeOffset != 0:
                TeOffset = InputFileAlign[Index] - (TeOffset % InputFileAlign[Index])
                TeOffset = TeOffset % InputFileAlign[Index]
            
            #Make sure section data meet its alignment requirement by adding one raw pad section.
            if (InputFileAlign[Index] != 0 and (Size + HeaderSize + TeOffset) % InputFileAlign[Index]) != 0:
                Offset = (Size + sizeof(EFI_COMMON_SECTION_HEADER)+ HeaderSize + TeOffset + InputFileAlign[Index] - 1) & ~ (InputFileAlign [Index] - 1)
                Offset = Offset - Size - HeaderSize - TeOffset

                #The maximal alignment is 64K, the raw section size must be less than 0xffffff
                if FileBuffer != None and ((Size + Offset) < BufferLength):

                    str0 = b''
                    i = Offset
                    while i > 0:
                        str0 = str0 + b'0'
                        i = i - 1
                    
                    FileBuffer = FileBuffer.replace(FileBuffer[Size - 1:Size + Offset],str0)
                    #FileBuffer[Size:Size + Offset] = 0
                    SectHeader = EFI_COMMON_SECTION_HEADER(FileBuffer[Size - 1:Size + sizeof(EFI_COMMON_SECTION_HEADER)])
                    SectHeader.Type = EFI_SECTION_RAW
                    SectHeader.SET_SECTION_SIZE(Offset)
                Size = Size + Offset
            
        #Now read the contents of the file into the buffer
        #Buffer must be enough to contain the file content.
        if FileSize > 0 and FileBuffer != None and ((Size + FileSize) <= BufferLength):
            FileBuffer = FileBuffer.replace(FileBuffer[Size - 1:],Data)
            #FileBuffer[Size:] = Data
        Size += FileSize

    #Set the real required buffer size.
    if Size > BufferLength:
        BufferLength = Size
        return EFI_BUFFER_TOO_SMALL
    else:
        BufferLength = Size
        return EFI_SUCCESS


#Generate an encapsulating section of type EFI_SECTION_COMPRESSION
#Input file must be already sectioned. The function won't validate
#the input files' contents. Caller should hand in files already
#with section header.
def GenSectionCompressionSection(InputFileName:str,InputFileAlign:int,InputFileNum:int,SectCompSubType:int,OutFileBuffer = b'') -> int:    
    #Read all input file contenes into a buffer 
    #first get the size of all contents
    
    logger = logging.getLogger('GenSec')
    
    CompressFunction = COMPRESS_FUNCTION()
    
    FileBuffer = b''
    InputLength = 0
    Status = GetSectionContents(InputFileName,InputFileAlign,InputFileNum,InputLength,FileBuffer)
    
    if Status == EFI_BUFFER_TOO_SMALL:
        
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileName,InputFileAlign,InputFileName,InputLength,FileBuffer)
    
    if EFI_ERROR(Status):
        return Status
    
    if FileBuffer == None:
        return EFI_OUT_OF_RESOURCES
    
    #Now data is in FileBuffer, compress the data
    if SectCompSubType == EFI_NOT_COMPRESSED:
        CompressedLength = InputLength
        HeaderLength = sizeof(EFI_COMPRESSION_SECTION)
        if CompressedLength + HeaderLength >= MAX_SECTION_SIZE:
            HeaderLength = sizeof(EFI_COMPRESSION_SECTION2)
        TotalLength = CompressedLength + HeaderLength
        
        #Copy file buffer to the none compressed data
        OutputBuffer = b''
        OutputBuffer = OutputBuffer.replace(OutputBuffer[HeaderLength - 1:],FileBuffer)
        #OutputBuffer[HeaderLength:] = FileBuffer
        FileBuffer = OutputBuffer
        
    elif SectCompSubType == EFI_STANDARD_COMPRESSION:
        CompressFunction = COMPRESS_FUNCTION(EfiCompress)
        
    else:
        logger.error("Invalid parameter, unknown compression type")
        return EFI_ABORTED
    
    #Actual compressing 
    if CompressFunction != None:
        Status = CompressFunction(FileBuffer,InputLength,OutputBuffer,CompressedLength)
        if Status == EFI_BUFFER_TOO_SMALL:
            HeaderLength = sizeof(EFI_COMPRESSION_SECTION)
            if CompressedLength + HeaderLength >= MAX_SECTION_SIZE:
                HeaderLength = sizeof(EFI_COMPRESSION_SECTION2)
            TotalLength = CompressedLength + HeaderLength
            Status = CompressFunction (FileBuffer, InputLength, OutputBuffer[HeaderLength - 1:], CompressedLength)
            
        FileBuffer = OutputBuffer
            
        if EFI_ERROR(Status):
            return Status
        if FileBuffer == None:
            return EFI_OUT_OF_RESOURCES
    
    
    #Add the section header for the compressed data    
    if TotalLength >= MAX_SECTION_SIZE:
        CompressionSect = EFI_COMPRESSION_SECTION2()
        CompressionSect.CommonHeader.Size[0] = 0xff
        CompressionSect.CommonHeader.Size[1] = 0xff
        CompressionSect.CommonHeader.Size[2] = 0xff
        
        CompressionSect.CommonHeader.Type = EFI_SECTION_COMPRESSION
        CompressionSect.CommonHeader.ExtendedSize = TotalLength
        CompressionSect.CompressionType = SectCompSubType
        CompressionSect.UncompressedLength = InputLength
    else:
        CompressionSect = EFI_COMPRESSION_SECTION()
        CompressionSect.CommonHeader.Type = EFI_SECTION_COMPRESSION
        CompressionSect.CommonHeader.SET_SECTION_SIZE(TotalLength)
        CompressionSect.CompressionType = SectCompSubType
        CompressionSect.UncompressedLength = InputLength
    
    Header = struct2stream(CompressionSect)
    OutFileBuffer = Header + FileBuffer
    return EFI_SUCCESS


#Genarate an encapsulating section of type EFI_SECTION_GUID_DEFINED
#Input file must be already sectioned. The function won't validate
#the input files' contents. Caller should hand in files already
#with section header.
def GenSectionGuidDefinedSection(InputFileName:str,InputFileAlign:int,InputFileNum:int,VendorGuid:EFI_GUID,
                                 DataAttribute:int,DataHeaderSize:int,OutFileBuffer=b'') -> int:
    
    logger=logging.getLogger('GenSec')
    
    FileBuffer = b''
    InputLength = 0
    #Read all input file contents into a buffer
    #first get the siaze of all file contents
    Status = GetSectionContents(InputFileName,InputFileAlign,InputFileNum,InputLength,FileBuffer)
    
    if Status == EFI_BUFFER_TOO_SMALL:
        if CompareGuid(VendorGuid,mZeroGuid) == 0:
            Offset = sizeof(CRC32_SECTION_HEADER)
            if InputLength + Offset >= MAX_SECTION_SIZE:
                Offset = sizeof(CRC32_SECTION_HEADER2)
        else:
            Offset = sizeof(EFI_GUID_DEFINED_SECTION)
            if InputLength + Offset >= MAX_SECTION_SIZE:
                Offset = sizeof(EFI_GUID_DEFINED_SECTION2)
        TotalLength = InputLength + Offset
        
        if FileBuffer == None:
            return EFI_OUT_OF_RESOURCES
        
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileName,InputFileAlign,InputFileNum,InputLength,FileBuffer[Offset:])
    
    if EFI_ERROR(Status):
        logger.error("Error opening file for reading")
        return Status
    
    if InputLength == 0:
        logger.error("Invalid parameter, the size of input file %s can't be zero",InputFileName)
        return EFI_NOT_FOUND
    
    #InputLength != 0, but FileBuffer == NULL means out of resources.
    if FileBuffer == None:
        logger.error("Memory cannot be allocated")
        return EFI_OUT_OF_RESOURCES
    
    #Now data is in FileBuffer + Offset
    if CompareGuid(VendorGuid, mZeroGuid) == 0:
        #Defalut Guid section is CRC32
        Crc32InputFileContent = FileBuffer[Offset - 1:]
        Crc32Input ='InputFile'
        Crc32Output='OutPutFile'
        with open(Crc32Input,'rb') as Input:
            Input.read(Crc32InputFileContent)
        Crc32Checksum = GenCrc32.CalculateCrc32(Crc32Input,Crc32Output)
        
        if TotalLength >= MAX_SECTION_SIZE:
            Crc32GuidSect2 = CRC32_SECTION_HEADER2()
            Crc32GuidSect2.GuidSectionHeader.CommonHeader.Type = EFI_SECTION_GUID_DEFINED
            Crc32GuidSect2.GuidSectionHeader.CommonHeader.Size[0] = 0xff
            Crc32GuidSect2.GuidSectionHeader.CommonHeader.Size[1] = 0xff
            Crc32GuidSect2.GuidSectionHeader.CommonHeader.Size[2] = 0xff
            Crc32GuidSect2.GuidSectionHeader.CommonHeader.ExtendedSize = TotalLength
            Crc32GuidSect2.GuidSectionHeader.SectionDefinitionGuid = mEfiCrc32SectionGuid
            Crc32GuidSect2.GuidSectionHeader.Attributes = EFI_GUIDED_SECTION_AUTH_STATUS_VALID
            Crc32GuidSect2.GuidSectionHeader.DataOffset = sizeof (CRC32_SECTION_HEADER2)
            Crc32GuidSect2.CRC32Checksum = Crc32Checksum
            FileBuffer = struct2stream(Crc32GuidSect2) + FileBuffer
        else:
            Crc32GuidSect = CRC32_SECTION_HEADER()
            Crc32GuidSect.GuidSectionHeader.CommonHeader.Type = EFI_SECTION_GUID_DEFINED
            Crc32GuidSect.GuidSectionHeader.CommonHeader.SET_SECTION_SIZE(TotalLength)
            Crc32GuidSect.GuidSectionHeader.SectionDefinitionGuid = mEfiCrc32SectionGuid
            Crc32GuidSect.GuidSectionHeader.Attributes = EFI_GUIDED_SECTION_AUTH_STATUS_VALID
            Crc32GuidSect.GuidSectionHeader.DataOffset = sizeof (CRC32_SECTION_HEADER)
            Crc32GuidSect.CRC32Checksum = Crc32Checksum
            FileBuffer = struct2stream(Crc32GuidSect) + FileBuffer
    else:
        if TotalLength >= MAX_SECTION_SIZE:
            VendorGuidSect2 = EFI_GUID_DEFINED_SECTION2()
            VendorGuidSect2.CommonHeader.Type = EFI_SECTION_GUID_DEFINED
            VendorGuidSect2.CommonHeader.Size[0] = 0xff
            VendorGuidSect2.CommonHeader.Size[1] = 0xff
            VendorGuidSect2.CommonHeader.Size[2] = 0xff
            VendorGuidSect2.CommonHeader.ExtendedSize = InputLength + sizeof (EFI_GUID_DEFINED_SECTION2)
            VendorGuidSect2.SectionDefinitionGuid = VendorGuid
            VendorGuidSect2.Attributes = DataAttribute
            VendorGuidSect2.DataOffset = sizeof (EFI_GUID_DEFINED_SECTION2) + DataHeaderSize
            FileBuffer = struct2stream(VendorGuidSect2) + FileBuffer
        else:
            VendorGuidSect = EFI_GUID_DEFINED_SECTION2()
            VendorGuidSect.CommonHeader.Type = EFI_SECTION_GUID_DEFINED
            VendorGuidSect.CommonHeader.SET_SECTION_SIZE(TotalLength)
            VendorGuidSect.SectionDefinitionGuid = VendorGuid
            VendorGuidSect.Attributes = DataAttribute
            VendorGuidSect.DataOffset = sizeof (EFI_GUID_DEFINED_SECTION) + DataHeaderSize
            FileBuffer = struct2stream(VendorGuidSect) + FileBuffer

    OutFileBuffer = FileBuffer
    return EFI_SUCCESS


#Generate a section of type EFI_SECTION_FREEROM_SUBTYPE_GUID
#The function won't validate the input files contents.
#The utility will add section header to the file
def GenSectionSubtypeGuidSection(InputFileName:str,InputFileAlign:int,InputFileNum:int,
                                 SubTypeGuid:EFI_GUID,OutFileBuffer=b'') -> int:
    
    logger = logging.getLogger('GenSec')
    
    InputLength = 0
    # Offset = 0
    FileBuffer = None
    # TotalLength = 0
    
    if InputFileNum > 1:
        logger.error("Invalid parameter, more than one input file specified")
        return STATUS_ERROR
    elif InputFileNum < 1:
        logger.error("Invalid parameter, no input file specified")
        return STATUS_ERROR
    
    
    #Read all input file contents into a buffer
    #first get the size of all file contents
    Status = GetSectionContents(InputFileName,InputFileAlign,InputFileNum,InputLength,FileBuffer)
    
    if Status == EFI_BUFFER_TOO_SMALL:
        Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION)
        if InputLength + Offset >= MAX_SECTION_SIZE:
            Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION2)
        TotalLength = InputLength + Offset
        
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileName,InputFileAlign,InputFileNum,InputLength,FileBuffer)
    
    if EFI_ERROR(Status):
        logger.error("Error opening file for reading")
        return Status
    if InputLength == 0:
        logger.error("Invalid parameter", "the size of input file %s can't be zero", InputFileName)
        return EFI_NOT_FOUND
    
    #InputLength != 0,but FileBuffer == NULL means out of resources.
    if FileBuffer == None:
        logger.error("Resource, memory cannot be allocated")
        return EFI_OUT_OF_RESOURCES
    
    #Now data is in FileBuffer + Offset
    if TotalLength >= MAX_SECTION_SIZE:
        SubtypeGuidSect2 = EFI_FREEFORM_SUBTYPE_GUID_SECTION2()
        SubtypeGuidSect2.CommonHeader = EFI_SECTION_FREEFORM_SUBTYPE_GUID
        SubtypeGuidSect2.CommonHeader.Size[0] = 0xff
        SubtypeGuidSect2.CommonHeader.Size[1] = 0xff
        SubtypeGuidSect2.CommonHeader.Size[2] = 0xff
        SubtypeGuidSect2.CommonHeader.ExtendedSize = InputLength + sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION2)
        SubtypeGuidSect2.SubTypeGuid = SubTypeGuid
        FileBuffer = struct2stream(SubtypeGuidSect2) + FileBuffer
    else:
        SubtypeGuidSect = EFI_FREEFORM_SUBTYPE_GUID_SECTION()
        SubtypeGuidSect.CommonHeader.Type = EFI_SECTION_FREEFORM_SUBTYPE_GUID
        SubtypeGuidSect.CommonHeader.SET_SECTION_SIZE(TotalLength)
        SubtypeGuidSect2.SubTypeGuid = SubTypeGuid
        FileBuffer = struct2stream(SubtypeGuidSect) + FileBuffer

    OutFileBuffer =FileBuffer
    return EFI_SUCCESS


#Support routine for th PE/COFF file Loader that reads a buffer from a PE/COFF file
def FfsRebaseImageRead(FileHandle,FileOffset:int,ReadSize:int,Buffer) -> int:
    Destination8 = Buffer
    Source8 = FileHandle[FileOffset:]
    Length = ReadSize
    while Length:
        Destination8 = Source8 
        Destination8 += 1
        Source8 += 1
        Length -= 1
    return EFI_SUCCESS


#InFile is input file for getting alignment
#return the alignment
def GetAlignmentFromFile(InFile:str,Alignment:int = 0) -> int:
    InFileHandle = None
    PeFileBuffer = None
    #Alignment = 0
    
    with open(InFile,'rb') as InFileHandle:
        if InFileHandle is None:
            return EFI_ABORTED
        PeFileBuffer = InFileHandle.read() 
        PeFileSize = len(PeFileBuffer)
    
    CommonHeader = EFI_COMMON_SECTION_HEADER()
    CurSecHdrSize = sizeof(CommonHeader)
    ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
    ImageContext.Handle =  PeFileBuffer + CurSecHdrSize
    ImageContext.ImageRead = PE_COFF_LOADER_READ_FILE()
    Status = PeCoffLoaderGetImageInfo(ImageContext)
    if EFI_ERROR(Status):
        return Status
    
    Alignment = ImageContext.SectionAlignment
    return EFI_SUCCESS


def main():
    pass