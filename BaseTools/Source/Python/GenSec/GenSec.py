# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent


from FirmwareStorageFormat.SectionHeader import *
import logging
import sys
import GenCrc32
import argparse
from EfiCompress import *


UTILITY_NAME = 'GenSec'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1



mSectionTypeName =[
    None,
    "EFI_SECTION_COMPRESSION",
    "EFI_SECTION_GUID_DEFINED",
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    None,
    "EFI_SECTION_PE32",
    "EFI_SECTION_PIC",
    "EFI_SECTION_TE",
    "EFI_SECTION_DXE_DEPEX",
    "EFI_SECTION_VERSION",
    "EFI_SECTION_USER_INTERFACE",
    "EFI_SECTION_COMPATIBILITY16",
    "EFI_SECTION_FIRMWARE_VOLUME_IMAGE",
    "EFI_SECTION_FREEFORM_SUBTYPE_GUID",
    "EFI_SECTION_RAW",
    None,
    "EFI_SECTION_PEI_DEPEX",
    "EFI_SECTION_SMM_DEPEX"
]

mCompressionTypeName={ "PI_NONE", "PI_STD" }

EFI_GUIDED_SECTION_NONE=0x80
mGUIDedSectionAttribue={"NONE", "PROCESSING_REQUIRED", "AUTH_STATUS_VALID"}

mAlignName={"1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
  "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
  "512K", "1M", "2M", "4M", "8M", "16M"}


STATUS_SUCCESS = 0
STATUS_WARNING = 1
STATUS_ERROR   = 2


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
    if DosHdr.e_magic == EFI_IMAGE_DOS_SIGNATURE:
        #DOS image header is present ,so read the PE header after the DOS image header
        ImageContext.PeCoffHeaderOffset = DosHdr.e_lfanew
        
    #Get the PE/COFF Header pointer
    PeHdr =  EFI_IMAGE_OPTIONAL_HEADER_UNION(ImageContext.Handle + ImageContext.PeCoffHeaderOffset)
    if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
        #Check the PE/COFF Header Signature.If not,then try to get a TE header
        TeHdr = EFI_TE_IMAGE_HEADER(PeHdr)
        if TeHdr.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
            return RETURN_UNSUPPORTED
        ImageContext.IsTeImage = True
    
    return RETURN_SUCCESS


#Checks the PE or TE header of a PE/COFF or TE image to determine if it supported
def PeCoffLoaderCheckImageType(ImageContext:PE_COFF_LOADER_IMAGE_CONTEXT,PeHdr:EFI_IMAGE_OPTIONAL_HEADER_UNION,TeHdr:EFI_TE_IMAGE_HEADER):
    #See if the machine type is supported
    #We supported a native machine type(IA-32/Itanium-based)
    if ImageContext.IsTeImage == False:
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
    SectionHeader = EFI_IMAGE_SECTION_HEADER()
    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY()
    OptionHeader = EFI_IMAGE_OPTIONAL_HEADER_POINTER()
    DebugDirectoryEntryRva = 0
    
    if ImageContext == None:
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
    OptionHeader.Header = PeHdr.Pe32.OptionalHeader
    
    #Retrieve the base address of the image
    if ImageContext.IsTeImage == 0:
        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
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
    
    if (ImageContext.IsTeImage == 0) and (PeHdr.Pe32.FileHeader.Characteristics & EFI_IMAGE_FILE_RELOCS_STRIPPED) != 0:
        ImageContext.RelocationsStripped = True
    elif ImageContext.IsTeImage != 0 and TeHdr.DataDirectory[0].Size == 0 and TeHdr.DataDirectory[0].VirtualAddress == 0:
        ImageContext.RelocationsStripped = True
    else:
        ImageContext.RelocationsStripped = False
        
    if ImageContext.IsTeImage == 0:
        if PeHdr.Pe32.OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ImageContext.ImageSize = OptionHeader.Optional32.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional32.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional32.SizeOfHeaders
            
            if OptionHeader.Optional32.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = EFI_IMAGE_DATA_DIRECTORY(OptionHeader.Optional32.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG])
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
        else:
            ImageContext.ImageSize = OptionHeader.Optional64.SizeOfImage
            ImageContext.SectionAlignment = OptionHeader.Optional64.SectionAlignment
            ImageContext.SizeOfHeaders = OptionHeader.Optional64.SizeOfHeaders
            
            if OptionHeader.Optional64.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_DEBUG:
                DebugDirectoryEntry = EFI_IMAGE_DATA_DIRECTORY(OptionHeader.Optional64.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_DEBUG])
                DebugDirectoryEntryRva = DebugDirectoryEntry.VirtualAddress
                
        if DebugDirectoryEntryRva != 0:
            DebugDirectoryEntryFileOffset = 0
            SectionHeaderOffset = ImageContext.PeCoffHeaderOffset +\
                                    sizeof(c_uint32) +\
                                    sizeof(EFI_IMAGE_FILE_HEADER)+\
                                    PeHdr.Pe32.FileHeader.SizeOfOptionalHeader
                                    
            for Index in range(PeHdr.Pe32.FileHeader.NumberOfSections):
                #Read section header from file
                Size = sizeof(EFI_IMAGE_SECTION_HEADER)
                Status = ImageContext.ImageRead(ImageContext.Handle,SectionHeaderOffset,
                                                Size,SectionHeader)
                if RETURN_ERROR(Status):
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    return Status
                
                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData
                    break
                SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER)
                
                if DebugDirectoryEntryFileOffset != 0:
                    for Index in range(0,DebugDirectoryEntry.Size,sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)):
                        Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
                        Status = ImageContext.ImageRead(ImageContext.Handle,DebugDirectoryEntryFileOffset + Index,
                                                        Size,DebugEntry)
                        if RETURN_ERROR(Status):
                            ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                            return Status
    
                        if DebugEntry.Type == EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                            ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index
                            if DebugEntry.RVA == 0 and DebugEntry.FileOffset != 0:
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
                #Read section header from file
                Size = sizeof (EFI_IMAGE_SECTION_HEADER)
                Status = ImageContext.ImageRead(ImageContext.Handle,SectionHeaderOffset,Size,SectionHeader)
                if RETURN_ERROR (Status):
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    return Status
                
                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva -\
                        SectionHeader.VirtualAddress + SectionHeader.PointerToRawData\
                            + sizeof (EFI_TE_IMAGE_HEADER) -TeHdr.StrippedSize
                            
                    #File offset of the debug directory was found, if this is not the last
                    #section,then skip to the last section for calculating the image size
                    if Index <TeHdr.NumberOfSections - 1:
                        SectionHeaderOffset += (TeHdr.NumberOfSections - 1 - Index) * sizeof (EFI_IMAGE_SECTION_HEADER)
                        Index = TeHdr.NumberOfSections - 1
                        continue
                if Index + 1 == TeHdr.NumberOfSections:
                    ImageContext.ImageSize = SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize +\
                        ImageContext.SectionAlignment - 1 & ~ (ImageContext.SectionAlignment - 1)
                SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER)
            
            if DebugDirectoryEntryFileOffset != 0:
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


#Determine if an integer represents character that is a hex digit
def isxdigit(c:int):
    return ('0' <= c and c <= '9') or ('a' <= c and c <= 'f') or ('A' <= c and c <= 'F')



#Converts a null terminated ascii string that represents a number into a UINT64 value.
def AsciiStringToUint64(AsciiString:str,IsHex:bool,ReturnValue:int):
    Value = 0
    Index = 0

    #Check input parameter
    if AsciiString == None or ReturnValue == None or len(AsciiString) > 0xff:
        return EFI_INVALID_PARAMETER
    while AsciiString[Index] == ' ':
        Index += 1

    #Add each character to the result

    #Skip first two chars only if the string starts with '0x' or '0X'
    if AsciiString[Index] == '0' and (AsciiString[Index + 1] == 'x' or AsciiString[Index + 1] == 'X'):
        IsHex = True
        Index += 2
    if IsHex:
        #Convert the hex string.
        while AsciiString[Index] != '\0':
            CurrentChar = AsciiString[Index]
            if CurrentChar == ' ':
                break
            
            #Verify Hex string
            if isxdigit(int(CurrentChar)) == 0:
                return EFI_ABORTED
            
            Value *= 16
            if CurrentChar >= '0' and CurrentChar <= '9':
                Value += CurrentChar - '0'
            elif CurrentChar >= 'a' and CurrentChar <= 'f':
                Value += CurrentChar - 'a' + 10
            elif CurrentChar >= 'A' and CurrentChar <= 'F':
                Value += CurrentChar - 'A' + 10
            Index += 1
        ReturnValue = Value
    else:
        #Convert dec string is a number
        while Index < len (AsciiString):
            CurrentChar = AsciiString[Index]
            if CurrentChar == ' ':
                break
            
            #Verify Dec string
            if isdigit(int(CurrentChar)) == 0:
                return EFI_ABORTED
            Value = Value * 10
            Value += CurrentChar - '0'
            Index += 1
        ReturnValue = Value
    return EFI_SUCCESS


def isdigit(c:int):
    return '0' <= c and c <= '9'
    

#Converts a string to an EFI_GUID.
def StringToGuid(AsciiGuidBuffer:str,GuidBuffer:EFI_GUID):
    Data4 = []*8
    logger =logging.getLogger('GenSec')
    if AsciiGuidBuffer == None or GuidBuffer == None:
        return EFI_INVALID_PARAMETER
    #Check Guid Format strictly xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Index = 0
    while AsciiGuidBuffer[Index] != '\0' and Index < 37:
        if Index == 8 or Index == 13 or Index == 18 or Index == 23:
            if AsciiGuidBuffer[Index] != '-':
                break
        else:
            if (AsciiGuidBuffer[Index] >= '0' and AsciiGuidBuffer[Index] <= '9') or\
                (AsciiGuidBuffer[Index] >= 'a' and AsciiGuidBuffer[Index] <= 'f') or\
                    (AsciiGuidBuffer[Index] >= 'A' and AsciiGuidBuffer[Index] <= 'F'):
                    continue
            else:
                break
        Index += 1

    if Index < 36 or AsciiGuidBuffer[36] != '\0':
        logger.error("Invalid option value")
        return EFI_ABORTED

    #Scan the guid string into the buffer
    if True:
       Data1 = AsciiGuidBuffer[0:8]
       Data2 = AsciiGuidBuffer[8:12]
       Data3 = AsciiGuidBuffer[12:16]
       Data4[0] = AsciiGuidBuffer[16:18]
       Data4[1] = AsciiGuidBuffer[18:20]
       Data4[2] = AsciiGuidBuffer[20:22]
       Data4[3] = AsciiGuidBuffer[22:24]
       Data4[4] = AsciiGuidBuffer[24:26]
       Data4[5] = AsciiGuidBuffer[26:28]
       Data4[6] = AsciiGuidBuffer[28:30]
       Data4[7] = AsciiGuidBuffer[30:32]
       if len(Data1 + Data2 + Data3+Data4[0]+Data4[1]+Data4[2]+\
            Data4[3]+Data4[4]+Data4[5]+Data4[6]+Data4[7]) != AsciiGuidBuffer:
            Index = 0
       else:
            Index = 11


    #Verify the correct number of items were scanned.
    if Index != 11:
        logger.error("Invalid option value")
        return EFI_ABORTED

    #Copy the data into our GUID.
    GuidBuffer.Data1     = Data1
    GuidBuffer.Data2     = Data2
    GuidBuffer.Data3     = Data3
    GuidBuffer.Data4[0]  = Data4[0]
    GuidBuffer.Data4[1]  = Data4[1]
    GuidBuffer.Data4[2]  = Data4[2]
    GuidBuffer.Data4[3]  = Data4[3]
    GuidBuffer.Data4[4]  = Data4[4]
    GuidBuffer.Data4[5]  = Data4[5]
    GuidBuffer.Data4[6]  = Data4[6]
    GuidBuffer.Data4[7]  = Data4[7]



mZeroGuid = EFI_GUID(0x0,0x0,0x0,(0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0))
# mZeroGuid.Data1 = 0x0
# mZeroGuid.Data2 = 0x0
# mZeroGuid.Data3 = 0x0
# mZeroGuid.Data4 = (0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0)

mEfiCrc32SectionGuid = EFI_GUID()
mEfiCrc32SectionGuid.Data1 = 0xFC1BCDB0
mEfiCrc32SectionGuid.Data2 = 0x7D31
mEfiCrc32SectionGuid.Data3 = 0x49aa
mEfiCrc32SectionGuid.Data4 = (0x93, 0x6A, 0xA4, 0x60, 0x0D, 0x9D, 0xD0, 0x83)


parser=argparse.ArgumentParser(description="Create Firmware File Section files  per PI Spec")
parser.add_argument("-o","--outputfile",dest="output",help="File is the SectionFile to be created.")
parser.add_argument("-s","--sectiontype",dest="SectionType",help="SectionType defined in PI spec is one type of\
                    EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED,EFI_SECTION_PE32, \
                    EFI_SECTION_PIC, EFI_SECTION_TE,EFI_SECTION_DXE_DEPEX, EFI_SECTION_COMPATIBILITY16,\
                    EFI_SECTION_USER_INTERFACE, EFI_SECTION_VERSION,EFI_SECTION_FIRMWARE_VOLUME_IMAGE, EFI_SECTION_RAW,\
                    EFI_SECTION_FREEFORM_SUBTYPE_GUID,EFI_SECTION_PEI_DEPEX, EFI_SECTION_SMM_DEPEX. if -s option is not given,\
                    EFI_SECTION_ALL is default section type.")
parser.add_argument("-c","--compress",dest="Compress",help="Compress method type can be PI_NONE or PI_STD.\
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
parser.add_argument("--version", action="version", version='%(prog)s Version 1.0',
                    help="Show program's version number and exit.")


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
def GenSectionCommonLeafSection(SectionType:int,InputFileNum:int,InputFileName=[],OutFileBuffer = b'') -> int:    
    
    logger=logging.getLogger('GenSec')

    if InputFileNum > 1:
        logger.error("Invalid parameter,more than one input file specified")
        return STATUS_ERROR
    elif InputFileNum < 1:
        logger.error("Invalid parameter,no input file specified")
        return STATUS_ERROR
        
    #Open input file and get its size 
    with open (InputFileName[0],"rb") as InFile:
        if InFile == None:
            logger.error("Error opening file %s",InputFileName[0])
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
    OutFileBuffer = struct2stream(CommonSect) + Data
    status = STATUS_SUCCESS
    return status


#Converts Align String to align value (1~16M).
def StringtoAlignment(AlignBuffer:str, AlignNumber:int) -> int:

    #Check AlignBuffer
    if AlignBuffer == None:
        return EFI_INVALID_PARAMETER

    for ch in mAlignName:
        if AlignBuffer == ch:
            AlignNumber = 1 << mAlignName.index(ch)
            return EFI_SUCCESS
    return EFI_INVALID_PARAMETER

#Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileNum:int,BufferLength:int,InputFileName=[],InputFileAlign=[],
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
                FileBuffer = FileBuffer + b'0'
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
                
            #TempSectHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Data[0:sizeof(HeaderSize)])
            TempSectHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Data)
            
            if TempSectHeader.Type == EFI_SECTION_TE:
                #Header = EFI_TE_IMAGE_HEADER()
                TeHeaderSize = sizeof(EFI_TE_IMAGE_HEADER)
                TeHeader = EFI_TE_IMAGE_HEADER.from_buffer_copy(Data)
                if TeHeader.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
                    TeOffset = TeHeader.StrippedSize - sizeof(TeHeader)

            elif TempSectHeader.Type == EFI_SECTION_GUID_DEFINED:
                if FileSize >= MAX_SECTION_SIZE:
                    GuidSectHeader2 = EFI_GUID_DEFINED_SECTION2.from_buffer_copy(Data)
                    if GuidSectHeader2.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED == 0:
                        HeaderSize = GuidSectHeader2.DataOffset
                else:
                    GuidSectHeader = EFI_GUID_DEFINED_SECTION.from_buffer_copy(Data)
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
                Offset1 = Offset

                #The maximal alignment is 64K, the raw section size must be less than 0xffffff
                if FileBuffer != None and ((Size + Offset) < BufferLength):
                    # while Offset1 > 0:
                    #     FileBuffer = FileBuffer + b'0'
                    #     Offset1 -= 1
                    SectHeader = EFI_COMMON_SECTION_HEADER()
                    SectHeader.Type = EFI_SECTION_RAW
                    SectHeader.SET_SECTION_SIZE(Offset)
                    #FileBuffer = FileBuffer.replace(FileBuffer[Size:Size + sizeof(EFI_COMMON_SECTION_HEADER)],struct2stream(SectHeader))
                    FileBuffer = struct2stream(SectHeader)
                Size = Size + Offset
            
        #Now read the contents of the file into the buffer
        #Buffer must be enough to contain the file content.
        if FileSize > 0 and FileBuffer != None and ((Size + FileSize) <= BufferLength):
            FileBuffer = FileBuffer + Data
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
def GenSectionCompressionSection(InputFileNum:int,SectCompSubType:int,InputFileName=[],InputFileAlign=[],OutFileBuffer = b'') -> int:    
    #Read all input file contenes into a buffer 
    #first get the size of all contents
    
    logger = logging.getLogger('GenSec')
    
    CompressFunction = None
    FileBuffer = b''
    OutputBuffer = b''
    InputLength = 0
    CompressedLength = 0
    Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
    if Status == EFI_BUFFER_TOO_SMALL:
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
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
        OutputBuffer = FileBuffer
        
    elif SectCompSubType == EFI_STANDARD_COMPRESSION:
        CompressFunction = EfiCompress
        
    else:
        logger.error("Invalid parameter, unknown compression type")
        return EFI_ABORTED
    
    #Actual compressing 
    if CompressFunction != None:
        Status = CompressFunction(InputLength,CompressedLength,FileBuffer,OutputBuffer)
        if Status == EFI_BUFFER_TOO_SMALL:
            HeaderLength = sizeof(EFI_COMPRESSION_SECTION)
            if CompressedLength + HeaderLength >= MAX_SECTION_SIZE:
                HeaderLength = sizeof(EFI_COMPRESSION_SECTION2)
            TotalLength = CompressedLength + HeaderLength
            Status = CompressFunction (FileBuffer, InputLength, OutputBuffer, CompressedLength)
            
        FileBuffer = OutputBuffer
            
        if EFI_ERROR(Status):
            return Status
        if FileBuffer == None:
            return EFI_OUT_OF_RESOURCES
    
    #Add the section header for the compressed data    
    if TotalLength >= MAX_SECTION_SIZE:
        CompressionSect2 = EFI_COMPRESSION_SECTION2()
        CompressionSect2.CommonHeader.Size[0] = 0xff
        CompressionSect2.CommonHeader.Size[1] = 0xff
        CompressionSect2.CommonHeader.Size[2] = 0xff
        
        CompressionSect2.CommonHeader.Type = EFI_SECTION_COMPRESSION
        CompressionSect2.CommonHeader.ExtendedSize = TotalLength
        CompressionSect2.CompressionType = SectCompSubType
        CompressionSect2.UncompressedLength = InputLength
        FileBuffer = struct2stream(CompressionSect2) + FileBuffer
    else:
        CompressionSect = EFI_COMPRESSION_SECTION()
        CompressionSect.CommonHeader.Type = EFI_SECTION_COMPRESSION
        CompressionSect.CommonHeader.SET_SECTION_SIZE(TotalLength)
        CompressionSect.CompressionType = SectCompSubType
        CompressionSect.UncompressedLength = InputLength
        FileBuffer = struct2stream(CompressionSect) + FileBuffer
    
    OutFileBuffer = FileBuffer
    return EFI_SUCCESS


#Genarate an encapsulating section of type EFI_SECTION_GUID_DEFINED
#Input file must be already sectioned. The function won't validate
#the input files' contents. Caller should hand in files already
#with section header.
def GenSectionGuidDefinedSection(InputFileNum:int,VendorGuid:EFI_GUID,DataAttribute:int,
                                 DataHeaderSize:int,InputFileName=[],InputFileAlign=[],OutFileBuffer=b'') -> int:
    
    logger=logging.getLogger('GenSec')
    
    FileBuffer = b''
    InputLength = 0
    Offset = 0
    #Read all input file contents into a buffer
    #first get the size of all file contents
    Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
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
            logger.error("Resource, memory cannot be allocated")
            return EFI_OUT_OF_RESOURCES
        
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
    if EFI_ERROR(Status):
        logger.error("Error opening file for reading")
        return Status
    
    if InputLength == 0:
        logger.error("Invalid parameter, the size of input file %s can't be zero",InputFileName[0])
        return EFI_NOT_FOUND
    
    #InputLength != 0, but FileBuffer == NULL means out of resources.
    if FileBuffer == None:
        logger.error("Memory cannot be allocated")
        return EFI_OUT_OF_RESOURCES
    
    #Now data is in FileBuffer
    if CompareGuid(VendorGuid, mZeroGuid) == 0:
        #Defalut Guid section is CRC32
        Crc32InputFileContent = FileBuffer
        Crc32Input ='InputFile'
        Crc32Output='OutPutFile'
        with open(Crc32Input,'rb') as Input:
            Input.read(Crc32InputFileContent)
        Crc32Checksum = GenCrc32.CalculateCrc32(Crc32Input,Crc32Output)
        Crc32Checksum = int.from_bytes(byteorder='little')
        
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
            VendorGuidSect = EFI_GUID_DEFINED_SECTION()
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
def GenSectionSubtypeGuidSection(InputFileNum:int,SubTypeGuid:EFI_GUID,
                                InputFileName=[],InputFileAlign=[],OutFileBuffer=b'') -> int:
    
    logger = logging.getLogger('GenSec')
    
    InputLength = 0
    Offset = 0
    FileBuffer = b''

    
    if InputFileNum > 1:
        logger.error("Invalid parameter, more than one input file specified")
        return STATUS_ERROR
    elif InputFileNum < 1:
        logger.error("Invalid parameter, no input file specified")
        return STATUS_ERROR
    
    
    #Read all input file contents into a buffer
    #first get the size of all file contents
    Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
    if Status == EFI_BUFFER_TOO_SMALL:
        Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION)
        if InputLength + Offset >= MAX_SECTION_SIZE:
            Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION2)
        TotalLength = InputLength + Offset
        
        #Read all input file contents into a buffer
        Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    
    if EFI_ERROR(Status):
        logger.error("Error opening file for reading")
        return Status
    if InputLength == 0:
        logger.error("Invalid parameter", "the size of input file %s can't be zero", InputFileName[0])
        return EFI_NOT_FOUND
    
    #InputLength != 0,but FileBuffer == NULL means out of resources.
    if FileBuffer == None:
        logger.error("Resource, memory cannot be allocated")
        return EFI_OUT_OF_RESOURCES
    
    #Now data is in FileBuffer
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
def FfsRebaseImageRead(FileOffset:int,ReadSize:int,FileHandle = b'',Buffer = b'') -> int:
    Destination8 = Buffer
    Source8 = FileHandle[FileOffset:]
    Length = ReadSize
    while Length - 1:
        Destination8 = Source8 
        Destination8 += 1
        Source8 += 1
        #Length -= 1
    return EFI_SUCCESS


#InFile is input file for getting alignment
#return the alignment
def GetAlignmentFromFile(InFile:str,Alignment:int = 0) -> int:
    
    logger = logging.getLogger('GenSec')

    PeFileBuffer = b''
    
    with open(InFile,'rb') as InFileHandle:
        if InFileHandle == None:
            logger.error("Error opening file")
            return EFI_ABORTED
        Data = InFileHandle.read()
    PeFileSize = len(Data)
    PeFileBuffer = Data
    
    CommonHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(PeFileBuffer)
    CurSecHdrSize = sizeof(CommonHeader)
    ImageContext = PE_COFF_LOADER_IMAGE_CONTEXT()
    ImageContext.Handle =  PeFileBuffer[CurSecHdrSize:CurSecHdrSize + sizeof(c_uint64)]
    ImageContext.ImageRead = FfsRebaseImageRead
    Status = PeCoffLoaderGetImageInfo(ImageContext)
    if EFI_ERROR(Status):
        logger.error("Invalid PeImage,he input file is %s and return status is %x",InFile,Status)
        return Status
    
    Alignment = ImageContext.SectionAlignment
    return EFI_SUCCESS


#Main function
def main():
    SectGuidHeaderLength = 0
    LogLevel = 0
    InputFileAlignNum = 0
    MAXIMUM_INPUT_FILE_NUM = 10
    InputFileNum = 0
    InputFileName = None
    InputFileAlign = []
    InputLength = 0
    OutFileBuffer = b''
    StringBuffer = ''
    VendorGuid = mZeroGuid
    SectType = EFI_SECTION_ALL
    SectGuidAttribute = EFI_GUIDED_SECTION_NONE
    Status = STATUS_SUCCESS
    
    args = parser.parse_args()
    argc = len(sys.argv)
    
    logger=logging.getLogger('GenSec')
    if args.quiet:
        logger.setLevel(logging.CRITICAL)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    lh = logging.StreamHandler(sys.stdout)
    lf = logging.Formatter("%(levelname)-8s: %(message)s")
    lh.setFormatter(lf)
    logger.addHandler(lh)
    
    if argc == 1:
        parser.print_help()
        logger.error("Missing options")
        return STATUS_ERROR
    
    #Parse command line
    if args.SectionType:
        SectionName = args.SectionType
        if SectionName == None:
            logger.error("Invalid option value, Section Type can't be NULL")
            #return STATUS_ERROR
            
    if args.output:
        OutputFileName = args.output
        if OutputFileName == None:
            logger.error("Invalid option value, Output file can't be NULL")
            #return STATUS_ERROR
            
    if args.Compress:
        CompressionName = args.Type
        if CompressionName == None:
            logger.error("Invalid option value, Compression Type can't be NULL")
            #return STATUS_ERROR 
            
    if args.GuidValue:
        Status = StringToGuid(args.GuidValue,VendorGuid)
        if EFI_ERROR (Status):
            logger.error("Invalid option value")
            #return STATUS_ERROR
        
    if args.dummyfile:
        DummyFileName = args.dummyfile
        if DummyFileName == None:
            logger.error("Invalid option value, Dummy file can't be NULL")
            #return STATUS_ERROR
            
    if args.GuidAttr:
        if args.GuidAttr == None:
            logger.error("Invalid option value, Guid section attributes can't be NULL")
            #return STATUS_ERROR
        if args.GuidAttr == mGUIDedSectionAttribue[EFI_GUIDED_SECTION_PROCESSING_REQUIRED]:
            SectGuidAttribute |= EFI_GUIDED_SECTION_PROCESSING_REQUIRED
        elif args.GuidAttr == mGUIDedSectionAttribue[EFI_GUIDED_SECTION_AUTH_STATUS_VALID]:
            SectGuidAttribute |= EFI_GUIDED_SECTION_AUTH_STATUS_VALID
        elif args.GuidAttr == mGUIDedSectionAttribue[0]:
            #None atrribute
            SectGuidAttribute |= EFI_GUIDED_SECTION_NONE
        else:
            logger.error("Invalid option value")
            #return STATUS_ERROR
    
    if args.GuidHeaderLength:
        Status = AsciiStringToUint64(args.GuidHeaderLength,False,SectGuidHeaderLength)
        if EFI_ERROR (Status):
            logger.error("Invalid option value for GuidHeaderLength")
            #return STATUS_ERROR
    
    if args.String:
        StringBuffer = args.String
        if args.String == None:
            logger.error("Invalid option value, Name can't be NULL")
            #return STATUS_ERROR
        
    if args.Number:
        if args.Number == None:
            logger.error("Invalid option value, build number can't be NULL")
            #return STATUS_ERROR
        
        #Verify string is a integrator number
        for ch in args.Number:
            if ch != '-' and isdigit(int(ch)) == 0:
                logger.error("Invalid option value")
                #return STATUS_ERROR
        VersionNumber = int(args.Number)
        
    # if args.debug_level:
    #     Status = AsciiStringToUint64(args.debug_level,False,LogLevel)
    #     if EFI_ERROR (Status):
    #         logger.error("Invalid option value, Debug Level range is 0~9, current input level is %s", LogLevel)
    #     if LogLevel > 9:
    #         logger.error("Invalid option value, Debug Level range is 0~9, current input level is %s", LogLevel)
    #     SetPrintLevel (LogLevel)
        
    #Section file alignment requirement
    if args.SectionAlign:
        if InputFileAlignNum == 0:
            for i in range(MAXIMUM_INPUT_FILE_NUM):
                InputFileAlign[i] = 1
        elif InputFileAlignNum % MAXIMUM_INPUT_FILE_NUM == 0:
            for i in range(MAXIMUM_INPUT_FILE_NUM):
                InputFileAlign[InputFileNum + i] = 1

        if args.SectionAlign == "0":
            InputFileAlign[InputFileAlignNum] = 0
        else:
            Status = StringtoAlignment(args.SectionAlign,InputFileAlign[InputFileAlignNum])
            if EFI_ERROR (Status):
                logger.error("Invalid option value")
                #return STATUS_ERROR
        InputFileAlignNum += 1

    #Get input file name
    if InputFileNum == 0 and InputFileName == None:
        for i in range(MAXIMUM_INPUT_FILE_NUM):
            InputFileName[i] = '0'

    elif InputFileNum % MAXIMUM_INPUT_FILE_NUM == 0:
        for i in range(MAXIMUM_INPUT_FILE_NUM):
            InputFileName[InputFileNum + i] = '0'
    for i in range(InputFileNum):
        InputFileName[InputFileNum] = sys.argv[0]
        InputFileNum += 1
    
    if InputFileAlignNum > 0 and InputFileAlignNum != InputFileNum:
        logger.error("Invalid option, section alignment must be set for each section")
        #return STATUS_ERROR
    for Index in range(InputFileAlignNum):
        if InputFileAlign[Index] == 0:
            Status = GetAlignmentFromFile(InputFileName[Index], InputFileAlign[Index])
            if EFI_ERROR(Status):
                logger.error("Fail to get Alignment from %s",InputFileName[InputFileNum])
    
    if DummyFileName != None:
        #Open file and read contents
        with open(DummyFileName,'rb') as DummyFile:
            if DummyFile == None:
                logger.error("Error opening file")
                #return STATUS_ERROR
            Data = DummyFile.read()
        DummyFileSize = len(Data)
        DummyFileBuffer = Data
        
        if InputFileName == None:
            logger.error("Resource, memory cannot be allocated")
            #return STATUS_ERROR
        with open(InputFileName[0],'rb') as InFile:
            if InFile == None:
                logger.error("Error opening file", InputFileName[0])
                #return STATUS_ERROR
            Data = InFile.read()
        InFileSize = len(Data)
        InFileBuffer =Data
        
        if InFileSize > DummyFileSize:
            if DummyFileBuffer == InFileBuffer[(InFileSize - DummyFileSize):]:
                SectGuidHeaderLength = InFileSize - DummyFileSize
        if SectGuidHeaderLength == 0:
            SectGuidAttribute |= EFI_GUIDED_SECTION_PROCESSING_REQUIRED
    
    #Parse all command line parameters to get the corresponding section type
    if SectionName == None:
        #No specified Section type, default is SECTION_ALL.
        SectType = EFI_SECTION_ALL
    elif SectionName == mSectionTypeName[EFI_SECTION_COMPRESSION]:
        SectType = EFI_SECTION_COMPRESSION
        if CompressionName == None:
            #Default is PI_STD compression algorithm.
            SectCompSubType = EFI_STANDARD_COMPRESSION
        elif CompressionName == mCompressionTypeName[EFI_NOT_COMPRESSED]:
            SectCompSubType = EFI_NOT_COMPRESSED
        elif CompressionName == mCompressionTypeName[EFI_STANDARD_COMPRESSION]:
            SectCompSubType = EFI_STANDARD_COMPRESSION
        else:
            logger.error("Invalid option value", "--compress = %s",CompressionName)
            #return STATUS_ERROR
    elif SectionName == mSectionTypeName[EFI_SECTION_GUID_DEFINED]:
        SectType = EFI_SECTION_GUID_DEFINED
        if SectGuidAttribute & EFI_GUIDED_SECTION_NONE != 0:
            #NONE attribute, clear attribute value.
            SectGuidAttribute = SectGuidAttribute & ~EFI_GUIDED_SECTION_NONE
    elif SectionName == mSectionTypeName[EFI_SECTION_PE32]:
        SectType = EFI_SECTION_PE32
    elif SectionName == mSectionTypeName[EFI_SECTION_PIC]:
        SectType = EFI_SECTION_PIC
    elif SectionName == mSectionTypeName[EFI_SECTION_TE]:
        SectType = EFI_SECTION_TE
    elif SectionName == mSectionTypeName[EFI_SECTION_DXE_DEPEX]:
        SectType = EFI_SECTION_DXE_DEPEX
    elif SectionName == mSectionTypeName[EFI_SECTION_SMM_DEPEX]:
        SectType = EFI_SECTION_SMM_DEPEX
    elif SectionName == mSectionTypeName[EFI_SECTION_VERSION]:
        SectType = EFI_SECTION_VERSION
        if VersionNumber < 0 or VersionNumber > 65535:
            logger.error("Invalid option value", "%d is not in 0~65535",VersionNumber)
            #return STATUS_ERROR
    elif SectionName == mSectionTypeName[EFI_SECTION_USER_INTERFACE]:
        SectType = EFI_SECTION_USER_INTERFACE
        if StringBuffer[0] == '\0':
            logger.error("Missing option, user interface string")
            #return STATUS_ERROR
    elif SectionName == mSectionTypeName[EFI_SECTION_COMPATIBILITY16]:
        SectType = EFI_SECTION_COMPATIBILITY16
    elif SectionName == mSectionTypeName[EFI_SECTION_FIRMWARE_VOLUME_IMAGE]:
        SectType = EFI_SECTION_FIRMWARE_VOLUME_IMAGE
    elif SectionName == mSectionTypeName[EFI_SECTION_FREEFORM_SUBTYPE_GUID]:
        SectType = EFI_SECTION_FREEFORM_SUBTYPE_GUID
    elif SectionName == mSectionTypeName[EFI_SECTION_RAW]:
        SectType = EFI_SECTION_RAW
    elif SectionName == mSectionTypeName[EFI_SECTION_PEI_DEPEX]:
        SectType = EFI_SECTION_PEI_DEPEX
    else:
        logger.error("Invalid option value", "SectionType = %s",SectionName
        #return STATUS_ERROR
    )
    
    #GuidValue is only required by Guided section and SubtypeGuid section.
    if SectType != EFI_SECTION_GUID_DEFINED and SectType != EFI_SECTION_FREEFORM_SUBTYPE_GUID and\
        SectionName != None and (CompareGuid (VendorGuid, mZeroGuid) != 0):
            print("Warning: the input guid value is not required for this section type %s\n", SectionName)
    
    #Check whether there is GUID for the SubtypeGuid section
    if SectType == EFI_SECTION_FREEFORM_SUBTYPE_GUID and (CompareGuid (VendorGuid, mZeroGuid) == 0):
        logger.error("Missing options, GUID")
        #return STATUS_ERROR

    #Check whether there is input file
    if SectType != EFI_SECTION_VERSION and SectType != EFI_SECTION_USER_INTERFACE:
        #The input file are required for other section type.
        if InputFileNum == 0:
            logger.error("Missing options, Input files")
    
    #Check whether there is output file
    if OutputFileName == None:
        logger.error("Missing options, Output file") 
        #return STATUS_ERROR
    
    #Finish the command line parsing
    #With in this switch,build and write out the section header including any section
    #type specific pieces. If there is an input file, it's tacked on later
    if SectType == EFI_SECTION_COMPRESSION:
        Status = GenSectionCompressionSection(InputFileNum,SectCompSubType,InputFileName,InputFileAlign,OutFileBuffer)
    
    elif SectType == EFI_SECTION_GUID_DEFINED:
        Status = GenSectionGuidDefinedSection(InputFileNum,VendorGuid,SectGuidAttribute,SectGuidHeaderLength,InputFileName,InputFileAlign,OutFileBuffer)
        
    elif SectType == EFI_SECTION_FREEFORM_SUBTYPE_GUID:
        Status == GenSectionSubtypeGuidSection(InputFileNum,VendorGuid,InputFileName,InputFileAlign,OutFileBuffer)
        
    elif SectType == EFI_SECTION_VERSION:
        Index = sizeof(EFI_COMMON_SECTION_HEADER)
        Index += 2
        #StringBuffer is ascii.. unicode is 2X + 2 bytes for terminating unicode null.
        Index += len(StringBuffer) * 2 + 2
        VersionSect = EFI_VERSION_SECTION()
        VersionSect.CommonHeader.Type = SectType
        VersionSect.CommonHeader.SET_SECTION_SIZE(Index)
        VersionSect.BuildNumber = VersionNumber
        OutFileBuffer = struct2stream(VersionSect)
        Ascii2UnicodeString(StringBuffer,VersionSect.VersionString)
        
    elif SectType == EFI_SECTION_USER_INTERFACE:
        Index = sizeof (EFI_COMMON_SECTION_HEADER)
        Index += len (StringBuffer) * 2 + 2
        
        UiSect = EFI_USER_INTERFACE_SECTION()
        UiSect.CommonHeader.Type == SectType
        UiSect.CommonHeader.SET_SECTION_SIZE(Index)
        OutFileBuffer = struct2stream(UiSect)
        Ascii2UnicodeString (StringBuffer, UiSect.FileNameString)
        
    elif SectType == EFI_SECTION_ALL:
        #Read all input file contents into a buffer
        #first fet the size of all file contents
        
        Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,OutFileBuffer)
        if Status == EFI_BUFFER_TOO_SMALL:
            Status = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,OutFileBuffer)
    
    else:
        #All other section types are caught by default(they're all the same)
        Status =  GenSectionCommonLeafSection(SectType,InputFileNum,InputFileName,OutFileBuffer)
        
    if Status != EFI_SUCCESS or OutFileBuffer == None:
        logger.error("Status is not successful, Status value is 0x%X",int(Status))
        #return STATUS_ERROR
        
    #Get output file length
    if SectType != EFI_SECTION_ALL:
        SectionHeader = EFI_COMMON_SECTION_HEADER(OutFileBuffer[0:sizeof(EFI_COMMON_SECTION_HEADER)])
        InputLength = SectionHeader.Size & 0x00ffffff
        if InputLength == 0xffffff:
            SectionHeader = EFI_COMMON_SECTION_HEADER2(SectionHeader)
            InputLength = SectionHeader.ExtendedSize
            
    #Write the output file
    with open(OutputFileName,'wb') as OutFile:
        if OutFile == None:
            logger.error("Error opening file for writing")
            #return STATUS_ERROR
        OutFile.write(OutFileBuffer)
    
            
if __name__=="__main__":
    exit(main())