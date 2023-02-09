# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

import sys
sys.path.append("..") 

from FirmwareStorageFormat.SectionHeader import *
import logging
import GenCrc32.GenCrc32 as Gen
import argparse
from EfiCompress import *
from PeCoff import *
from BaseTypes import *
from ParseInf import *
import os


STATUS_SUCCESS = 0
STATUS_WARNING = 1
STATUS_ERROR   = 2


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


mCompressionTypeName = ["PI_NONE", "PI_STD"]

EFI_GUIDED_SECTION_NONE=0x80
mGUIDedSectionAttribue=["NONE", "PROCESSING_REQUIRED", "AUTH_STATUS_VALID"]

mAlignName=["1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
  "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
  "512K", "1M", "2M", "4M", "8M", "16M"]

mZeroGuid = EFI_GUID()
mZeroGuid.Data1 = 0x00000000
mZeroGuid.Data2 = 0x0000
mZeroGuid.Data3 = 0x0000
mZeroGuid.Data4[0] = 0x00
mZeroGuid.Data4[1] = 0x00
mZeroGuid.Data4[2] = 0x00
mZeroGuid.Data4[3] = 0x00
mZeroGuid.Data4[4] = 0x00
mZeroGuid.Data4[5] = 0x00
mZeroGuid.Data4[6] = 0x00
mZeroGuid.Data4[7] = 0x00


mEfiCrc32SectionGuid = EFI_GUID()
mEfiCrc32SectionGuid.Data1 = 0xFC1BCDB0
mEfiCrc32SectionGuid.Data2 = 0x7D31
mEfiCrc32SectionGuid.Data3 = 0x49aa
mEfiCrc32SectionGuid.Data4[0] = 0x93
mEfiCrc32SectionGuid.Data4[1] = 0x6A
mEfiCrc32SectionGuid.Data4[2] = 0xA4
mEfiCrc32SectionGuid.Data4[3] = 0x60
mEfiCrc32SectionGuid.Data4[4] = 0x0D
mEfiCrc32SectionGuid.Data4[5] = 0x9D
mEfiCrc32SectionGuid.Data4[6] = 0xD0
mEfiCrc32SectionGuid.Data4[7] =0x83



#Write ascii string as unicode string format to FILE
def Ascii2UnicodeString(String:str):
    unistr = ''
    Enc = String.encode()
    for ch in Enc:
        ch = '%02X' % ch
        unistr += ch
        #print(ch)
    return unistr
    

#Generate a leaf section of type other than EFI_SECTION_VERSION
#and EFI_SECTION_USER_INTERFACE. Input file must be well formed.
#The function won't validate the input file's contents. For
#common leaf sections, the input file may be a binary file.
#The utility will add section header to the file.
def GenSectionCommonLeafSection(SectionType:c_uint8,InputFileNum:c_uint32,InputFileName=[],OutFileBuffer = b''):
    
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
        Status = STATUS_ERROR
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
    Status = STATUS_SUCCESS
    return Status,OutFileBuffer


#Converts Align String to align value (1~16M).
def StringtoAlignment(AlignBuffer:str, AlignNumber:c_uint32) -> int:

    #Check AlignBuffer
    if AlignBuffer == None:
        return EFI_INVALID_PARAMETER

    for ch in mAlignName:
        if AlignBuffer == ch:
            AlignNumber = 1 << mAlignName.index(ch)
            Status = EFI_SUCCESS
            return Status,AlignNumber
    return EFI_INVALID_PARAMETER

#Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileNum:c_uint32,BufferLength:c_uint32,InputFileName=[],InputFileAlign=[],
                        FileBuffer=b''):
    
    logger=logging.getLogger('GenSec')
    
    if InputFileNum < 1:
        logger.error("Invalid parameter, must specify at least one input file")
        return EFI_INVALID_PARAMETER
    if BufferLength == None:
        logger.error("Invalid parameter, BufferLength can't be NULL")
        return EFI_INVALID_PARAMETER

    Size = 0
    Offset = 0 
    TeOffset = 0
    

    #Go through array of file names and copy their contents to the output buffer
    for Index in range(InputFileNum):
        #Make sure section ends on a DWORD boundary
        while Size & 0x03 != 0:
            if FileBuffer != None and Size < BufferLength:
                FileBuffer = FileBuffer + b'\0'
            Size += 1
            
        #Open file and read contents 
        with open(InputFileName[Index],'rb') as InFile:
            if InFile == None:
                logger.error("Error opening file")
                return EFI_ABORTED
            Data = InFile.read()
        FileSize = len(Data)
        
        #Adjust section buffer when section alignment is required.
        if (sum(InputFileAlign) != len(InputFileAlign)):
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
                
            # print("%d %d %d,%d,%d" %(Size,HeaderSize,Offset,InputFileAlign[Index],((Size + HeaderSize + TeOffset) % InputFileAlign[Index])))
            # print(BufferLength)
            #Make sure section data meet its alignment requirement by adding one raw pad section.
            if (InputFileAlign[Index] != 0) and (((Size + HeaderSize + TeOffset) % InputFileAlign[Index]) != 0) and Index != 0:
                Offset = (Size + sizeof(EFI_COMMON_SECTION_HEADER)+ HeaderSize + TeOffset + InputFileAlign[Index] - 1) & ~ (InputFileAlign [Index] - 1)
                Offset = Offset - Size - HeaderSize - TeOffset
                print(Offset)
                #The maximal alignment is 64K, the raw section size must be less than 0xffffff
                if FileBuffer != None and ((Size + Offset) < BufferLength):
                    SectHeader = EFI_COMMON_SECTION_HEADER()
                    SectHeader.Type = EFI_SECTION_RAW
                    SectHeader.SET_SECTION_SIZE(Offset)
                    #FileBuffer = FileBuffer.replace(FileBuffer[Size:Size + sizeof(EFI_COMMON_SECTION_HEADER)],struct2stream(SectHeader))
                    FileBuffer = FileBuffer + struct2stream(SectHeader) + b'\0'* (Offset - sizeof(EFI_COMMON_SECTION_HEADER))
                Size = Size + Offset
            
        #Now read the contents of the file into the buffer
        #Buffer must be enough to contain the file content.
        if FileSize > 0 and FileBuffer != None and ((Size + FileSize) <= BufferLength):
            FileBuffer = FileBuffer + Data
            #FileBuffer = FileBuffer.replace(FileBuffer[Size:(Size + FileSize)],Data)
            if len(FileBuffer) == 0:
                return EFI_ABORTED
        Size += FileSize

    #Set the real required buffer size.
    if Size > BufferLength:
        BufferLength = Size
        Status = EFI_BUFFER_TOO_SMALL
    else:
        BufferLength = Size
        Status = EFI_SUCCESS
    return Status,FileBuffer,BufferLength


#Generate an encapsulating section of type EFI_SECTION_COMPRESSION
#Input file must be already sectioned. The function won't validate
#the input files' contents. Caller should hand in files already
#with section header.
def GenSectionCompressionSection(InputFileNum:c_uint32,SectCompSubType:c_uint8,InputFileName=[],InputFileAlign=[],OutFileBuffer = b''):    
    #Read all input file contenes into a buffer 
    #first get the size of all contents
    
    logger = logging.getLogger('GenSec')
    
    CompressFunction = None
    FileBuffer = b''
    OutputBuffer = b''
    InputLength = 0
    CompressedLength = 0
    TotalLength = 0
    res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    if type(res) == int:
        Status = res
    else:
        Status = res[0]
        FileBuffer = res[1]
        InputLength = res[2]
    
    if Status == EFI_BUFFER_TOO_SMALL:
        #Read all input file contents into a buffer
        FileBuffer = b''
        res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            FileBuffer = res[1]
            InputLength = res[2]
        
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
    # print(len(FileBuffer))
    #Actual compressing 
    if CompressFunction != None:
        res = CompressFunction(InputLength,CompressedLength,FileBuffer,OutputBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            OutputBuffer = res[1]
            CompressedLength = res[2]
            #print(res)
            
        if Status == EFI_BUFFER_TOO_SMALL:
            HeaderLength = sizeof(EFI_COMPRESSION_SECTION)
            if CompressedLength + HeaderLength >= MAX_SECTION_SIZE:
                HeaderLength = sizeof(EFI_COMPRESSION_SECTION2)
            TotalLength = CompressedLength + HeaderLength
            # OutputBuffer = b'\0' * TotalLength
            res = CompressFunction(InputLength,CompressedLength,FileBuffer,OutputBuffer)
            if type(res) == int:
                Status = res
            else:
                Status = res[0]
                OutputBuffer = res[1]
                CompressedLength = res[2]
                #print(res)
            
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
    Status = EFI_SUCCESS
    return Status,OutFileBuffer


#Genarate an encapsulating section of type EFI_SECTION_GUID_DEFINED
#Input file must be already sectioned. The function won't validate
#the input files' contents. Caller should hand in files already
#with section header.
def GenSectionGuidDefinedSection(InputFileNum:c_uint32,VendorGuid:EFI_GUID,DataAttribute:c_uint16,
                                 DataHeaderSize:c_uint32,InputFileName=[],InputFileAlign=[],OutFileBuffer=b'') -> int:
    
    logger=logging.getLogger('GenSec')
    
    FileBuffer = b''
    InputLength = 0
    Offset = 0
    #Read all input file contents into a buffer
    #first get the size of all file contents
    res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    if type(res) == int:
        Status = res
    else:
        Status = res[0]
        FileBuffer = res[1]
        InputLength = res[2]
        
    
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
        FileBuffer = b''
        res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            FileBuffer = res[1]
            InputLength = res[2]
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
        with open(Crc32Input,'wb') as Input:
            Input.write(Crc32InputFileContent)
        Crc32Checksum = Gen.CalculateCrc32(Crc32Input,Crc32Output)
        Crc32Checksum = int.from_bytes(Crc32Checksum,byteorder='little')
        os.remove('InputFile')
        os.remove('OutPutFile')
        
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
    # print(DataHeaderSize)
    OutFileBuffer = FileBuffer
    Status = EFI_SUCCESS
    return Status,OutFileBuffer


#Generate a section of type EFI_SECTION_FREEROM_SUBTYPE_GUID
#The function won't validate the input files contents.
#The utility will add section header to the file
def GenSectionSubtypeGuidSection(InputFileNum:c_uint32,SubTypeGuid:EFI_GUID,
                                InputFileName=[],InputFileAlign=[],OutFileBuffer=b''):
    
    logger = logging.getLogger('GenSec')
    
    InputLength = 0
    Offset = 0
    FileBuffer = b''
    TotalLength = 0

    
    if InputFileNum > 1:
        logger.error("Invalid parameter, more than one input file specified")
        return STATUS_ERROR
    elif InputFileNum < 1:
        logger.error("Invalid parameter, no input file specified")
        return STATUS_ERROR
    
    
    #Read all input file contents into a buffer
    #first get the size of all file contents
    res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
    if type(res) == int:
        Status = res
    else:
        Status =res[0]
        FileBuffer = res[1]
        InputLength = res[2]
        
    if Status == EFI_BUFFER_TOO_SMALL:
        Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION)
        if InputLength + Offset >= MAX_SECTION_SIZE:
            Offset = sizeof(EFI_FREEFORM_SUBTYPE_GUID_SECTION2)
        TotalLength = InputLength + Offset
        
        #Read all input file contents into a buffer
        FileBuffer = b''
        res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,FileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status =res[0]
            FileBuffer = res[1]
            InputLength = res[2]
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
        SubtypeGuidSect.SubTypeGuid = SubTypeGuid
        FileBuffer = struct2stream(SubtypeGuidSect) + FileBuffer

    OutFileBuffer = FileBuffer
    Status = EFI_SUCCESS
    return Status,OutFileBuffer,SubTypeGuid


#Support routine for th PE/COFF file Loader that reads a buffer from a PE/COFF file
def FfsRebaseImageRead(FileOffset:c_uint64,ReadSize:c_uint32,FileHandle:str,Buffer = b''):
    Destination8 = Buffer
    FileHandle = FileHandle.encode()
    Source8 = FileHandle[FileOffset:]
    Length = ReadSize
    # while Length - 1:
    #     Destination8 = Source8 
    #     Destination8 += 1
    #     Source8 += 1
    #     #Length -= 1
    #Destination8 += Source8[0:Length]
    Destination8 =  Destination8.replace(Destination8[0:Length],Source8[0:Length])
    Status = EFI_SUCCESS
    return Status,ReadSize,Destination8


#InFile is input file for getting alignment
#return the alignment
def GetAlignmentFromFile(InFile:str,Alignment:c_uint32):

    PeFileBuffer = b''
    Alignment = 0
    
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
    #ImageContext.Handle =  PeFileBuffer[CurSecHdrSize:CurSecHdrSize + sizeof(c_uint64)]
    ImageContext.Handle =  PeFileBuffer[CurSecHdrSize:CurSecHdrSize + sizeof(c_uint64)].decode()
    
    #For future use in PeCoffLoaderGetImageInfo like EfiCompress
    #ImageContext.ImageRead = FfsRebaseImageRead[0]
    Status = PeCoffLoaderGetImageInfo(ImageContext)
    if EFI_ERROR(Status):
        logger.error("Invalid PeImage,he input file is %s and return status is %x",InFile,Status)
        return Status
    
    Alignment = ImageContext.SectionAlignment
    Status = EFI_SUCCESS
    return Status,Alignment