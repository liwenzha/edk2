# @file
#This file contains functions required to generate a Firmware File System file.
#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

import argparse
from FirmwareStorageFormat.SectionHeader import *
from BaseTypes import *
import logging
import sys


UTILITY_NAME = 'GenFfs'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1


mAlignName=["1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
  "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
  "512K", "1M", "2M", "4M", "8M", "16M"]


parser=argparse.ArgumentParser(description="This file contains functions required to generate a Firmware File System file.")
parser.add_argument("input",help = "Input file name")
parser.add_argument("-o","--outputfile",dest="output",help="File is FFS file to be created.")
parser.add_argument("-t","--filetype",dest="type",help="Type is one FV file type defined in PI spec,which is\
                    EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FREEFORM,EFI_FV_FILETYPE_SECURITY_CORE, \
                    EFI_FV_FILETYPE_PEIM, EFI_FV_FILETYPE_PEI_CORE,EFI_FV_FILETYPE_DXE_CORE, EFI_FV_FILETYPE_DRIVER,\
                    EFI_FV_FILETYPE_APPLICATION, EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER,EFI_FV_FILETYPE_SMM, EFI_FV_FILETYPE_SMM_CORE,\
                    EFI_FV_FILETYPE_MM_STANDALONE,EFI_FV_FILETYPE_MM_CORE_STANDALONE, EFI_FV_FILETYPE_COMBINED_SMM_DXE,\
                    EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE.")
parser.add_argument("-g","--fileguid",dest="FileGuid",help="FileGuid is one module guid.\
                    Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
parser.add_argument("-x","--fixed",dest="fix",help="Indicates that the file may not be moved\
                    from its present location.")
parser.add_argument("-s","--checksum",dest="checksum",help="Indicates to calculate file checksum.")
parser.add_argument("-a","--align",dest="FileAlign",help="FileAlign points to file alignment, which only support\
                    the following align: 1,2,4,8,16,128,512,1K,4K,32K,64K\
                    128K,256K,512K,1M,2M,4M,8M,16M")
parser.add_argument("-i","--sectionfile",dest="SectionFile",help="Section file will be contained in this FFS file.")
parser.add_argument("-oi","--optionalsectionfile",dest="SectionFile",help="If the Section file exists, it will be contained in this FFS file, otherwise, it will be ignored.")
parser.add_argument("-n","--sectionalign",dest="SectionAlign",help="SectionAlign points to section alignment, which support\
                    the alignment scope 0~16M. If SectionAlign is specified\
                    as 0, tool get alignment value from SectionFile. It is\
                    specified together with sectionfile to point its alignment in FFS file.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%s Version %d.%d'%(UTILITY_NAME,UTILITY_MINOR_VERSION,UTILITY_MAJOR_VERSION),
                    help="Show program's version number and exit.")


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


#Converts File Type String to value.  EFI_FV_FILETYPE_ALL indicates that an
#unrecognized file type was specified.
def StringToType(String:str):
    if String == None:
        return EFI_FV_FILETYPE_ALL
    Index = 0
    for Index in range(int(sizeof (mFfsFileType) / sizeof (c_char))):
        if mFfsFileType [Index] != None and String == mFfsFileType [Index]:
            return Index
    return EFI_FV_FILETYPE_ALL


#Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileNum:c_uint32,BufferLength:c_uint32,InputFileName=[],InputFileAlign=[],
                        FileBuffer=b'',):
    
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
    

    #Go through array of file names and copy their contents
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
                #Offset1 = Offset

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


#Support routine for th PE/COFF file Loader that reads a buffer from a PE/COFF file
def FfsRebaseImageRead(FileOffset:c_uint64,ReadSize:c_uint32,FileHandle = b'',Buffer = b'') -> int:
    Destination8 = Buffer
    Source8 = FileHandle[FileOffset:]
    Length = ReadSize
    # while Length - 1:
    #     Destination8 = Source8 
    #     Destination8 += 1
    #     Source8 += 1
    #     #Length -= 1
    Destination8 += Source8[0:Length]
    Status = EFI_SUCCESS
    return Status,ReadSize,Buffer


#InFile is input file for getting alignment
#return the alignment
def GetAlignmentFromFile(InFile:str,Alignment:c_uint32) -> int:

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
    Status = EFI_SUCCESS
    return Status,Alignment


def main():
    args = parser.parse_args()
    argc = len(sys.argv)
    
    if argc == 1:
        parser.print_help()
        logger.error("Missing options")
        return STATUS_ERROR
    
    
    
if __name__=="__main__":
    exit(main())