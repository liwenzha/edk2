# @file
#This file contains functions required to generate a Firmware File System file.
#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

import argparse
import sys
sys.path.append('..')

from FirmwareStorageFormat.SectionHeader import *
from FirmwareStorageFormat.FfsFileHeader import *
from PeCoff import *
from BaseTypes import *
from ParseInf import *
import logging


UTILITY_NAME = 'GenFfs'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1


mFfsFileType = [
    None,                                      #0x00
    "EFI_FV_FILETYPE_RAW",                     #0x01
    "EFI_FV_FILETYPE_FREEFORM",                #0x02
    "EFI_FV_FILETYPE_SECURITY_CORE",           #0x03
    "EFI_FV_FILETYPE_PEI_CORE",                #0x04
    "EFI_FV_FILETYPE_DXE_CORE",                #0x05
    "EFI_FV_FILETYPE_PEIM",                    #0x06
    "EFI_FV_FILETYPE_DRIVER",                  #0x07
    "EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER",    #0x08
    "EFI_FV_FILETYPE_APPLICATION",             #0x09
    "EFI_FV_FILETYPE_SMM",                     #0x0A
    "EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE",   #0x0B
    "EFI_FV_FILETYPE_COMBINED_SMM_DXE",        #0x0C
    "EFI_FV_FILETYPE_SMM_CORE",                #0x0D
    "EFI_FV_FILETYPE_MM_STANDALONE",           #0x0E
    "EFI_FV_FILETYPE_MM_CORE_STANDALONE"       #0x0F
]


mAlignName = ["1", "2", "4", "8", "16", "32", "64", "128", "256", "512",
  "1K", "2K", "4K", "8K", "16K", "32K", "64K", "128K", "256K",
  "512K", "1M", "2M", "4M", "8M", "16M"]


mFfsValidAlignName =["8", "16", "128", "512", "1K", "4K", "32K", "64K", "128K","256K",
  "512K", "1M", "2M", "4M", "8M", "16M"]

mFfsValidAlign = [0, 8, 16, 128, 512, 1024, 4096, 32768, 65536, 131072, 262144,
                   524288, 1048576, 2097152, 4194304, 8388608, 16777216]

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

mEfiFfsSectionAlignmentPaddingGuid = (0x04132C8D, 0x0A22, 0x4FA8, (0x82, 0x6E, 0x8B, 0xBF, 0xEF, 0xDB, 0x83, 0x6C))


MAX_FFS_SIZE = 0x1000000
MAXIMUM_INPUT_FILE_NUM = 10
FFS_FIXED_CHECKSUM = 0xAA

#FFS File Attributes.
FFS_ATTRIB_LARGE_FILE = 0x01
FFS_ATTRIB_DATA_ALIGNMENT2 = 0x02
FFS_ATTRIB_FIXED = 0x04
FFS_ATTRIB_CHECKSUM = 0x40


#File Types Definitions
EFI_FV_FILETYPE_ALL = 0x00
EFI_FV_FILETYPE_SECURITY_CORE = 0x03
EFI_FV_FILETYPE_PEI_CORE = 0x04
EFI_FV_FILETYPE_DXE_CORE = 0x05
EFI_FV_FILETYPE_PEIM = 0x06
EFI_FV_FILETYPE_DRIVER = 0x07
EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER = 0x08
EFI_FV_FILETYPE_APPLICATION = 0x09


#FFS File State Bits.
EFI_FILE_HEADER_CONSTRUCTION = 0x01
EFI_FILE_HEADER_VALID = 0x02
EFI_FILE_DATA_VALID = 0x04


parser=argparse.ArgumentParser(description="This file contains functions required to generate a Firmware File System file.")
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
parser.add_argument("-i","--sectionfile",dest="SectionFile",action = 'append',help="Section file will be contained in this FFS file.")
parser.add_argument("-oi","--optionalsectionfile",dest="OptionalSectionFile",action = 'append',help="If the Section file exists, it will be contained in this FFS file, otherwise, it will be ignored.")
parser.add_argument("-n","--sectionalign",dest="SectionAlign",help="SectionAlign points to section alignment, which support\
                    the alignment scope 0~16M. If SectionAlign is specified\
                    as 0, tool get alignment value from SectionFile. It is\
                    specified together with sectionfile to point its alignment in FFS file.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%s Version %d.%d'%(UTILITY_NAME,UTILITY_MINOR_VERSION,UTILITY_MAJOR_VERSION),
                    help="Show program's version number and exit.")


logger = logging.getLogger('GenFfs')


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
    #Index = 0
    for Index in range(int(sizeof (mFfsFileType) // sizeof (c_char))):
        if mFfsFileType [Index] != None and String == mFfsFileType [Index]:
            return Index
    return EFI_FV_FILETYPE_ALL


#Get the contents of all section files specified in InputFileName into FileBuffer
def GetSectionContents(InputFileNum:c_uint32,BufferLength:c_uint32,FfsAttrib:c_uint8,MaxAlignment:c_uint32,
                       PESectionNum:c_uint8,InputFileName=[],InputFileAlign=[],FileBuffer=b'',):
    
    # if InputFileNum < 1:
    #     logger.error("Invalid parameter, must specify at least one input file")
    #     return EFI_INVALID_PARAMETER
    # if BufferLength == None:
    #     logger.error("Invalid parameter, BufferLength can't be NULL")
    #     return EFI_INVALID_PARAMETER

    Size = 0
    Offset = 0 
    TeOffset = 0
    MaxEncounteredAlignment = 1
    

    #Go through array of file names and copy their contents
    for Index in range(InputFileNum):
        #Make sure section ends on a DWORD boundary
        while Size & 0x03 != 0:
            # if FileBuffer != None and Size < BufferLength:
            #     FileBuffer = FileBuffer + b'\0'
            Size += 1
            
        #Open file and read contents 
        with open(InputFileName[Index],'rb') as InFile:
            if InFile == None:
                logger.error("Error opening file")
                return EFI_ABORTED
            Data = InFile.read()
        FileSize = len(Data)
    
        #Check this section is Te/Pe section, and Calculate the numbers of Te/Pe section.
        TeOffset = 0
        if FileSize >= MAX_FFS_SIZE:
            HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER2)
        else:
            HeaderSize = sizeof(EFI_COMMON_SECTION_HEADER)
            
        #TempSectHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Data[0:sizeof(HeaderSize)])
        TempSectHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(Data)
        
        if TempSectHeader.Type == EFI_SECTION_TE:
            PESectionNum += 1 
            #TeHeaderSize = sizeof(EFI_TE_IMAGE_HEADER)
            TeHeader = EFI_TE_IMAGE_HEADER.from_buffer_copy(Data)
            if TeHeader.Signature == EFI_TE_IMAGE_HEADER_SIGNATURE:
                TeOffset = TeHeader.StrippedSize - sizeof(TeHeader)

        elif TempSectHeader.Type == EFI_SECTION_PE32:
            PESectionNum += 1
            
        elif TempSectHeader.Type == EFI_SECTION_GUID_DEFINED:
            if FileSize >= MAX_SECTION_SIZE:
                GuidSectHeader2 = EFI_GUID_DEFINED_SECTION2.from_buffer_copy(Data)
                if (GuidSectHeader2.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED) == 0:
                    HeaderSize = GuidSectHeader2.DataOffset
            else:
                GuidSectHeader = EFI_GUID_DEFINED_SECTION.from_buffer_copy(Data)
                if (GuidSectHeader.Attributes & EFI_GUIDED_SECTION_PROCESSING_REQUIRED) == 0:
                    HeaderSize = GuidSectHeader.DataOffset
            PESectionNum += 1
        
        elif TempSectHeader.Type == EFI_SECTION_COMPRESSION or TempSectHeader.Type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
            #for the encapsulated section, assume it contains Pe/Te section
            PESectionNum += 1
    
        #Revert TeOffset to the converse value relative to Alignment
        #This is to assure the original PeImage Header at Alignment.         
        if TeOffset != 0 and InputFileAlign [Index] != 0:
            TeOffset = InputFileAlign[Index] - (TeOffset % InputFileAlign[Index])
            TeOffset = TeOffset % InputFileAlign[Index]
        
        #Make sure section data meet its alignment requirement by adding one raw pad section.
        if (InputFileAlign[Index] != 0 and (Size + HeaderSize + TeOffset) % InputFileAlign[Index]) != 0:
            Offset = (Size + sizeof(EFI_COMMON_SECTION_HEADER)+ HeaderSize + TeOffset + InputFileAlign[Index] - 1) & ~ (InputFileAlign [Index] - 1)
            Offset = Offset - Size - HeaderSize - TeOffset
            #Offset1 = Offset

            #The maximal alignment is 64K, the raw section size must be less than 0xffffff
            if FileBuffer != None and ((Size + Offset) < BufferLength):
                
                SectHeader = EFI_FREEFORM_SUBTYPE_GUID_SECTION()
                SectHeader.CommonHeader.SET_SECTION_SIZE(Offset)
                #FileBuffer = struct2stream(SectHeader)
                FileBuffer = FileBuffer + struct2stream(SectHeader) + b'\0'* (Offset - sizeof(EFI_COMMON_SECTION_HEADER))
                
                if (FfsAttrib & FFS_ATTRIB_FIXED) != 0 and MaxEncounteredAlignment <= 1 and Offset >= sizeof (EFI_FREEFORM_SUBTYPE_GUID_SECTION):
                    SectHeader.CommonHeader.Type = EFI_SECTION_FREEFORM_SUBTYPE_GUID
                    SectHeader.SubTypeGuid = mEfiFfsSectionAlignmentPaddingGuid
                else:
                    SectHeader.CommonHeader.Type   = EFI_SECTION_RAW
            Size = Size + Offset
        
        #Get the Max alignment of all input file datas
        if MaxEncounteredAlignment < InputFileAlign [Index]:
            MaxEncounteredAlignment = InputFileAlign [Index]
            
        #Now read the contents of the file into the buffer
        #Buffer must be enough to contain the file content.
        if FileSize > 0 and FileBuffer != None and ((Size + FileSize) <= BufferLength):
            FileBuffer = FileBuffer + Data
            if len(FileBuffer) == 0:
                logger.error("Error reading file:%s" %InputFileName[Index])
                return EFI_ABORTED
        Size += FileSize

    MaxAlignment = MaxEncounteredAlignment
    
    #Set the real required buffer size.
    if Size > BufferLength:
        BufferLength = Size
        Status = EFI_BUFFER_TOO_SMALL
    else:
        BufferLength = Size
        Status = EFI_SUCCESS
    return Status,FileBuffer,BufferLength,MaxAlignment,PESectionNum


#Support routine for th PE/COFF file Loader that reads a buffer from a PE/COFF file
def FfsRebaseImageRead(FileOffset:c_uint64,ReadSize:c_uint32,FileHandle :str,Buffer = b''):
    Destination8 = Buffer
    FileHandle = FileHandle.encode()
    Source8 = FileHandle[FileOffset:]
    Length = ReadSize
    # while Length - 1:
    #     Destination8 = Source8 
    #     Destination8 += 1
    #     Source8 += 1
    #     #Length -= 1
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
    #ImageContext.ImageRead = FfsRebaseImageRead
    Status = PeCoffLoaderGetImageInfo(ImageContext)
    if EFI_ERROR(Status):
        logger.error("Invalid PeImage,he input file is %s and return status is %x" %(InFile,Status))
        return Status
    
    Alignment = ImageContext.SectionAlignment
    Status = EFI_SUCCESS
    return Status,Alignment


#This function calculates the value needed for a valid UINT8 checksum
def CalculateSum8(Size:int,Buffer=b''):
    Sum = 0
    #Perform the byte sum for buffer
    for Index in range(Size):
        Sum = Sum + Buffer[Index]
    return Sum


#This function calculates the UINT8 sum for the requested region.
def CalculateChecksum8(Size:int,Buffer=b''):
    return 0x100 - CalculateSum8 (Size,Buffer)


#Main function
def main():
    Status = EFI_SUCCESS
    FileGuid = EFI_GUID(0,0,0,(0,0,0,0,0,0,0,0))
    # FfsAttrib = EFI_FFS_FILE_ATTRIBUTES()
    InputFileNum = 0
    Alignment = 0
    InputFileName = []
    InputFileAlign = []
    OutputFileName = ''
    FileSize = 0
    FfsAttrib = 0
    FfsAlign = 0
    MaxAlignment = 1
    PeSectionNum = 0
    FileBuffer = b''
    FfsFiletype = EFI_FV_FILETYPE_ALL
    PeSectionNum = 0
    
    AlignmentBuffer = ''
    
    args = parser.parse_args()
    argc = len(sys.argv)
    
    if argc == 1:
        parser.print_help()
        logger.error("Missing options")
        return STATUS_ERROR
    
    #Parse command line
    if args.type:
        if args.type == None or args.type[0] == '-':
            logger.error("Invalid option value, %s is not a valid file type" %args.type)
            Status = STATUS_ERROR
            return Status
        
        FfsFiletype = StringToType(args.type)
        if FfsFiletype == EFI_FV_FILETYPE_ALL:
            logger.error("Invalid option value, %s is not a valid file type" %args.type)
            Status = STATUS_ERROR
            return Status
        
    if args.output:
        if args.output == None or args.output[0] == '-':
            logger.error("Invalid option value, Output file is missing for -o option")
            Status = STATUS_ERROR
            return Status
        
        OutputFileName = args.output
        
    if args.FileGuid:
        res = StringToGuid(args.FileGuid,FileGuid)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            FileGuid = res[1]
        
        if EFI_ERROR(Status):
            logger.error("Invalid option value, %s = %s" %("-g",args.FileGuid))
            Status = STATUS_ERROR
            return Status
        
    if args.fix:
        FfsAttrib |= FFS_ATTRIB_FIXED
        
    if args.checksum:
        FfsAttrib |= FFS_ATTRIB_CHECKSUM
        
    if args.FileAlign:
        if args.FileAlign == None or args.FileAlign[0] == '-':
            logger.error("Invalid option value, Align value is missing for -a option")
            Status = STATUS_ERROR
            return Status
        for Index in range(sizeof(mFfsValidAlignName)//sizeof(c_char)):
            if args.FileAlign == "1" or args.FileAlign == "2" or args.FileAlign == "4":
                #1,2,4 byte algnment same to 8 byte alignment
                Index = 0
            else:
                logger.error("Invalid option value", "%s = %s" %("-a",args.FileAlign))
                Status = STATUS_ERROR
                return Status
        FfsAlign = Index
        
    if args.SectionFile or args.OptionalSectionFile:
        #Get Input file name and its alignment
        if args.SectionFile == None or args.SectionFile[0] == '-':
            logger.error("Invalid option value, input section file is missing for -i option")
            Status = STATUS_ERROR
            return Status
        
        #Get input file
        if args.SectionFile:
            InputFileName = args.SectionFile
            InputFileNum = len(InputFileName)
        elif args.OptionalSectionFile:
            InputFileName = args.OptionalSectionFile
            InputFileNum = len(InputFileName)
            
        #Allocate file align 
        if InputFileName == 0 and InputFileName != None:
                for i in range(MAXIMUM_INPUT_FILE_NUM):
                    InputFileAlign.append(0)
        elif InputFileNum % MAXIMUM_INPUT_FILE_NUM == 0:
            for i in range(InputFileNum,InputFileNum + MAXIMUM_INPUT_FILE_NUM,1):
                InputFileAlign.append(0)
            
        #Section File alignment requirement
        if args.SectionAlign:
            if args.SectionAlign != None and args.SectionAlign == "0":
                res = GetAlignmentFromFile(InputFileName[InputFileNum], Alignment)
                if type(res) == int:
                    Status = res
                else:
                    Status = res[0]
                    Alignment = res[1]
                if EFI_ERROR(Status):
                    logger.error("Fail to get Alignment from %s" %InputFileName[InputFileNum])
                    Status = STATUS_ERROR
                    return Status
                
                if Alignment < 0x400:
                    AlignmentBuffer = str(Alignment)
                    print(AlignmentBuffer) 
                elif Alignment >= 0x100000:
                    AlignmentBuffer = str(int(Alignment//0x100000)) + 'M'
                    print(AlignmentBuffer)
                else:
                    AlignmentBuffer = str(int(Alignment//0x400)) + 'K'
                    print(AlignmentBuffer)
                res = StringtoAlignment(AlignmentBuffer,InputFileAlign[InputFileNum])
                if type(res) == int:
                    Status = res
                else:
                    Status = res[0]
                    InputFileAlign[InputFileNum] = res[1]
            else:
                res = StringtoAlignment(AlignmentBuffer,InputFileAlign[InputFileNum])
                if type(res) == int:
                    Status = res
                else:
                    Status = res[0]
                    InputFileAlign[InputFileNum] = res[1]
            if EFI_ERROR (Status):
                logger.error("Invalid option value", "%s = %s" %("-n",args.SectionAlign))
                Status = STATUS_ERROR
                return Status
        # InputFileNum += 1
            
    if args.SectionAlign:     #Sectionalign should be accompanied by -oi/-i
        if not args.SectionFile and not args.OptionalSectionFile:
            logger.error("Unknown option, SectionAlign option must be specified with section file.")
            Status = STATUS_ERROR
            return Status
        
    # if args.verbose:   #Skip Verbose temporarily
    #     pass
            
    # if args.quiet:     #Skip Quiet temporarily
    #     pass 
    
    # if args.debug:     #Skip Debug temporarily
    #     pass 
    
    else:
        logger.error("Unknown option")
        Status = STATUS_ERROR
        return Status
    
    
    #Check the complete input parameters.
    if FfsFiletype == EFI_FV_FILETYPE_ALL:
        logger.error("Missing option, filetype")
    if CompareGuid (FileGuid, mZeroGuid) == 0:
        logger.error("Missing option, fileguid")
    if InputFileNum == 0:
        logger.error("Missing option, Input files")
        
        
    #Calculate the size of all input section files.
    res = GetSectionContents(InputFileNum,FileSize,InputFileName,FfsAttrib,MaxAlignment,PeSectionNum,
                             InputFileName,InputFileAlign,FileBuffer)
    if type(res) == int:
        Status = res
    else:
        Status = res[0]
        FileBuffer = res[1]
        FileSize = res[2]
        MaxAlignment = res[3]
        PeSectionNum = res[4]
    
    if (FfsFiletype == EFI_FV_FILETYPE_SECURITY_CORE or FfsFiletype == EFI_FV_FILETYPE_PEI_CORE or\
           FfsFiletype == EFI_FV_FILETYPE_DXE_CORE) and (PeSectionNum != 1):
        logger.error("Invalid parameter, Fv File type %s must have one and only one Pe or Te section, but %u Pe/Te section are input" %(mFfsFileType [FfsFiletype], PeSectionNum))
        Status = STATUS_ERROR
        return Status
    
    if (FfsFiletype == EFI_FV_FILETYPE_PEIM or FfsFiletype == EFI_FV_FILETYPE_DRIVER or\
           FfsFiletype == EFI_FV_FILETYPE_COMBINED_PEIM_DRIVER or FfsFiletype == EFI_FV_FILETYPE_APPLICATION) and\
               (PeSectionNum < 1):
        logger.error("Invalid parameter, Fv File type %s must have at least one Pe or Te section, but no Pe/Te section is input" %mFfsFileType [FfsFiletype])
        Status = STATUS_ERROR
        return Status
    
    if Status == EFI_BUFFER_TOO_SMALL:
        FileBuffer = b''
        res = GetSectionContents(InputFileNum,FileSize,InputFileName,FfsAttrib,MaxAlignment,PeSectionNum,
                             InputFileName,InputFileAlign,FileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            FileBuffer = res[1]
            FileSize = res[2]
            MaxAlignment = res[3]
            PeSectionNum = res[4]
        
    if EFI_ERROR (Status):
        Status = STATUS_ERROR
        return Status
        
    #Create Ffs file header.
    FfsFileHeader = EFI_FFS_FILE_HEADER2()
    FfsFileHeader.Name = FileGuid
    FfsFileHeader.Type = FfsFiletype
    
    #Update FFS Alignment based on the max alignment required by input section files
    for Index in range(int(sizeof (mFfsValidAlign) // sizeof (c_uint32) - 1)):
        if MaxAlignment > mFfsValidAlign [Index] and MaxAlignment <= mFfsValidAlign [Index + 1]:
            break
    if FfsAlign < Index:
        FfsAlign = Index
        
    #Now FileSize includes the EFI_FFS_FILE_HEADER
    if FileSize + sizeof (EFI_FFS_FILE_HEADER) >= MAX_FFS_SIZE:
        HeaderSize = sizeof (EFI_FFS_FILE_HEADER2)
        FileSize += sizeof (EFI_FFS_FILE_HEADER2)
        FfsFileHeader.ExtendedSize = FileSize
        FfsFileHeader.Size[0] = 0
        FfsFileHeader.Size[1] = 0
        FfsFileHeader.Size[2] = 0
        FfsAttrib |= FFS_ATTRIB_LARGE_FILE
    else:
        HeaderSize = sizeof (EFI_FFS_FILE_HEADER)
        FileSize += sizeof (EFI_FFS_FILE_HEADER)
        FfsFileHeader.Size[0] = FileSize & 0xFF
        FfsFileHeader.Size[1] = (FileSize & 0xFF00) >> 8
        FfsFileHeader.Size[2] = (FileSize & 0xFF0000) >> 16
        
    #FfsAlign larger than 7,set FFS_ATTRIB_DATA_ALIGNMENT2
    if FfsAlign < 8:
        FfsFileHeader.Attributes = FfsAttrib | (FfsAlign << 3)
    else:
        FfsFileHeader.Attributes = FfsAttrib | ((FfsAlign & 0x7) << 3) | FFS_ATTRIB_DATA_ALIGNMENT2
        
    #Fill in checksums and state,these must be zero for checksumming
    FfsFileHeader.IntegrityCheck.Checksum.Header = CalculateChecksum8(HeaderSize,struct2stream(FfsFileHeader))
    
    if FfsFileHeader.Attributes & FFS_ATTRIB_CHECKSUM:
        #Ffs header checksum = zero, so only need to calculate ffs body.
        FfsFileHeader.IntegrityCheck.Checksum.File = CalculateChecksum8(FileSize - HeaderSize,FileBuffer)
    else:
        FfsFileHeader.IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM
    
    FfsFileHeader.State = EFI_FILE_HEADER_CONSTRUCTION | EFI_FILE_HEADER_VALID | EFI_FILE_DATA_VALID
    
    
    #Open output file to write ffs data
    with open("OutputFileName","wb") as FfsFile:
        if FfsFile == None:
            logger.error("Error opening file:%s" %OutputFileName)
            Status = STATUS_ERROR
            return Status
        FfsFile.write(struct2stream(FfsFileHeader))      #Write header
        if FileBuffer != None:
            FfsFile.write(FileBuffer)                        #Write data
    
    
if __name__=="__main__":
    exit(main())