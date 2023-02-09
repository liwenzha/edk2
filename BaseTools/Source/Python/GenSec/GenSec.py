# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

import sys
sys.path.append("..") 

from FirmwareStorageFormat.SectionHeader import *
import logging
import argparse
from EfiCompress import *
from PeCoff import *
from BaseTypes import *
from ParseInf import *
from GenSecOperations import *
import copy


UTILITY_NAME = 'GenSec'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1
__BUILD_VERSION = "Developer Build based on Revision: Unknown"

def Version():
    print("%s Version %d.%d %s" %(UTILITY_NAME, UTILITY_MAJOR_VERSION, UTILITY_MINOR_VERSION,__BUILD_VERSION))

def Usage():
    print("Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.")
    print("Create Firmware File Section files  per PI Spec")
    print("Usage: %s [options] [input_file]" %UTILITY_NAME)
    
    #Details Option
    print("Options:")
    print("  -o FileName, --outputfile FileName\n\
                        File is the SectionFile to be created.")
    print("  -s [SectionType], --sectiontype[SectionType]\n\
                        SectionType defined in PI spec is one type of\n\
                        EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED,\n\
                        EFI_SECTION_PE32,EFI_SECTION_PIC, EFI_SECTION_TE,\n\
                        EFI_SECTION_DXE_DEPEX, EFI_SECTION_COMPATIBILITY16,\n\
                        EFI_SECTION_USER_INTERFACE, EFI_SECTION_VERSION,\n\
                        EFI_SECTION_FIRMWARE_VOLUME_IMAGE,EFI_SECTION_RAW,\n\
                        EFI_SECTION_FREEFORM_SUBTYPE_GUID,\n\
                        EFI_SECTION_PEI_DEPEX, EFI_SECTION_SMM_DEPEX.\n\
                        if -s option is not given,\n\
                        EFI_SECTION_ALL is default section type.")
    print("  -c [Type], --compress [Type]\n\
                        Compress method type can be PI_NONE or PI_STD.\n\
                        if -c option is not given, PI_STD is default type.")
    print("  -g GuidValue, --vendor GuidValue\n\
                        GuidValue is one specific vendor guid value.\n\
                        Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    print("  -l GuidHeaderLength, --HeaderLength GuidHeaderLength\n\
                        GuidHeaderLength is the size of header of guided data")
    print("  -r GuidAttr, --attributes GuidAttr\n\
                        GuidAttr is guid section attributes, which may be\n\
                        PROCESSING_REQUIRED, AUTH_STATUS_VALID and NONE.\n\
                        if -r option is not given, default PROCESSING_REQUIRED")
    print("  -n String, --name String\n\
                        String is a NULL terminated string used in Ui section.")
    print("  -j Number, --buildnumber Number\n\
                        Number is an integer value between 0 and 65535\n\
                        used in Ver section.")
    print("  --sectionalign SectionAlign\n\
                        SectionAlign points to section alignment, which support\n\
                        the alignment scope 0~16M. If SectionAlign is specified\n\
                        as 0, tool get alignment value from SectionFile. It is\n\
                        specified in same order that the section file is input.")
    print("  --dummy dummyfile\n\
                        compare dummyfile with input_file to decide whether\n\
                        need to set PROCESSING_REQUIRED attribute.")
    print("  -v, --verbose         Turn on verbose output with informational messages.")
    print("  -q, --quiet           Disable all messages except key message and fatal error")
    print("  -d, --debug           level  Enable debug messages, at input debug level.")
    print("  --version             Show program's version number and exit.")
    print("  -h, --help            Show program's version number and exit.")

        

#Main function
def main():
    SectGuidHeaderLength = 0
    LogLevel = 0
    InputFileAlignNum = 0
    MAXIMUM_INPUT_FILE_NUM = 10
    InputFileNum = 0
    InputFileName = []
    InputFileAlign = []
    InputLength = 0
    OutFileBuffer = b''
    OutputFileName = ''
    StringBuffer = ''
    # VendorGuid = mZeroGuid
    VendorGuid = copy.deepcopy(mZeroGuid)
    SectType = EFI_SECTION_ALL
    SectGuidAttribute = EFI_GUIDED_SECTION_NONE
    Status = STATUS_SUCCESS
    DummyFileName = ''
    SectionName = None
    VersionNumber = 0
    
    #args = parser.parse_args()
    logger=logging.getLogger('GenSec')
    
    argc = len(sys.argv)
    if argc == 1:
            logger.error("Missing options,No options input")
            print('\n')
            Usage()
            return STATUS_ERROR

    #Start to parse command line without using argparse...
    argc -= 1
    arg_index = 1
    
    if sys.argv[arg_index] == "-h" or sys.argv[arg_index] == "--help":
        Version()
        Usage()
        return STATUS_SUCCESS
    
    if sys.argv[arg_index] == "--version":
        Version()
        return STATUS_SUCCESS

    while argc > 0:
        #Parse command line
        #print(arg_index)
        if sys.argv[arg_index] == "-s" or sys.argv[arg_index] == "--SectionType":
            SectionName = sys.argv[arg_index + 1]
            if SectionName == None:
                logger.error("Invalid option value, Section Type can't be NULL")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
                
        if sys.argv[arg_index] == "-o" or sys.argv[arg_index] == "--outputfile":
            OutputFileName = sys.argv[arg_index + 1]
            if OutputFileName == None:
                logger.error("Invalid option value, Output file can't be NULL")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
                
        if sys.argv[arg_index] == "-c" or sys.argv[arg_index] == "--compress":
            CompressionName = sys.argv[arg_index + 1]
            if CompressionName == None:
                logger.error("Invalid option value, Compression Type can't be NULL")
                return STATUS_ERROR 
            argc -= 2
            arg_index += 2
            continue
                
        if sys.argv[arg_index] == "-g" or sys.argv[arg_index] == "--vendor":
            res = StringToGuid(sys.argv[arg_index + 1],VendorGuid)
            if type(res) == int:
                Status = res
            else:
                Status = res[0]
                VendorGuid = res[1]
                
            if EFI_ERROR (Status):
                logger.error("Invalid option value")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
            
        if sys.argv[arg_index] == "--dummy":
            DummyFileName = sys.argv[arg_index + 1]
            if DummyFileName == None:
                logger.error("Invalid option value, Dummy file can't be NULL")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
                
        if sys.argv[arg_index] == "-r" or sys.argv[arg_index] == "--attributes":
            if sys.argv[arg_index + 1] == None:
                logger.error("Invalid option value, Guid section attributes can't be NULL")
                return STATUS_ERROR
            if sys.argv[arg_index + 1] == mGUIDedSectionAttribue[EFI_GUIDED_SECTION_PROCESSING_REQUIRED]:
                SectGuidAttribute |= EFI_GUIDED_SECTION_PROCESSING_REQUIRED
            elif sys.argv[arg_index + 1] == mGUIDedSectionAttribue[EFI_GUIDED_SECTION_AUTH_STATUS_VALID]:
                SectGuidAttribute |= EFI_GUIDED_SECTION_AUTH_STATUS_VALID
            elif sys.argv[arg_index + 1] == mGUIDedSectionAttribue[0]:
                #None atrribute
                SectGuidAttribute |= EFI_GUIDED_SECTION_NONE
            else:
                logger.error("Invalid option value")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
        
        if sys.argv[arg_index] == "-l" or sys.argv[arg_index] == "--HeaderLength":
            res = AsciiStringToUint64(sys.argv[arg_index + 1],False,SectGuidHeaderLength)
            if type(res) == int:
                Status = res
            else:
                Status = res[0]
                SectGuidHeaderLength = res[1]
                
            if EFI_ERROR (Status):
                logger.error("Invalid option value for GuidHeaderLength")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            continue
        
        if sys.argv[arg_index] == "-n" or sys.argv[arg_index] == "--name":
            StringBuffer = sys.argv[arg_index + 1]
            if StringBuffer == None:
                logger.error("Invalid option value, Name can't be NULL")
                return STATUS_ERROR
            argc -= 2
            arg_index += 2
            print('The python tool of GenSec is called!')
            continue
            
        if sys.argv[arg_index] == "-j" or sys.argv[arg_index] == "--buildnumber":
            if sys.argv[arg_index + 1] == None:
                logger.error("Invalid option value, build number can't be NULL")
                return STATUS_ERROR
            
            #Verify string is a integrator number
            for ch in sys.argv[arg_index + 1]:
                if ch != '-' and isdigit(ch) == 0:
                    logger.error("Invalid option value")
                    return STATUS_ERROR
            VersionNumber = int(sys.argv[arg_index + 1])
            argc -= 2
            arg_index += 2
            continue
        
        if sys.argv[arg_index] == "-q" or sys.argv[arg_index] == "--quiet":
            logger.setLevel(logging.CRITICAL)
            argc -= 1
            arg_index += 1
            continue
        
        if sys.argv[arg_index] == "-v" or sys.argv[arg_index] == "--verbose":
            logger.setLevel(logging.DEBUG)
            argc -= 1
            arg_index += 1
            continue
 
        if sys.argv[arg_index] == "d" or sys.argv[arg_index] == "--debug":
            Status = AsciiStringToUint64 (sys.argv[arg_index + 1], False, LogLevel)
            if type(res) == int:
                Status = res
            else:
                Status = res[0]
                LogLevel = res[1]
            if EFI_ERROR (Status):
                logger.error("Invalid option value", "%s = %s"  %(sys.argv[arg_index],sys.argv[arg_index + 1]))
                return STATUS_ERROR
            if LogLevel > 9:
                logger.error("Invalid option value,Debug Level range is 0~9, current input level is %d" %(LogLevel))
                return STATUS_ERROR
            logger.setLevel(LogLevel)
            argc -= 2
            arg_index += 2
            continue
            
        #Section File alignment requirement
        if sys.argv[arg_index] == "--sectionalign":
            if InputFileAlignNum == 0:
                for i in range(MAXIMUM_INPUT_FILE_NUM):
                    InputFileAlign.append(1)
            elif InputFileAlignNum % MAXIMUM_INPUT_FILE_NUM == 0:
                for i in range(InputFileNum,InputFileNum + MAXIMUM_INPUT_FILE_NUM,1):
                    InputFileAlign.append(1)

            if sys.argv[arg_index + 1] == "0":
                InputFileAlign[InputFileAlignNum] = 0
                #InputFileAlign.append(0)
            else:
                res = StringtoAlignment(sys.argv[arg_index + 1],InputFileAlign[InputFileAlignNum])
                if type(res) == int:
                    Status = res
                else:
                    Status = res[0]
                    InputFileAlign[InputFileAlignNum] = res[1]
                    #InputFileAlign.append(res[1])
                if Status != 0:
                    logger.error("Invalid option value:Alignment")
                    return STATUS_ERROR
            argc -= 2
            arg_index += 2
            InputFileAlignNum += 1
            continue

        #Get Input file name
        if InputFileNum == 0 and len(InputFileName) == 0:
            for i in range(MAXIMUM_INPUT_FILE_NUM):
                InputFileName.append('0') 

        elif InputFileNum % MAXIMUM_INPUT_FILE_NUM == 0:
            for i in range(InputFileNum,InputFileNum + MAXIMUM_INPUT_FILE_NUM,1):
                InputFileName[i] = '0'
                
        InputFileName[InputFileNum] = sys.argv[arg_index]
        InputFileNum += 1
        argc -= 1
        arg_index += 1
        
        # if args.input:
        #     #InputFileName[InputFileNum] = args.input
        #     temp = []
        #     temp.append(args.input)
        #     InputFileName = temp[0]
        #     InputFileNum = len(InputFileName)
    
    if InputFileAlignNum > 0 and InputFileAlignNum != InputFileNum:
        logger.error("Invalid option, section alignment must be set for each section")
        return STATUS_ERROR
    for Index in range(InputFileAlignNum):
        if InputFileAlign[Index] == 0:
            res = GetAlignmentFromFile(InputFileName[Index], InputFileAlign[Index])
            if type(res) == int:
                Status = res
            else:
                Status =res[0]
                InputFileAlign[Index] = res[1]
            if EFI_ERROR(Status):
                logger.error("Fail to get Alignment from %s",InputFileName[InputFileNum])
                return STATUS_ERROR
    
    if DummyFileName:
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
            print("Warning: the input guid value is not required for this section type %s\n" %SectionName)
    
    #Check whether there is GUID for the SubtypeGuid section
    if SectType == EFI_SECTION_FREEFORM_SUBTYPE_GUID and (CompareGuid (VendorGuid, mZeroGuid) == 0):
        logger.error("Missing options: GUID")
        #return STATUS_ERROR

    #Check whether there is input file
    if SectType != EFI_SECTION_VERSION and SectType != EFI_SECTION_USER_INTERFACE:
        #The input file are required for other section type.
        if InputFileNum == 0:
            logger.error("Missing options: Input files")
    
    #Check whether there is output file
    if OutputFileName == None:
        logger.error("Missing options: Output file") 
        return STATUS_ERROR
    
    #Finish the command line parsing
    #With in this switch,build and write out the section header including any section
    #type specific pieces. If there is an input file, it's tacked on later
    if SectType == EFI_SECTION_COMPRESSION:
        res = GenSectionCompressionSection(InputFileNum,SectCompSubType,InputFileName,InputFileAlign,OutFileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status =res[0]
            OutFileBuffer = res[1]
            
    elif SectType == EFI_SECTION_GUID_DEFINED:
        res = GenSectionGuidDefinedSection(InputFileNum,VendorGuid,SectGuidAttribute,SectGuidHeaderLength,InputFileName,InputFileAlign,OutFileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status =res[0]
            OutFileBuffer = res[1]
         
    elif SectType == EFI_SECTION_FREEFORM_SUBTYPE_GUID:
        res = GenSectionSubtypeGuidSection(InputFileNum,VendorGuid,InputFileName,InputFileAlign,OutFileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status =res[0]
            OutFileBuffer = res[1]
            SubTypeGuid = res[2]
        
    elif SectType == EFI_SECTION_VERSION:
        Index = sizeof(EFI_COMMON_SECTION_HEADER)
        Index += 2
        #StringBuffer is ascii.. unicode is 2X + 2 bytes for terminating unicode null.
        Index += len(StringBuffer) * 2 + 2
        # print(Index)
        nums = len(StringBuffer)
        VersionSect = SET_EFI_VERSION_SECTION(nums)
        VersionSect.CommonHeader.Type = SectType
        VersionSect.CommonHeader.SET_SECTION_SIZE(Index)
        
        VersionSect.BuildNumber = VersionNumber

        Enc = StringBuffer.encode()
        for i in range(nums):
            ch = Enc[i]
            VersionSect.VersionString[i] = ch
        
        OutFileBuffer = struct2stream(VersionSect) + b'\0\0'
        
    elif SectType == EFI_SECTION_USER_INTERFACE:
        Index = sizeof (EFI_COMMON_SECTION_HEADER)
        Index += len (StringBuffer) * 2 + 2
        nums = len(StringBuffer)
        
        UiSect = SET_EFI_USER_INTERFACE_SECTION(nums)
        UiSect.CommonHeader.Type = SectType
        UiSect.CommonHeader.SET_SECTION_SIZE(Index)
        
        Enc = StringBuffer.encode()
        for i in range(nums):
            ch = Enc[i]
            UiSect.FileNameString[i] = ch
            
        OutFileBuffer = struct2stream(UiSect) + b'\0\0'
        
    elif SectType == EFI_SECTION_ALL:
        #Read all input file contents into a buffer
        #first fet the size of all file contents
        
        res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,OutFileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            OutFileBuffer = res[1]
            InputLength = res[2]
            
        if Status == EFI_BUFFER_TOO_SMALL:
            #OutFileBuffer = b'\0'* InputLength
            res = GetSectionContents(InputFileNum,InputLength,InputFileName,InputFileAlign,OutFileBuffer)
            if type(res) == int:
                Status = res
            else:
                Status = res[0]
                OutFileBuffer = res[1]
                InputLength = res[2]
            
    else:
        #All other section types are caught by default(they're all the same)
        res =  GenSectionCommonLeafSection(SectType,InputFileNum,InputFileName,OutFileBuffer)
        if type(res) == int:
            Status = res
        else:
            Status = res[0]
            OutFileBuffer = res[1]
        
        
    #Get output file length
    if SectType != EFI_SECTION_ALL:
        #SectionHeader = EFI_COMMON_SECTION_HEADER(OutFileBuffer[0:sizeof(EFI_COMMON_SECTION_HEADER)])
        SectionHeader = EFI_COMMON_SECTION_HEADER.from_buffer_copy(OutFileBuffer[0:sizeof(EFI_COMMON_SECTION_HEADER)])
        #InputLength = SectionHeader.Size & 0x00ffffff
        magic = lambda nums: int(''.join(str(i) for i in nums))
        InputLength = magic(SectionHeader.Size)
        if InputLength == 0xffffff:
            SectionHeader = EFI_COMMON_SECTION_HEADER2.from_buffer_copy(OutFileBuffer[0:sizeof(EFI_COMMON_SECTION_HEADER2)])
            InputLength = SectionHeader.ExtendedSize
            
    #Write the output file
    with open(OutputFileName,'wb') as OutFile:
        if OutFile == None:
            logger.error("Error opening file for writing")
            #return STATUS_ERROR
        OutFile.write(OutFileBuffer)
    
            
if __name__=="__main__":
    exit(main())