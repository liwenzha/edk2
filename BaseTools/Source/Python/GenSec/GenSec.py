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
from PeCoff import *
from BaseTypes import *
from ParseInf import *
from GenSecOperations import *


UTILITY_NAME = 'GenSec'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1


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
        
    #Section File alignment requirement
    if args.SectionAlign:
        if InputFileAlignNum == 0:
            for i in range(MAXIMUM_INPUT_FILE_NUM):
                InputFileAlign.append(1)
        elif InputFileAlignNum % MAXIMUM_INPUT_FILE_NUM == 0:
            for i in range(InputFileNum,InputFileNum + MAXIMUM_INPUT_FILE_NUM,1):
                InputFileAlign[i] = 0

        if args.SectionAlign == "0":
            InputFileAlign[InputFileAlignNum] = 0
        else:
            Status = StringtoAlignment(args.SectionAlign,InputFileAlign[InputFileAlignNum])
            if EFI_ERROR (Status):
                logger.error("Invalid option value")
                #return STATUS_ERROR
        InputFileAlignNum += 1

    #Get input file name
    if InputFileNum == 0 and len(InputFileName) == 0:
        for i in range(MAXIMUM_INPUT_FILE_NUM):
            InputFileName.append('0') 

    elif InputFileNum % MAXIMUM_INPUT_FILE_NUM == 0:
        for i in range(InputFileNum,InputFileNum + MAXIMUM_INPUT_FILE_NUM,1):
            InputFileName[i] = '0'
            
    # for i in range(InputFileNum):
    InputFileName[InputFileNum] = sys.argv[0]
    InputFileNum += 1
    #到此为止，命令行的读取结束
    
    
    #这里开始对于读取到的参数进行分析处理
    if InputFileAlignNum > 0 and InputFileAlignNum != InputFileNum:
        logger.error("Invalid option, section alignment must be set for each section")
        #return STATUS_ERROR
    for Index in range(InputFileAlignNum):
        if InputFileAlign[Index] == 0:
            Status = GetAlignmentFromFile(InputFileName[Index], InputFileAlign[Index])
            if EFI_ERROR(Status):
                logger.error("Fail to get Alignment from %s",InputFileName[InputFileNum])
    
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