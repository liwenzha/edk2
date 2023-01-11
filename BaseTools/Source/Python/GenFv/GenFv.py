# @file
# This contains all code necessary to build the GenFv utility.
# Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent

import argparse
import logging
#import sys
from FirmwareStorageFormat.FvHeader import *
from BaseTypes import *
from ParseInf import *

UTILITY_NAME = 'GenFv'
UTILITY_MAJOR_VERSION = 0
UTILITY_MINOR_VERSION = 1

CAPSULE_FLAGS_PERSIST_ACROSS_RESET = 0x00010000
CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE = 0x00020000
CAPSULE_FLAGS_INITIATE_RESET = 0x00040000

EFI_GUID_STRING = "EFI_GUID"
FV_BASE_ADDRESS_STRING = "[FV_BASE_ADDRESS]"
OPTIONS_SECTION_STRING = "[options]"
EFI_CAPSULE_GUID_STRING = "EFI_CAPSULE_GUID"
EFI_CAPSULE_HEADER_SIZE_STRING = "EFI_CAPSULE_HEADER_SIZE"
EFI_CAPSULE_FLAGS_STRING = "EFI_CAPSULE_FLAGS"

mFvBaseAddress = [0]*0x10

mEfiFirmwareFileSystem2Guid = EFI_GUID(0x8c8ce578, 0x8a3d, 0x4f1c, (0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3 ))
mEfiFirmwareFileSystem3Guid = EFI_GUID(0x5473c07a, 0x3dcb, 0x4dca, (0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a ))
mZeroGuid = EFI_GUID(0,0,0,(0,0,0,0,0,0,0,0))
mDefaultCapsuleGuid = EFI_GUID(0x3B6686BD, 0x0D76, 0x4030, (0xB7, 0x0E, 0xB5, 0x51, 0x9E, 0x2F, 0xC5, 0xA0))

mCapDataInfo = CAP_INFO()

STATUS_ERROR = 2

logger = logging.getLogger("GenFv")

parser=argparse.ArgumentParser(description = "This contains all code necessary to build the GenFv utility.")
parser.add_argument("-o","--outputfile",dest = "Output",help = "File is the FvImage or CapImage to be created.")
parser.add_argument("-i","--inputfile",dest = "Input",help = "File is the input FV.inf or Cap.inf to specify how to construct FvImage or CapImage.")
parser.add_argument("-b","--blocksize",dest = "BlockSize",help = "BlockSize is one HEX or DEC format value.BlockSize is required by Fv Image.")
parser.add_argument("-n","--numberblock",dest = "NumberBlock",help = "NumberBlock is one HEX or DEC format value.NumberBlock is one optional parameter.")
parser.add_argument("-f","--ffsfile",dest = "FfsFile",dest = "FfsFile",help = "FfsFile is placed into Fv Image multi files can input one by one")
parser.add_argument("-s","--filetakensize", dest = "FileTakenSize", help = "FileTakenSize specifies the size of the required\
                    space that the input file is placed in Fvimage. It is specified together with the input file.")
parser.add_argument("-r","--baseaddr",dest = "Address", help = "Address is the rebase start address for drivers that\
                    run in Flash. It supports DEC or HEX digital format.If it is set to zero, no rebase action will be taken")
parser.add_argument("-F","--force-rebase",dest = "ForceRebase",help = "If value is TRUE, will always take rebase action\
                    If value is FALSE, will always not take reabse action.If not specified, will take rebase action if rebase address greater than zero,\
                    will not take rebase action if rebase address is zero.")
parser.add_argument("-a","--addrfile",dest = "AddressFile",help = "AddressFile is one file used to record the child\
                    FV base address when current FV base address is set.")
parser.add_argument("-m","--map",dest = "logfile",help = "Logfile is the output fv map file name. if it is not\
                    given, the FvName.map will be the default map file name")
parser.add_argument("-g","--guid",dest = "Guid",help = "GuidValue is one specific capsule guid value or fv file system guid value.")
parser.add_argument("--FvNameGuid",dest = "FvNameGuid",help = "Guid is used to specify Fv Name.\
                    Its format is xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
parser.add_argument("--capflag",dest = "CapFlag",help = "Capsule Reset Flag can be PersistAcrossReset,\
                    or PopulateSystemTable or InitiateReset or not set")
parser.add_argument("--capoemflag",dest = "CapOEMFlag",help = "Capsule OEM Flag is an integer between 0x0000 and 0xffff")
parser.add_argument("--capheadsize",dest = "HeadSize",help = "HeadSize is one HEX or DEC format value.HeadSize is required by Capsule Image.")
parser.add_argument("-c","--capsule",dest = "capsule",help = "Create Capsule Image.")
parser.add_argument("-p","--dump",dest = "dump",help = "Dump Capsule Image header.")
parser.add_argument("-v","--verbose",dest = "verbose",help = "Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest = "quiet",help = "Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest = "debug",help = "Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%s Version %d.%d'%(UTILITY_NAME,UTILITY_MINOR_VERSION,UTILITY_MAJOR_VERSION),
                    help="Show program's version number and exit.")


def EFI_ERROR(A):
    if A < 0:
        return True
    else:
        return False

#This function opens a file and reads it into a memory buffer.  The function
#will allocate the memory buffer and returns the size of the buffer.
def GetFileImage(InputFileName:str,InputFileImage:bytes,BytesRead:c_uint32):
    Status = STATUS_ERROR
    #Verify input parameters.
    if InputFileName == None or len (InputFileName) == 0 or InputFileImage == None:
        return EFI_INVALID_PARAMETER
    
    #Open the file and copy contents into a memory buffer.
    with open(InputFileName,"rb") as InputFile:
        if InputFile == None:
            logger.error("Error opening the input file: %s" %InputFileName)
            return EFI_ABORTED
        Data = InputFile.read()
        if Data == None:
            logger.error("Error reading the input file: %s" %InputFileName)
            return EFI_ABORTED
        FileSize = len(Data)
        
    InputFileImage = Data
    BytesRead = FileSize
    Status = EFI_SUCCESS
    return Status,InputFileImage,BytesRead


#This function parses a Cap.INF file and copies info into a CAP_INFO structure.
def ParseCapInf(InfFile:MEMORY_FILE,CapInfo:CAP_INFO):
    Value = ''
    Value64 = 0
    Status = FindToken (InfFile, OPTIONS_SECTION_STRING, EFI_CAPSULE_GUID_STRING, 0, Value)
    if Status == EFI_SUCCESS:
        #Get the Capsule Guid
        res = StringToGuid(Value,CapInfo.CapGuid)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            CapInfo.CapGuid = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid parameter, %s = %s" %(EFI_CAPSULE_GUID_STRING, Value))
            return EFI_ABORTED
        
    #Read the Capsule Header Size
    Status = FindToken (InfFile, OPTIONS_SECTION_STRING, EFI_CAPSULE_HEADER_SIZE_STRING, 0, Value);
    if Status == EFI_SUCCESS:
        res = AsciiStringToUint64(Value, False, Value64)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            Value64 = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid parameter, %s = %s" %(EFI_CAPSULE_HEADER_SIZE_STRING, Value))
            return EFI_ABORTED
        CapInfo.HeaderSize = Value64

    #Read the Capsule Flag
    Status = FindToken (InfFile, OPTIONS_SECTION_STRING, EFI_CAPSULE_FLAGS_STRING, 0, Value)
    






#This is the main function which will be called from application to create UEFI Capsule image.
def GenerateCapImage(InfFileImage:bytes,InfFileSize:c_uint64,CapFileName:str):
    InfMemoryFile = MEMORY_FILE()
    Status = STATUS_ERROR
    
    if InfFileImage != None:
        InfMemoryFile.FileImage           = InfFileImage.decode()
        InfMemoryFile.CurrentFilePointer  = InfFileImage.decode()
        InfMemoryFile.Eof                 = InfFileImage[InfFileSize:].decode()

    #Parse the Cap inf file for header information
    res = ParseCapInf(InfMemoryFile, mCapDataInfo)
    if Status != EFI_SUCCESS:
        return Status
    
    if mCapDataInfo.HeaderSize == 0:
        #make header size align 16 bytes.
        mCapDataInfo.HeaderSize = sizeof (EFI_CAPSULE_HEADER)
        mCapDataInfo.HeaderSize = (mCapDataInfo.HeaderSize + 0xF) & ~0xF
        
    if mCapDataInfo.HeaderSize < sizeof (EFI_CAPSULE_HEADER):
        logger.error("Invalid parameter, The specified HeaderSize cannot be less than the size of EFI_CAPSULE_HEADER.")
        return EFI_INVALID_PARAMETER
    
    if CapFileName == None and mCapDataInfo.CapName[0] != '\0':
        CapFileName = mCapDataInfo.CapName
        
    if CapFileName == None:
        logger.error("Missing required argument, Output Capsule file name")
        return EFI_INVALID_PARAMETER
        
    #Set Default Capsule Guid value
    if CompareGuid (mCapDataInfo.CapGuid, mZeroGuid) == 0:
        mCapDataInfo.CapGuid = mDefaultCapsuleGuid
        
    #Calculate the size of capsule image.
    Index = 0
    CapSize = mCapDataInfo.HeaderSize
    while mCapDataInfo.CapFiles [Index][0] != '\0':
        with open(mCapDataInfo.CapFiles[Index],"rb") as fpin:
            if fpin == None:
                logger.error("Error opening file:%s" %mCapDataInfo.CapFiles[Index])
                return EFI_ABORTED
            Data = fpin.read()
            FileSize = len(Data)
            CapSize  += FileSize
        Index += 1
        
    #create capsule header and get capsule body
    CapBuffer = b''
    CapsuleHeader = EFI_CAPSULE_HEADER()
    CapsuleHeader.HeaderSize = mCapDataInfo.HeaderSize
    CapsuleHeader.Flags = mCapDataInfo.Flags
    CapsuleHeader.CapsuleImageSize = CapSize
    
    Index    = 0
    FileSize = 0
    CapSize  = CapsuleHeader.HeaderSize
    while mCapDataInfo.CapFiles [Index][0] != '\0':
        with open(mCapDataInfo.CapFiles[Index],"rb") as fpin:
            if fpin == None:
                logger.error("Error opening file:%s" %mCapDataInfo.CapFiles[Index])
                return EFI_ABORTED
            Data = fpin.read()
            FileSize = len(Data)
            CapBuffer = struct2stream(CapsuleHeader) + Data
        Index += 1
        CapSize  += FileSize
        
    #Write capsule data into the outputfile
    with open(CapFileName,"wb") as fpout:
        if fpout == None:
            logger.error("Error opening file:%s" %CapFileName)
            return EFI_ABORTED
        fpout.write(CapBuffer)
    Status = EFI_SUCCESS
    return Status
        

def main():
    InfFileName = ''
    AddrFileName = ''
    TempNumber = 0
    CapsuleFlag = False
    DumpCapsule = False
    InfFileImage = b''
    InfFileSize   = 0
    mFvBaseAddressNumber = 0
    Status = EFI_SUCCESS
    #Index = 0
    
    CapsuleHeader = EFI_CAPSULE_HEADER()
    mFvDataInfo = FV_INFO()
    mCapDataInfo = CAP_INFO()
     
    args = parser.parse_args()
    argc =len(args)
    
    if argc == 1:
        parser.print_help()
        logger.error("Missing options.No input options specified.")
        return STATUS_ERROR
    
    #Set the default FvGuid
    mFvDataInfo.FvFileSystemGuid = mEfiFirmwareFileSystem2Guid
    mFvDataInfo.ForceRebase = -1
    
    #Parse command line
    if args.Input:
        InfFileName = args.Input
        if args.Input == None:
            logger.error("Invalid option value, Input file can't be null")
            Status = STATUS_ERROR
            return Status
        
    if args.AddressFile:
        AddrFileName = args.AddressFile
        if args.AddressFile == None:
            logger.error("Invalid option value, Address file can't be null")
            Status = STATUS_ERROR
            return Status
        
    if args.Output:
        OutFileName = args.Output
        if args.Output == None:
            logger.error("Invalid option value, Output file can't be null")
            Status = STATUS_ERROR
            return Status
        
    if args.Address:
        res = AsciiStringToUint64 (args.Address, False, TempNumber)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempNumber = res[1]
        if EFI_ERROR (Status):
            logger.error("Invalid option value, %s = %s" %("-r", args.Address))
            return STATUS_ERROR
        mFvDataInfo.BaseAddress = TempNumber
        mFvDataInfo.BaseAddressSet = True
        
    if args.BlockSize:
        res = AsciiStringToUint64 (args.BlockSize, False, TempNumber)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempNumber = res[1]
        if EFI_ERROR (Status):
            logger.error("Invalid option value, %s = %s" %("-r", args.BlockSize))
            return STATUS_ERROR
        if TempNumber == 0:
            logger.error("Invalid option value, Fv block size can't be set to zero")
            return STATUS_ERROR
        mFvDataInfo.FvBlocks[0].Length = TempNumber
    
    if args.NumberBlock:
        res = AsciiStringToUint64 (args.NumberBlock, False, TempNumber)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempNumber = res[1]
        if EFI_ERROR (Status):
            logger.error("Invalid option value, %s = %s" %("-r", args.NumberBlock))
            return STATUS_ERROR
        if TempNumber == 0:
            logger.error("Invalid option value, Fv block number can't be set to zero")
            return STATUS_ERROR
        mFvDataInfo.FvBlocks[0].NumBlocks = TempNumber
    
    if args.FfsFile:
        if args.FfsFile == None:
            logger.error("Invalid option value, Input Ffsfile can't be null")
            return STATUS_ERROR
        
        if len(args.FfsFile) > MAX_LONG_FILE_PATH - 1:
            logger.error("Invalid option value, Input Ffsfile name %s is too long!" %args.FfsFile)
            return STATUS_ERROR

        mFvDataInfo.FvFiles[Index] = args.FfsFile[0:(MAX_LONG_FILE_PATH - 1)]
        mFvDataInfo.FvFiles[Index][MAX_LONG_FILE_PATH - 1] = 0

        if args.FileTakenSize:
            if args.FileTakenSize == None:
                logger.error("Invalid option value, Ffsfile Size can't be null")
                return STATUS_ERROR
            res = AsciiStringToUint64(args.FileTakenSize,False,TempNumber)
            if type(res) == 'int':
                Status = res
            else:
                Status = res[0]
                TempNumber = res[1]
            if EFI_ERROR (Status):
                logger.error("Invalid option value, %s = %s" %("-r", args.NumberBlock))
                return STATUS_ERROR
            mFvDataInfo.SizeofFvFiles[Index] = TempNumber
        Index += 1
        
    if args.FileTakenSize and not args.FfsFile:
        logger.error("Invalid option, It must be specified together with -f option to specify the file size.")
        return STATUS_ERROR
    
    if args.capsule:
        CapsuleFlag = True
    
    if args.ForceRebase:
        if args.ForceRebase == None:
            logger.error("Invalid option value, Force rebase flag can't be null")
            return STATUS_ERROR
        if args.ForceRebase == "TRUE":
            mFvDataInfo.ForceRebase = 1
        elif args.ForceRebase == "FALSE":
            mFvDataInfo.ForceRebase = 0
        else:
            logger.error("Invalid option, force rebase flag value must be \"TRUE\" or \"FALSE\"")
            return STATUS_ERROR

    if args.HeadSize:
        #Get Capsule Image Header Size
        res = AsciiStringToUint64(args.HeadSize,False,TempNumber)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempNumber = res[1]
        if EFI_ERROR (Status):
            logger.error("Invalid option value, %s = %s" %("-r", args.HeadSize))
            return STATUS_ERROR
        mCapDataInfo.HeaderSize = TempNumber
        
    if args.CapFlag:
        #Get Capsule Header
        if args.CapFlag == None:
            logger.error("Option value is not set, %s = %s" %("--capflag",args.CapFlag))
            return STATUS_ERROR
        if "InitiateReset" "PopulateSystemTable":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_POPULATE_SYSTEM_TABLE
        elif args.CapFlag == "PersistAcrossReset":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET
        elif "InitiateReset" == "InitiateReset":
            mCapDataInfo.Flags |= CAPSULE_FLAGS_PERSIST_ACROSS_RESET | CAPSULE_FLAGS_INITIATE_RESET
        else:
            logger.error("Invalid option value, %s = %s" %("--capflag",args.CapFlag))
            
    if args.CapOEMFlag:
        if args.CapOEMFlag == None:
            logger.error("Invalid option value, Capsule OEM flag can't be null")
        res = AsciiStringToUint64(args.CapOEMFlag,False,TempNumber)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            TempNumber = res[1]
        if EFI_ERROR(Status) or TempNumber > 0xffff:
            logger.error("Invalid option value, Capsule OEM flag can't be null")
            return STATUS_ERROR
        mCapDataInfo.Flags |= TempNumber
          
    #if args."--capguid"? 这个部分还要看一下
    if args.Guid:
        #Get the Capsule or Fv Guid
        res = StringToGuid(args.Guid,mCapDataInfo.CapGuid)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            mCapDataInfo.CapGuid = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid option value, %s = %s" %(EFI_GUID_STRING,args.Guid))
            return STATUS_ERROR
        mFvDataInfo.FvFileSystemGuid = mCapDataInfo.CapGuid
        mFvDataInfo.FvFileSystemGuidSet = True
        
    if args.FvNameGuid:
        #Get Fv Name Guid
        res = StringToGuid(args.FvNameGuid,mFvDataInfo.FvNameGuid)
        if type(res) == 'int':
            Status = res
        else:
            Status = res[0]
            mFvDataInfo.FvNameGuid = res[1]
        if EFI_ERROR(Status):
            logger.error("Invalid option value, %s = %s" %(EFI_GUID_STRING,args.FvNameGuid))
            return STATUS_ERROR
        mFvDataInfo.FvNameGuidSet = True
        
    if args.dump:
        DumpCapsule = True
        
    if args.logfile:
        MapFileName = args.logfile
        if MapFileName == None:
            logger.error("Invalid option value, Map file can't be null")
            return STATUS_ERROR

    if args.verbose:
        pass
    
    if args.quiet:
        pass
    
    if args.debug:
        pass
    
    else:
        logger.error("Unknown option")
        return STATUS_ERROR
    
    #check input parameter, InfFileName can be NULL
    if InfFileName == None and DumpCapsule:
        logger.error("Missing option, Input Capsule Image")
        return STATUS_ERROR
    
    if DumpCapsule == False and OutFileName == None:
        logger.error("Missing option, Output File")
        return STATUS_ERROR
    
    #Read the INF file image
    if InfFileName != None:
        res = GetFileImage(InfFileName,InfFileImage,InfFileSize)
        if type(res) == 'int':
             Status = res
        else:
            Status = res[0]
            InfFileImage = res[1]
            InfFileSize = res[2]
        
    if EFI_ERROR (Status):
        return STATUS_ERROR
    
    if DumpCapsule:
        #Dump Capsule Image Header Information
        CapsuleHeader = EFI_CAPSULE_HEADER.from_buffer_copy(InfFileImage[0:])
        if OutFileName == None:
            FpFile = None
            logger.error("No OutFile")
        else:
            FpFile = open(OutFileName,"w")
            if FpFile == None:
                logger.error("Error opening file")
                return STATUS_ERROR
        if FpFile != None:
            FpFile.write("Capsule %s Image Header Information\n" %InfFileName)
            FpFile.write("GUID %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n"
                  %(CapsuleHeader.CapsuleGuid.Data1,CapsuleHeader.CapsuleGuid.Data2,CapsuleHeader.CapsuleGuid.Data3,
                    CapsuleHeader.CapsuleGuid.Data4[0],CapsuleHeader.CapsuleGuid.Data4[1],
                    CapsuleHeader.CapsuleGuid.Data4[2],CapsuleHeader.CapsuleGuid.Data4[3],
                    CapsuleHeader.CapsuleGuid.Data4[4],CapsuleHeader.CapsuleGuid.Data4[5],
                    CapsuleHeader.CapsuleGuid.Data4[6],CapsuleHeader.CapsuleGuid.Data4[7]))
            FpFile.write("Header size 0x%08X\n" %CapsuleHeader.HeaderSize)
            FpFile.write("Flags 0x%08X\n" %CapsuleHeader.Flags)
            FpFile.write("Capsule image size 0x%08X\n" %CapsuleHeader.CapsuleImageSize)
            FpFile.close()
            
    elif CapsuleFlag:
        #Call the GenerateCapImage to generate Capsule Image
        Index = 0
        while mFvDataInfo.FvFiles[Index][0] != '\0':
            mCapDataInfo.CapFiles[Index] = mFvDataInfo.FvFiles[Index]
            Index += 1
        Status = GenerateCapImage(InfFileImage,InfFileSize,OutFileName)
        
    else:
        # Will take rebase action at below situation:
        # 1. ForceRebase Flag specified to TRUE;
        # 2. ForceRebase Flag not specified, BaseAddress greater than zero.
        
        # Call the GenerateFvImage to generate Fv Image
        res = GenerateFvImage(InfFileImage,InfFileSize,OutFileName,MapFileName)
    
    #Update boot driver address and runtime driver address in address file
    if Status == EFI_SUCCESS and AddrFileName != None and mFvBaseAddressNumber > 0:
        FpFile = open(AddrFileName,"w")
        if FpFile == None:
            logger.error("Error opening file")
            return STATUS_ERROR
        FpFile.write(FV_BASE_ADDRESS_STRING)
        FpFile.write("\n")
        for Index in range(mFvBaseAddressNumber):
            FpFile.write("0x%x\n" %mFvBaseAddress[Index])
        FpFile.close()
        
    return Status
    

if __name__ == "__main__":
    exit(main())