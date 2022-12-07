# @file
#  Utility program to create an EFI option ROM image from binary and EFI PE32 files.
#
#  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##


#Import modules
import argparse
import logging
from EfiStruct import *

STATUS_SUCCESS = 0
STATUS_ERROR = 2

parser = argparse.ArgumentParser(description='''
Utility program to create an EFI option ROM image from binary and EFI PE32 files.
''')
parser.add_argument("-o","--output",help = "Output Filename.File will be created to store the output content.")
parser.add_argument("-e",help = "EFI PE32 image files.")
parser.add_argument("-ec",help = "EfiFileName.EFI PE32 image files and will be compressed.")
parser.add_argument("-b",help = "Legacy binary files.")
parser.add_argument("-l","ClassCode.Hex ClassCode in the PCI data structure header.")
parser.add_argument("-r",help = "Rev.Hex Revision in the PCI data structure header.")
parser.add_argument("-n",help = "Not to automatically set the LAST bit in the last file.")
parser.add_argument("-f",help = "VendorId.Hex PCI Vendor ID for the device OpROM, must be specified")
parser.add_argument("-i",help = "DeviceId.One or more hex PCI Device IDs for the device OpROM, must be specified")
parser.add_argument("-p","--pci23",help = " Default layout meets PCI 3.0 specifications,specifying this flag will for a PCI 2.3 layout.")
parser.add_argument("-d","--dump",help = "Dump the headers of an existing option ROM image.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%(prog)s Version 1.0',
                    help="Show program's version number and exit.")

logger=logging.getLogger('EfiRom')

#Process a binary input file
def ProcessBinFile(OutFptr,Size:int,InFile:FILE_LIST):
    
    Status = STATUS_SUCCESS
    #Try to open the input file
    with open(InFile.FileName,"rb") as InFptr:
        if InFptr == None:
            logger.error("Error opening file : %s", InFile.FileName)
        Data = InFptr.read()
        FileSize = len(Data)
    Buffer = Data
    if len(Buffer) == 0:
        logger.error("Invalid, Failed to read all bytes from input file.")
        return STATUS_ERROR
    
    #Total size must be an even multiple of 512 bytes, and can't exceed
    #the option ROM image size.
    TotalSize = FileSize
    if TotalSize & 0x1FF:
        TotalSize = (TotalSize + 0x200) &~0x1ff
        
    if TotalSize > MAX_OPTION_ROM_SIZE:
        logger.error("Invalid parameter, Option ROM image size exceeds limit of 0x%X bytes.",MAX_OPTION_ROM_SIZE)
        return STATUS_ERROR
    
    #Return the size to the caller so they can keep track of the running total.
    Size =  TotalSize
    
    #Crude check to make sure it's a legitimate ROM image
    RomHdr = PCI_EXPANSION_ROM_HEADER.from_buffer_copy(Buffer[0:sizeof(PCI_EXPANSION_ROM_HEADER)])
    if RomHdr.Signature != PCI_EXPANSION_ROM_HEADER_SIGNATURE:
        logger.error("Invalid parameter, ROM image file has an invalid ROM signature.")
        return STATUS_ERROR
    
    #Make sure the pointer to the PCI data structure is within the size of the image.
    #Then check it for valid signature
    if RomHdr.PcirOffset > FileSize or RomHdr.PcirOffset == 0:
        logger.error("Invalid parameter, Invalid PCI data structure offset.")
        return STATUS_ERROR
    
    #Check the header is conform to PCI2.3 or PCI3.0
    if mOptions.Pci23 == 1:
        PciDs23 = PCI_DATA_STRUCTURE.from_buffer_copy(Buffer[RomHdr.PcirOffset:])
        if PciDs23.Signature != PCI_DATA_STRUCTURE_SIGNATURE:
            logger.error("Invalid parameter, PCI data structure has an invalid signature.")
            return STATUS_ERROR
    else:
        #Default setting is PCI3.0 header
        PciDs30 = PCI_3_0_DATA_STRUCTURE.from_buffer_copy(Buffer[RomHdr.PcirOffset:])
        logger.error("Invalid parameter, PCI data structure has an invalid signature.")
        return STATUS_ERROR
    
    #ReSet Option Rom size
    if mOptions.Pci23 == 1:
        PciDs23.ImageLength = TotalSize / 512
        CodeType = PciDs23.CodeType
    else:
        PciDs23.ImageLength = TotalSize / 512
        CodeType = PciDs30.CodeType
        
    #If this is the last image, then set the LAST bit unless requested not
    #to via the command-line -n argument. Otherwise, make sure you clear it.
    if InFile.Next == None and mOptions.NoLast == 0:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = INDICATOR_LAST
        else:
            PciDs30.Indicator = INDICATOR_LAST
    else:
        if mOptions.Pci23 == 1:
            PciDs23.Indicator = 0
        else:
            PciDs30.Indicator = 0
            
    if CodeType != PCI_CODE_TYPE_EFI_IMAGE:
        ByteCheckSum = 0
        for Index in range(FileSize - 1):
            ByteCheckSum = ByteCheckSum + Buffer[Index]
        Temp = ~ByteCheckSum + 1
        Buffer = Buffer.replace(Buffer[FileSize - 1] , Temp.to_bytes(1,byteorder= 'little'))
        
    #Now copy the input file contents out to the output file
    OutFptr.write(Buffer)
    if OutFptr == None:
        logger.error("Failed to write all file bytes to output file.")
        return STATUS_ERROR
    
    TotalSize -= FileSize
    #Pad the rest of the image to make it a multiple of 512 bytes
    while TotalSize > 0:
        # putc (~0, OutFptr)
        a = ~0
        OutFptr = OutFptr + a.to_bytes(1,byteorder= 'little')
        TotalSize -= 1
    return Status,Size
