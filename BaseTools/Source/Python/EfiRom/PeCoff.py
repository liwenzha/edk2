# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent


from BaseTypes import *
from FirmwareStorageFormat.SectionHeader import *
import logging


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


#PE32+ Subsystem type for EFI images
EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION = 10
EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11
EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12
EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER = 13


#EFI_IMAGE_OPTIONAL_HEADER32 and EFI_IMAGE_OPTIONAL_HEADER64
#are for use ONLY by tools.  All proper EFI code MUST use
#EFI_IMAGE_OPTIONAL_HEADER ONLY!!!
EFI_IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b


EFI_IMAGE_FILE_RELOCS_STRIPPED = 0x0001     #Relocation info stripped from file.


#Return status codes from the PE/COFF Loader services
IMAGE_ERROR_IMAGE_READ = 1
STATUS_ERROR = 2
logger = logging.getLogger('GenSec')


#PE32+ Machine tyoe for images
IMAGE_FILE_MACHINE_I386 = 0x014c
IMAGE_FILE_MACHINE_EBC = 0x0EBC
IMAGE_FILE_MACHINE_X64 = 0x8664
IMAGE_FILE_MACHINE_ARM = 0x01c0     #Thumb only
IMAGE_FILE_MACHINE_ARMT = 0x01c2    #32bit Mixed ARM and Thumb/Thumb 2 Little Endian
IMAGE_FILE_MACHINE_ARM64 = 0xAA64   #64bit ARM Architecture ,Little Endian
IMAGE_FILE_MACHINE_RISCV64 = 0x5064 #64bit RISC-V ISA
IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264 #64bit LoongArch Architecture


#Support old names for backward compatible
EFI_IMAGE_MACHINE_IA32 = IMAGE_FILE_MACHINE_I386
EFI_IMAGE_MACHINE_EBC = IMAGE_FILE_MACHINE_EBC
EFI_IMAGE_MACHINE_X64 = IMAGE_FILE_MACHINE_X64
EFI_IMAGE_MACHINE_ARMT = IMAGE_FILE_MACHINE_ARMT
EFI_IMAGE_MACHINE_AARCH64 = IMAGE_FILE_MACHINE_ARM64
EFI_IMAGE_MACHINE_RISCV64 = IMAGE_FILE_MACHINE_RISCV64
EFI_IMAGE_MACHINE_LOONGARCH64 = IMAGE_FILE_MACHINE_LOONGARCH64

EFI_IMAGE_DOS_SIGNATURE = 0x5A4D    # MZ
EFI_IMAGE_NT_SIGNATURE = 0x00004550 # PE00


#Directory Entries
EFI_IMAGE_DIRECTORY_ENTRY_DEBUG = 6


#Debug Format
EFI_IMAGE_DEBUG_TYPE_CODEVIEW = 2




#Retrieves the PE or TE Header from a PE/COFF or te image
def PeCoffLoaderGetPeHeader(ImageContext:PE_COFF_LOADER_IMAGE_CONTEXT,PeHdr:EFI_IMAGE_OPTIONAL_HEADER_UNION,TeHdr:EFI_TE_IMAGE_HEADER):
    #DosHdr = EFI_IMAGE_DOS_HEADER()

    DosHdrBuffer = b''
    ImageContext.IsTeImage = False
    
    #Read the DOS image header
    Size = sizeof(EFI_IMAGE_DOS_HEADER)
    res = ImageContext.ImageRead(0,Size,ImageContext.Handle,DosHdrBuffer)
    if type(res) == 'int':
        Status = res
        
    else:
        Status = res[0]
        Size = res[1]
        DosHdrBuffer = res[2]
        
    DosHdr = EFI_IMAGE_DOS_HEADER.from_buffer_copy(DosHdrBuffer)
    if RETURN_ERROR (Status):
        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
        return Status
    
    ImageContext.PeCoffHeaderOffset = 0
    if DosHdr.e_magic == EFI_IMAGE_DOS_SIGNATURE:
        #DOS image header is present ,so read the PE header after the DOS image header
        ImageContext.PeCoffHeaderOffset = DosHdr.e_lfanew
        
    #Get the PE/COFF Header pointer
    PeHdrBuffer = ImageContext.Handle[ImageContext.PeCoffHeaderOffset : ImageContext.PeCoffHeaderOffset + sizeof(EFI_IMAGE_OPTIONAL_HEADER_UNION)]
    PeHdr =  EFI_IMAGE_OPTIONAL_HEADER_UNION.from_buffer_copy(PeHdrBuffer)
    if PeHdr.Pe32.Signature != EFI_IMAGE_NT_SIGNATURE:
        #Check the PE/COFF Header Signature.If not,then try to get a TE header
        
        TeHdr = EFI_TE_IMAGE_HEADER.from_buffer_copy(PeHdrBuffer)
        if TeHdr.Signature != EFI_TE_IMAGE_HEADER_SIGNATURE:
            return RETURN_UNSUPPORTED
        ImageContext.IsTeImage = True
    
    Status = RETURN_SUCCESS
    return Status,PeHdr,TeHdr


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
            #Unsupported PeImage machine type
            return RETURN_UNSUPPORTED
    
    #See if the image type is supported.  We support EFI Applications,
    #EFI Boot Service Drivers, EFI Runtime Drivers and EFI SAL Drivers.
    if ImageContext.IsTeImage == False:
        ImageContext.ImageType = PeHdr.Pe32.OptionalHeader.Subsystem
    else:
        ImageContext.ImageType = TeHdr.Subsystem
    if ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER\
        and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER and ImageContext.ImageType != EFI_IMAGE_SUBSYSTEM_SAL_RUNTIME_DRIVER:
        #Unsupported PeImage subsystem type
        return RETURN_UNSUPPORTED
    Status = RETURN_SUCCESS
    return Status,PeHdr,TeHdr


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
    
    res = PeCoffLoaderGetPeHeader(ImageContext,PeHdr,TeHdr)
    if type(res) == 'int':
        Status = res

    else:
        Status = res[0]
        PeHdr = res[1]
        TeHdr = res[2]
    
    if RETURN_ERROR(Status):
        return Status
    
    #Verify machine type
    res = PeCoffLoaderCheckImageType(ImageContext,PeHdr,TeHdr)
    if type(res) == 'int':
        Status = res

    else:
        Status = res[0]
        PeHdr = res[1]
        TeHdr = res[2]
        
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
    ImageContext.CodeView = 0
    ImageContext.PdbPointer = 0
    
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
            
            #Modify ImageSize to contain .PDB file name if required and initialize
            #PdbRVA field...
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
                
        if DebugDirectoryEntryRva != 0:
            #Determine the file offset of the debug directory...  This means we walk
            #the sections to find which section contains the RVA of the debug directory

            DebugDirectoryEntryFileOffset = 0
            SectionHeaderOffset = ImageContext.PeCoffHeaderOffset +\
                                    sizeof(c_uint32) +\
                                    sizeof(EFI_IMAGE_FILE_HEADER)+\
                                    PeHdr.Pe32.FileHeader.SizeOfOptionalHeader
                                    
            for Index in range(PeHdr.Pe32.FileHeader.NumberOfSections):
                #Read section header from file
                Size = sizeof(EFI_IMAGE_SECTION_HEADER)
                SectionHeaderBuffer = b''
                res = ImageContext.ImageRead(SectionHeaderOffset,
                                                Size,ImageContext.Handle,SectionHeaderBuffer)
                if type(res)== 'int':
                    Status = res
                    logger.error("Status is not successful, Status value is 0x%X",int(Status))
                    return STATUS_ERROR
                else:
                    Status = res[0]
                    Size = res[1]
                    SectionHeaderBuffer = res[2]
                    
                SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(SectionHeaderBuffer)
                if RETURN_ERROR(Status):
                    ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                    return Status
                
                if DebugDirectoryEntryRva >= SectionHeader.VirtualAddress and DebugDirectoryEntryRva < SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize:
                    DebugDirectoryEntryFileOffset = DebugDirectoryEntryRva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData
                    break
                SectionHeaderOffset += sizeof (EFI_IMAGE_SECTION_HEADER)
                
            if DebugDirectoryEntryFileOffset != 0:
                for Index in range(0,DebugDirectoryEntry.Size,sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)):
                    #Read next debug directory entry
                    Size = sizeof (EFI_IMAGE_DEBUG_DIRECTORY_ENTRY)
                    DebugEntryBuffer = b''
                    res = ImageContext.ImageRead(DebugDirectoryEntryFileOffset + Index,
                                                    Size,ImageContext.Handle,DebugEntryBuffer)
                    if type(res)== 'int':
                        Status = res
                        logger.error("Status is not successful, Status value is 0x%X",int(Status))
                        return STATUS_ERROR
                    else:
                        Status = res[0]
                        Size = res[1]
                        DebugEntryBuffer = res[2]
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(DebugEntryBuffer)
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
                SectionHeaderBuffer = b''
                res = ImageContext.ImageRead(SectionHeaderOffset,Size,ImageContext.Handle,SectionHeaderBuffer)
                if type(res)== 'int':
                    Status = res
                    logger.error("Status is not successful, Status value is 0x%X",int(Status))
                    return STATUS_ERROR
                else:
                    Status = res[0]
                    Size = res[1]
                    SectionHeaderBuffer = res[2]
                SectionHeader = SectionHeader = EFI_IMAGE_SECTION_HEADER.from_buffer_copy(SectionHeaderBuffer)
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
                    DebugEntryBuffer = b''
                    res = ImageContext.ImageRead(DebugDirectoryEntryFileOffset,
                                                    Size,ImageContext.Handle,DebugEntryBuffer)
                    if type(res)== 'int':
                        Status = res
                        logger.error("Status is not successful, Status value is 0x%X",int(Status))
                        return STATUS_ERROR
                    else:
                        Status = res[0]
                        Size = res[1]
                        DebugEntryBuffer = res[2]
                    DebugEntry = EFI_IMAGE_DEBUG_DIRECTORY_ENTRY.from_buffer_copy(DebugEntryBuffer)
                    if RETURN_ERROR (Status):
                        ImageContext.ImageError = IMAGE_ERROR_IMAGE_READ
                        return Status
                    
                    if DebugEntry.Type is EFI_IMAGE_DEBUG_TYPE_CODEVIEW:
                        ImageContext.DebugDirectoryEntryRva = DebugDirectoryEntryRva + Index
                        Status = RETURN_SUCCESS
    return Status,ImageContext