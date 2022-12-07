# @file
#  Some structure definitions used in EfiRom.
#
#  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##



from ctypes import *
from struct import *

def SIGNATURE_16(A,B):
    return A | B << 8

def SIGNATURE_32(A,B,C,D):
    return SIGNATURE_16 (A, B) | SIGNATURE_16 (C, D) << 16
    
MAX_OPTION_ROM_SIZE = 1024 * 1024 * 16
PCI_EXPANSION_ROM_HEADER_SIGNATURE = 0xaa55
PCI_DATA_STRUCTURE_SIGNATURE = SIGNATURE_32 ('P', 'C', 'I', 'R')
INDICATOR_LAST = 0x80 
PCI_CODE_TYPE_EFI_IMAGE = 0x03



class FILE_LIST(Structure):
    __pack__ = 1
    __fields__ =[
        ('FileName',c_char),
        ('FileFlags',c_uint32),
        ('ClassCode',c_uint32),
        ('CodeRevision',c_uint16)
    ]
    

class PCI_EXPANSION_ROM_HEADER(Structure):
    __pack__ = 1
    __fields__ =[
        ('Signature',c_uint16),        #0xaa55
        ('Reserved',ARRAY(c_uint,0X16)),
        ('PcirOffset',c_uint16)
    ]
    

class PCI_DATA_STRUCTURE(Structure):
    __pack__ = 1
    __fields__ =[
        ('Signature',c_uint32),        #PCIR
        ('VendorId',c_uint16),
        ('DeviceId',c_uint16),
        ('Reserved0',c_uint16),
        ('Length',c_uint16),
        ('Revision',c_uint8),
        ('ClassCode',ARRAY(c_uint8,3)),
        ('ImageLength',c_uint16),
        ('CodeRevision',c_uint16),
        ('CodeType',c_uint8),
        ('Indicator',c_uint8),
        ('Reserved1',c_uint16)
    ]
    
    
class PCI_3_0_DATA_STRUCTURE(Structure):
    __pack__ = 1
    __fields__ =[
        ('Signature',c_uint32),        #PCIR
        ('VendorId',c_uint16),
        ('DeviceId',c_uint16),
        ('DeviceListOffset',c_uint16),
        ('Length',c_uint16),
        ('Revision',c_uint8),
        ('ClassCode',ARRAY(c_uint8,3)),
        ('ImageLength',c_uint16),
        ('CodeRevision',c_uint16),
        ('CodeType',c_uint8),
        ('Indicator',c_uint8),
        ('MaxRuntimeImageLength',c_uint16),
        ('ConfigUtilityCodeHeaderOffset',c_uint16),
        ('DMTFCLPEntryPointOffset',c_uint16)
    ]