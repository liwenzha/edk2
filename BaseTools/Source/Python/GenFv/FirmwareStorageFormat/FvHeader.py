## @file
# This file is used to define the FV Header C Struct.
#
# Copyright (c) 2021-, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
from ast import Str
from struct import *
from ctypes import *
from FirmwareStorageFormat.Common import *


class EFI_GUID(Structure):
    _pack_ = 1
    _fields_ = [
        ('Data1',c_uint32),
        ('Data2',c_uint16),
        ('Data3',c_uint16),
        ('Data4',ARRAY(c_uint8,8))
    ]


class EFI_CAPSULE_HEADER(Structure):
    _pack_ = 1
    _fields_ = [
        ('CapsuleGuid',EFI_GUID),
        ('HeaderSize',c_uint32),
        ('Flags',c_uint32),
        ('CapsuleImageSize',c_uint32)
    ]


class EFI_FV_BLOCK_MAP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('NumBlocks',c_uint32),
        ('Length',c_uint32)
    ]


MAX_LONG_FILE_PATH = 500
MAX_NUMBER_OF_FV_BLOCKS = 100
MAX_NUMBER_OF_FILES_IN_FV = 1000
class FV_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseAddressSet',bool),
        ('BaseAddress',c_uint64),
        ('FvFileSystemGuid',EFI_GUID),
        ('FvFileSystemGuidSet',bool),
        ('FvNameGuid',EFI_GUID),
        ('FvNameGuidSet',bool),
        ('FvExtHeaderFile',ARRAY(c_char,MAX_LONG_FILE_PATH)),
        ('Size',c_uint64),
        ('FvAttributes',c_uint32),
        ('FvName',ARRAY(c_char,MAX_LONG_FILE_PATH)),
        ('FvBlocks',ARRAY(EFI_FV_BLOCK_MAP_ENTRY,MAX_NUMBER_OF_FV_BLOCKS)),
        ('FvFiles',ARRAY(ARRAY(c_char,MAX_NUMBER_OF_FILES_IN_FV),MAX_LONG_FILE_PATH)),
        ('SizeofFvFiles',ARRAY(c_uint32,MAX_NUMBER_OF_FILES_IN_FV)),
        ('IsPiFvImage',bool),
        ('ForceRebase',c_int8),
    ]
    
    
MAX_NUMBER_OF_FILES_IN_CAP = 1000
class CAP_INFO(Structure):
    _pack_ = 1
    _fields_ = [
        ('CapGuid',EFI_GUID),
        ('HeaderSize',c_uint32),
        ('Flags',c_uint32),
        ('CapName',ARRAY(c_char,MAX_LONG_FILE_PATH)),
        ('CapFiles',ARRAY(ARRAY(c_char,MAX_NUMBER_OF_FILES_IN_CAP),MAX_LONG_FILE_PATH)),
    ]


class MEMORY_FILE(Structure):
    _pack_ = 1
    _fields_ = [
        ('FileImage',c_char),
        ('Eof',c_char),
        ('CurrentFilePointer',c_char),
    ]


class EFI_FV_BLOCK_MAP_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('NumBlocks',            c_uint32),
        ('Length',               c_uint32),
    ]


class EFI_FIRMWARE_VOLUME_HEADER(Structure):
    _fields_ = [
        ('ZeroVector',           ARRAY(c_uint8, 16)),
        ('FileSystemGuid',       GUID),
        ('FvLength',             c_uint64),
        ('Signature',            c_uint32),
        ('Attributes',           c_uint32),
        ('HeaderLength',         c_uint16),
        ('Checksum',             c_uint16),
        ('ExtHeaderOffset',      c_uint16),
        ('Reserved',             c_uint8),
        ('Revision',             c_uint8),
        ('BlockMap',             ARRAY(EFI_FV_BLOCK_MAP_ENTRY, 1)),
        ]

def Refine_FV_Header(nums):
    class EFI_FIRMWARE_VOLUME_HEADER(Structure):
        _fields_ = [
            ('ZeroVector',           ARRAY(c_uint8, 16)),
            ('FileSystemGuid',       GUID),
            ('FvLength',             c_uint64),
            ('Signature',            c_uint32),
            ('Attributes',           c_uint32),
            ('HeaderLength',         c_uint16),
            ('Checksum',             c_uint16),
            ('ExtHeaderOffset',      c_uint16),
            ('Reserved',             c_uint8),
            ('Revision',             c_uint8),
            ('BlockMap',             ARRAY(EFI_FV_BLOCK_MAP_ENTRY, nums)),
            ]
    return EFI_FIRMWARE_VOLUME_HEADER

class EFI_FIRMWARE_VOLUME_EXT_HEADER(Structure):
    _fields_ = [
        ('FvName',               GUID),
        ('ExtHeaderSize',        c_uint32)
        ]

class EFI_FIRMWARE_VOLUME_EXT_ENTRY(Structure):
    _fields_ = [
        ('ExtEntrySize',         c_uint16),
        ('ExtEntryType',         c_uint16)
        ]

class EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE_0(Structure):
    _fields_ = [
        ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
        ('TypeMask',             c_uint32)
        ]

class EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE(Structure):
    _fields_ = [
        ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
        ('TypeMask',             c_uint32),
        ('Types',                ARRAY(GUID, 1))
        ]

def Refine_FV_EXT_ENTRY_OEM_TYPE_Header(nums: int) -> EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE:
    class EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE(Structure):
        _fields_ = [
            ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
            ('TypeMask',             c_uint32),
            ('Types',                ARRAY(GUID, nums))
        ]
    return EFI_FIRMWARE_VOLUME_EXT_ENTRY_OEM_TYPE(Structure)

class EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE_0(Structure):
    _fields_ = [
        ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
        ('FormatType',           GUID)
        ]

class EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE(Structure):
    _fields_ = [
        ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
        ('FormatType',           GUID),
        ('Data',                 ARRAY(c_uint8, 1))
        ]

def Refine_FV_EXT_ENTRY_GUID_TYPE_Header(nums: int) -> EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE:
    class EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE(Structure):
        _fields_ = [
            ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
            ('FormatType',           GUID),
            ('Data',                 ARRAY(c_uint8, nums))
        ]
    return EFI_FIRMWARE_VOLUME_EXT_ENTRY_GUID_TYPE(Structure)

class EFI_FIRMWARE_VOLUME_EXT_ENTRY_USED_SIZE_TYPE(Structure):
    _fields_ = [
        ('Hdr',                  EFI_FIRMWARE_VOLUME_EXT_ENTRY),
        ('UsedSize',             c_uint32)
        ]
