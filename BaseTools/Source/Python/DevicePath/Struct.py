## @file
# This file is used to define needed C Struct and functions.
#
# Copyright (c) 2021-, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
##


from struct import *
from ctypes import *
from Common import *


END_DEVICE_PATH_TYPE = 0x7f
END_ENTIRE_DEVICE_PATH_SUBTYPE = 0xFF
END_DEVICE_PATH_LENGTH = 0x01

MAX_UINT32 = c_uint32(0xFFFFFFFF)
MAX_DEVICE_PATH_NODE_COUNT = 1024

HARDWARE_DEVICE_PATH = 0x01
SIZE_64KB = 0x00010000
HW_PCI_DP = 0x01
HW_PCCARD_DP = 0x02
HW_VENDOR_DP = 0x04
HW_CONTROLLER_DP = 0x05
HW_BMC_DP = 0x06
ACPI_DP = 0x01

ACPI_DEVICE_PATH = 0x02
ACPI_EXTENDED_DP = 0x02
MESSAGING_DEVICE_PATH = 0x03
MSG_ATAPI_DP = 0x01
MSG_SCSI_DP = 0x02
MSG_FIBRECHANNEL_DP = 0x03
MSG_1394_DP = 0x04
MSG_USB_DP = 0x05
MSG_I2O_DP = 0x06
MSG_INFINIBAND_DP = 0x09
MSG_VENDOR_DP = 0x0a
MSG_SASEX_DP = 0x16
MSG_NVME_NAMESPACE_DP = 0x17
MSG_UFS_DP = 0x19
MSG_SD_DP = 0x1A
MSG_EMMC_DP = 0x1D
MSG_MAC_ADDR_DP = 0x0b
RFC_1700_UDP_PROTOCOL = 17
RFC_1700_TCP_PROTOCOL = 6
MSG_IPv4_DP = 0x0c
MSG_IPv6_DP = 0x0d
MSG_UART_DP = 0x0e
MSG_ISCSI_DP = 0x13
MSG_BLUETOOTH_DP = 0x1b


USB_CLASS_AUDIO = 1
USB_CLASS_CDCCONTROL = 2
USB_CLASS_HID = 3
USB_CLASS_IMAGE = 6
USB_CLASS_PRINTER = 7
USB_CLASS_MASS_STORAGE = 8
USB_CLASS_HUB = 9
USB_CLASS_CDCDATA = 10
USB_CLASS_SMART_CARD = 11
USB_CLASS_VIDEO = 14
USB_CLASS_DIAGNOSTIC = 220
USB_CLASS_WIRELESS = 224
USB_CLASS_RESERVE = 254
USB_SUBCLASS_FW_UPDATE = 1
USB_SUBCLASS_IRDA_BRIDGE = 2
USB_SUBCLASS_TEST = 3

MSG_USB_WWID_DP = 0x10
MSG_DEVICE_LOGICAL_UNIT_DP = 0x11
MSG_VLAN_DP = 0x14
MSG_DNS_DP = 0x1F
MAX_UINT16 = c_uint16(0xFFFF)
MSG_URI_DP = 0x18
MSG_WIFI_DP = 0x1C
MSG_BLUETOOTH_LE_DP = 0x1E
MEDIA_DEVICE_PATH = 0x04
MEDIA_HARDDRIVE_DP = 0x01
SIGNATURE_TYPE_MBR = 0x01
SIGNATURE_TYPE_GUID = 0x02
MEDIA_CDROM_DP = 0x02
MEDIA_VENDOR_DP = 0x03
MEDIA_PROTOCOL_DP = 0x05
MEDIA_PIWG_FW_VOL_DP = 0x07
MEDIA_PIWG_FW_FILE_DP = 0x06
MEDIA_RELATIVE_OFFSET_RANGE_DP = 0x08
MEDIA_RAM_DISK_DP = 0x09

BBS_BBS_DP = 0x01
BBS_TYPE_FLOPPY = 0x01
BBS_TYPE_HARDDRIVE = 0x02
BBS_TYPE_CDROM = 0x03
BBS_TYPE_PCMCIA = 0x04
BBS_TYPE_USB = 0x05
BBS_TYPE_EMBEDDED_NETWORK = 0x06
BBS_TYPE_BEV = 0x80
BBS_TYPE_UNKNOWN = 0xFF
BBS_DEVICE_PATH = 0x05
MSG_SATA_DP = 0x12
MEDIA_FILEPATH_DP = 0x04


BIT0 = 0x00000001
BIT1 = 0x00000002
BIT2 = 0x00000004
BIT3 = 0x00000008
BIT4 = 0x00000001


#############Structures
class EFI_GUID(Structure):
    _pack_ = 1
    _fields_ = [
        ('Data1',c_uint32),
        ('Data2',c_uint16),
        ('Data',c_uint16),
        ('Data4',ARRAY(c_uint8,8))
    ]


class EFI_DEVICE_PATH_PROTOCOL(Structure):
    _pack_ = 1
    _fields_ = [
        ('Type',c_uint8),
        ('SubType',c_uint8),
        ('Length',ARRAY(c_uint8,2))
    ]


mUefiDevicePathLibEndDevicePath = EFI_DEVICE_PATH_PROTOCOL({END_DEVICE_PATH_TYPE,END_ENTIRE_DEVICE_PATH_SUBTYPE,{END_DEVICE_PATH_LENGTH,0}})
DEVICE_PATH_FROM_TEXT = EFI_DEVICE_PATH_PROTOCOL()


class DEVICE_PATH_FROM_TEXT_TABLE(Structure):
    _pack_ = 1
    _fields_ =[
        ('DevicePathNodeText',c_char),
        ('Function',DEVICE_PATH_FROM_TEXT)
    ]
    

class PCI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Function',c_uint8),
        ('Device',c_uint8)
    ]


class PCCARD_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('FunctionNumber',c_uint8)
    ]


class MEMMAP_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('MemoryType',c_uint32),
        ('StartingAddress',c_uint64),
        ('EndingAddress',c_uint64),
    ]


class VENDOR_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Guid',EFI_GUID),
    ]


class CONTROLLER_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('ControllerNumber',c_uint32),
    ]
  
class BMC_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('ControlInterfaceTypelerNumber',c_uint8),
        ('BaseAddress',ARRAY(c_uint8,8))
    ]


class ACPI_HID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('HID',c_uint32),
        ('UID',c_uint32),
    ]


class ACPI_EXTENDED_HID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('HID',c_uint32),
        ('UID',c_uint32),
        ('CID',c_uint32),
    ]


class ACPI_ADR_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('ADR',c_uint32),
    ]



class ATAPI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('PrimarySecondary',c_uint8),
        ('SlaveMaster',c_uint8),
        ('Lun',c_uint16),
    ]

class SCSI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Pun',c_uint16),
        ('Lun',c_uint16),
    ]


class FIBRECHANNEL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved',c_uint32),
        ('WWN',c_uint64),
        ('Lun',c_uint64),
    ]

class F1394_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved',c_uint32),
        ('Guid',c_uint64),
    ]


class USB_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('ParentPortNumber',c_uint8),
        ('InterfaceNumber',c_uint8),
    ]


class I2O_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Tid',c_uint32),
    ]


class INFINIBAND_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('ResourceFlags',c_uint32),
        ('PortGid',ARRAY(c_uint8,16)),
        ('ServiceId',c_uint64),
        ('TargetPortId',c_uint64),
        ('DeviceId',c_uint64),
    ]


class UART_FLOW_CONTROL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Guid',EFI_GUID),
        ('FlowControlMap',c_uint32),
    ]


class SAS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Guid',EFI_GUID),
        ('Reserved',c_uint32),
        ('SasAddress',c_uint64),
        ('Lun',c_uint64),
        ('DeviceTopology',c_uint16),
        ('RelativeTargetPort',c_uint16),
    ]

class NVME_NAMESPACE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('NamespaceId',c_uint32),
        ('NamespaceUuid',c_uint64),
    ]


class UFS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Pun',c_uint8),
        ('Lun',c_uint8),
    ]


class SD_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('SlotNumber',c_uint8),
    ]


class EMMC_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('SlotNumber',c_uint8),
    ]


class EFI_MAC_ADDRESS(Structure):
    _pack_ = 1
    _fields_ =[
        ('Addr',ARRAY(c_uint8,32)),
    ]


class MAC_ADDR_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('MacAddress',EFI_MAC_ADDRESS),
        ('IfType',c_uint8),
    ]
    

class EFI_IPv4_ADDRESS(Structure):
    _pack_ = 1
    _fields_ =[
        ('Addr',ARRAY(c_uint8,4)),
    ]


class IPv4_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('LocalIpAddress',EFI_IPv4_ADDRESS),
        ('RemoteIpAddress',EFI_IPv4_ADDRESS),
        ('LocalPort',c_uint16),
        ('RemotePort',c_uint16),
        ('Protocol',c_uint16),
        ('StaticIpAddress',bool),
        ('GatewayIpAddress',EFI_IPv4_ADDRESS),
        ('SubnetMask',EFI_IPv4_ADDRESS),
    ]



class EFI_IPv6_ADDRESS(Structure):
    _pack_ = 1
    _fields_ =[
        ('Addr',ARRAY(c_uint8,16)),
    ]


    
class IPv6_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('LocalIpAddress',EFI_IPv6_ADDRESS),
        ('RemoteIpAddress',EFI_IPv6_ADDRESS),
        ('LocalPort',c_uint16),
        ('RemotePort',c_uint16),
        ('Protocol',c_uint16),
        ('IpAddressOrigin',c_uint8),
        ('PrefixLength',c_uint8),
        ('GatewayIpAddress',EFI_IPv6_ADDRESS),
    ]


class UART_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved',c_uint32),
        ('BaudRate',c_uint64),
        ('DataBits',c_uint8),
        ('Parity',c_uint8),
        ('StopBits',c_uint8),
    ]


class USB_CLASS_TEXT(Structure):
    _pack_ = 1
    _fields_ =[
        ('ClassExist',bool),
        ('Class',c_uint8),
        ('SubClassExist',bool),
        ('SubClass',c_uint8),
    ]


class USB_CLASS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('ClassExist',bool),
        ('VendorId',c_uint16),
        ('ProductId',c_uint16),
        ('DeviceClass',c_uint8),
        ('DeviceSubClass',c_uint8),
        ('DeviceProtocol',c_uint8),
    ]



class USB_WWID_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('ClassExist',bool),
        ('InterfaceNumber',c_uint16),
        ('VendorId',c_uint16),
        ('ProductId',c_uint16),
    ]


class DEVICE_LOGICAL_UNIT_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('ClassExist',bool),
        ('Lun',c_uint8),
    ]


class ISCSI_DEVICE_PATH_WITH_NAME(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('NetworkProtocol',c_uint16),
        ('LoginOption',c_uint16),
        ('Lun',c_uint64),
        ('TargetPortalGroupTag',c_uint16),
        ('TargetName',ARRAY(c_char,1)),
    ]


class VLAN_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('VlanId',c_uint16),
    ]


class EFI_IP_ADDRESS(Union):
    _pack_ = 1
    _fields_ =[
        ('Addr',ARRAY(c_uint32,4)),
        ('v4',EFI_IPv4_ADDRESS),
        ('v6',EFI_IPv6_ADDRESS),
    ]


class DNS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('IsIPv6',c_uint8),
        ('IsIPv6',ARRAY(EFI_IP_ADDRESS,100)),
    ]


class URI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Uri',ARRAY(c_char,100)),
    ]


class BLUETOOTH_ADDRESS(Structure):
    _pack_ = 1
    _fields_ =[
        ('Address',ARRAY(c_uint8,6)),
    ]


class BLUETOOTH_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('BD_ADDR',BLUETOOTH_ADDRESS),
    ]


class WIFI_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('SSId',ARRAY(c_uint8,32)),
    ]


class BLUETOOTH_LE_ADDRESS(Structure):
    _pack_ = 1
    _fields_ =[
        ('Address',ARRAY(c_uint8,6)),
        ('Type',c_uint8),
    ]


class BLUETOOTH_LE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('PartitionNumber',c_uint32),
        ('PartitionStart',c_uint64),
        ('PartitionSize',c_uint64),
        ('Signature',ARRAY(c_uint8,16)),
        ('MBRType',c_uint8),
        ('SignatureType',c_uint8),
    ]


class HARDDRIVE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Address',BLUETOOTH_LE_ADDRESS),
    ]


class CDROM_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('BootEntry',c_uint32),
        ('PartitionStart',c_uint64),
        ('PartitionSize',c_uint64),
    ]


class MEDIA_PROTOCOL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Protocol',EFI_GUID),
    ]


class MEDIA_FW_VOL_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('FvName',EFI_GUID),
    ]


class MEDIA_FW_VOL_FILEPATH_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('FvFileName',EFI_GUID),
    ]



class MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('Reserved',c_uint32),
        ('StartingOffset',c_uint64),
        ('EndingOffset',c_uint64),
    ]


class MEDIA_RAM_DISK_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('StartingAddr',ARRAY(c_uint32,2)),
        ('EndingAddr',ARRAY(c_uint32,2)),
        ('TypeGuid',EFI_GUID),
        ('Instance',c_uint16),
    ]


class BBS_BBS_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('DeviceType',c_uint16),
        ('StatusFlag',c_uint16),
        ('String',ARRAY(c_char,1)),
    ]

class SATA_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('HBAPortNumber',c_uint16),
        ('PortMultiplierPortNumber',c_uint16),
        ('Lun',c_uint16),
    ]


class FILEPATH_DEVICE_PATH(Structure):
    _pack_ = 1
    _fields_ =[
        ('Header',EFI_DEVICE_PATH_PROTOCOL),
        ('PathName',ARRAY(c_char,1)),
    ]

############Functions
def Strtoi(Str:str):
    for ch in Str:
        res = ch == 'x' or ch == 'X'
    if res:
        return int(Str,16)
    else:
        return int(Str)


def SplitStr(List:str,Separator:str):
    Str = List
    ReturnStr = Str
    
    if IS_NULL(Str) == 0:
        return ReturnStr
    
    #Find first occurrence of the separator
    for ch in Str:
        if IS_NULL(ch) == 0:
            if ch == Separator:
                break
            
    for ch in Str:
        if ch == Separator:
            Str = '\0'
    
    List = Str
    return ReturnStr
        

def GetNextParamStr(List:str) ->str:
    #The separator is comma
    return SplitStr(List,',')


def DevPathFromTextGenericPath(Type:int,TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    SubtypeStr = GetNextParamStr(TextDeviceNode)
    DataStr = GetNextParamStr (TextDeviceNode)
    
    if DataStr == None:
        DataLength = 0
    else:
        DataLength =  int(len(DataStr) / 2)
    
    Node = CreateDeviceNode(Type,c_uint8(SubtypeStr),sizeof (EFI_DEVICE_PATH_PROTOCOL) + DataLength)
    StrHexToBytes(DataStr, DataLength * 2, Node + 1, DataLength)
    return Node

#Converts a generic text device path node to device path structure.
def DevPathFromTextPath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    TypeStr = GetNextParamStr(TextDeviceNode)
    return DevPathFromTextGenericPath(TypeStr,TextDeviceNode)


def DevPathFromTextHardwarePath(TextDeviceNode:str):
    return DevPathFromTextGenericPath(HARDWARE_DEVICE_PATH, TextDeviceNode)

def WriteUnaligned(Buffer:int,Value:int):
    assert (Buffer != None)
    Buffer = Value
    return Buffer


def SetDevicePathNodeLength(Node:EFI_DEVICE_PATH_PROTOCOL,Length:int) -> c_uint16:
    assert(Node != None)
    assert(Length >= sizeof (EFI_DEVICE_PATH_PROTOCOL) and Length < SIZE_64KB )
    return WriteUnaligned(Node.Length[0],Length)
 
def UefiDevicePathLibCreateDeviceNode(NodeType:c_uint8,NodeSubType:c_int8,NodeLength:c_uint16) -> EFI_DEVICE_PATH_PROTOCOL:
    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    if NodeLength < sizeof(EFI_DEVICE_PATH_PROTOCOL):
        return None

    DevicePath.Type = NodeType
    DevicePath.SubType = NodeSubType
    SetDevicePathNodeLength(DevicePath, NodeLength)
    
    return DevicePath


def CreateDeviceNode(NodeType:c_uint8,NodeSubType:c_int8,NodeLength:c_uint16) ->EFI_DEVICE_PATH_PROTOCOL:
    return UefiDevicePathLibCreateDeviceNode(NodeType,NodeSubType,NodeLength)



def DevPathFromTextPci(TextDeviceNode:str):
    Pci = PCI_DEVICE_PATH()
    DeviceStr   = GetNextParamStr (TextDeviceNode)
    FunctionStr = GetNextParamStr (TextDeviceNode)
    Pci.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_PCI_DP,sizeof (PCI_DEVICE_PATH))
    Pci.Function = Strtoi(FunctionStr)
    Pci.Device = Strtoi(DeviceStr)
    return Pci
    
    
def DevPathFromTextPcCard(TextDeviceNode:str):
    #Pccard = PCCARD_DEVICE_PATH()
    Pccard = PCCARD_DEVICE_PATH()
    FunctionNumberStr = GetNextParamStr(TextDeviceNode)
    Pccard.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_PCCARD_DP,sizeof (PCCARD_DEVICE_PATH))
    Pccard.FunctionNumber = Strtoi(FunctionNumberStr)
    return Pccard


def DevPathFromTextMemoryMapped(TextDeviceNode:str):
    MemMap = MEMMAP_DEVICE_PATH()
    MemoryTypeStr = GetNextParamStr(TextDeviceNode)
    StartingAddressStr = GetNextParamStr(TextDeviceNode)
    EndingAddressStr = GetNextParamStr(TextDeviceNode)
    MemMap.MemoryType = Strtoi(MemoryTypeStr)
    MemMap.StartingAddress = Strtoi(StartingAddressStr)
    MemMap.EndingAddress = Strtoi(EndingAddressStr)
    return MemMap


def ConvertFromTextVendor(TextDeviceNode:str,Type:int,SubType:int) -> EFI_DEVICE_PATH_PROTOCOL:
    GuidStr = GetNextParamStr(TextDeviceNode)
    DataStr = GetNextParamStr(TextDeviceNode)
    Length = len(DataStr)

    #Two hex characters make up 1 buffer byte
    Length  = len((Length + 1) / 2)
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(Type,SubType,sizeof (VENDOR_DEVICE_PATH) + Length)
    Vendor.Guid = StrToGuid(GuidStr)
    #Vendor = DataStr.encode()
    return Vendor


def DevPathFromTextVenHw(TextDeviceNode:str):
    return ConvertFromTextVendor(TextDeviceNode,HARDWARE_DEVICE_PATH,HW_VENDOR_DP)


def DevPathFromTextCtrl(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    ControllerStr = GetNextParamStr(TextDeviceNode)
    Controller = CONTROLLER_DEVICE_PATH()
    Controller.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_CONTROLLER_DP,sizeof (CONTROLLER_DEVICE_PATH))
    Controller.ControllerNumber = Strtoi(ControllerStr)
    return Controller


def DevPathFromTextBmc(TextDeviceNode:str):
    BmcDp = BMC_DEVICE_PATH()
    InterfaceTypeStr = GetNextParamStr(TextDeviceNode)
    BaseAddressStr = GetNextParamStr(TextDeviceNode)
    BmcDp.Header = CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_BMC_DP,sizeof (BMC_DEVICE_PATH))
    BmcDp.InterfaceType = Strtoi(InterfaceTypeStr)
    WriteUnaligned(BmcDp.BaseAddress,Strtoi(BaseAddressStr))


def DevPathFromTextGenericPath(Type:c_uint8,TextDeviceNode:str):
    Node = EFI_DEVICE_PATH_PROTOCOL()
    SubtypeStr = GetNextParamStr(TextDeviceNode)
    DataStr = GetNextParamStr(TextDeviceNode)
    
    if DataStr == None:
        DataLength = 0
    else:
        DataLength = int(len (DataStr) / 2)
    Node = CreateDeviceNode(Type,Strtoi (SubtypeStr),sizeof (EFI_DEVICE_PATH_PROTOCOL) + DataLength)
    #Node = DataStr.encode()
    return Node


def DevPathFromTextAcpiPath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath (ACPI_DEVICE_PATH, TextDeviceNode)


def EisaIdFromText(Text:str) -> int:
    return (((int(Text[0] - 'A') + 1) & 0x1f) << 10) +\
                (((int(Text[1] - 'A') + 1) & 0x1f) <<  5)\
                    +(((int(Text[2] - 'A') + 1) & 0x1f) <<  0)\
                        +Strtoi (Text[3]) << 16


def DevPathFromTextAcpi(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    Acpi = ACPI_HID_DEVICE_PATH()
    HIDStr = GetNextParamStr (TextDeviceNode)
    UIDStr = GetNextParamStr (TextDeviceNode)
    Acpi.Header = CreateDeviceNode(ACPI_DEVICE_PATH,ACPI_DP,sizeof (ACPI_HID_DEVICE_PATH))

    Acpi.HID = EisaIdFromText (HIDStr)
    Acpi.UID = Strtoi(UIDStr)
    return Acpi


def EFI_PNP_ID(_Id):
    return (_Id) >> 16


def ConvertFromTextAcpi(TextDeviceNode:str,PnPId:c_uint32)-> EFI_DEVICE_PATH_PROTOCOL:
    Acpi = ACPI_HID_DEVICE_PATH()
    UIDStr = GetNextParamStr (TextDeviceNode)
    Acpi.Header = CreateDeviceNode(ACPI_DEVICE_PATH,ACPI_DP,sizeof (ACPI_HID_DEVICE_PATH))
    Acpi.HID = EFI_PNP_ID (PnPId)
    Acpi.UID = Strtoi (UIDStr)
    return Acpi

def DevPathFromTextPcieRoot(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0a08)


def DevPathFromTextPciRoot(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0a03)


def DevPathFromTextFloppy(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0604)


def DevPathFromTextKeyboard(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0301)


def DevPathFromTextSerial(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0501)


def DevPathFromTextParallelPort(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextAcpi (TextDeviceNode, 0x0401)


def DevPathFromTextAcpiEx(TextDeviceNode:str)-> EFI_DEVICE_PATH_PROTOCOL:
    AcpiEx = ACPI_EXTENDED_HID_DEVICE_PATH()
    HIDStr    = GetNextParamStr (TextDeviceNode)
    CIDStr    = GetNextParamStr (TextDeviceNode)
    UIDStr    = GetNextParamStr (TextDeviceNode)
    HIDSTRStr = GetNextParamStr (TextDeviceNode)
    CIDSTRStr = GetNextParamStr (TextDeviceNode)
    UIDSTRStr = GetNextParamStr (TextDeviceNode)

    Length = sizeof (ACPI_EXTENDED_HID_DEVICE_PATH) + len(HIDSTRStr) + 1
    Length = Length + len (UIDSTRStr) + 1
    Length = Length + len (CIDSTRStr) + 1
    AcpiEx.Header = CreateDeviceNode (ACPI_DEVICE_PATH,ACPI_EXTENDED_DP,Length)

    AcpiEx.HID = EisaIdFromText (HIDStr)
    AcpiEx.CID = EisaIdFromText (CIDStr)
    AcpiEx.UID = Strtoi (UIDStr)

    #AsciiStr = str(AcpiEx + sizeof (ACPI_EXTENDED_HID_DEVICE_PATH))
    #AsciiStr = HIDSTRStr
    return AcpiEx


def DevPathFromTextAcpiExp(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    AcpiEx = ACPI_EXTENDED_HID_DEVICE_PATH()
    HIDStr    = GetNextParamStr (TextDeviceNode)
    CIDStr    = GetNextParamStr (TextDeviceNode)
    UIDSTRStr = GetNextParamStr (TextDeviceNode)
    Length = sizeof (ACPI_EXTENDED_HID_DEVICE_PATH) + len (UIDSTRStr) + 3
    AcpiEx.Header = CreateDeviceNode(ACPI_DEVICE_PATH,ACPI_EXTENDED_DP,Length)

    AcpiEx.HID = EisaIdFromText (HIDStr)
    if CIDStr == '\0' or CIDStr == '0':
        AcpiEx.CID = 0
    else:
        AcpiEx.CID = EisaIdFromText (CIDStr)
    AcpiEx.UID = 0
    return AcpiEx


def DevPathFromTextAcpiAdr(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    AcpiAdr = ACPI_ADR_DEVICE_PATH()
    Index = 0
    while True:
        DisplayDeviceStr = GetNextParamStr (TextDeviceNode)
        if IS_NULL(DisplayDeviceStr):
            break
        
        if len(DisplayDeviceStr) == 0:
            break
        (AcpiAdr.ADR) = str(AcpiAdr.ADR)
        (AcpiAdr.ADR)[Index] = str(Strtoi (DisplayDeviceStr))
        Index += 1
    (AcpiAdr.ADR) = int(AcpiAdr.ADR)
    return AcpiAdr


def DevPathFromTextMsg(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath (MESSAGING_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextAta(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Atapi = ATAPI_DEVICE_PATH()
    Atapi.Header = CreateDeviceNode (MESSAGING_DEVICE_PATH,MSG_ATAPI_DP,sizeof (ATAPI_DEVICE_PATH))
    PrimarySecondaryStr = GetNextParamStr (TextDeviceNode)
    SlaveMasterStr      = GetNextParamStr (TextDeviceNode)
    LunStr              = GetNextParamStr (TextDeviceNode)
    if PrimarySecondaryStr == 'Primary':
        Atapi.PrimarySecondary = 0
    elif PrimarySecondaryStr == 'Secondary':
        Atapi.PrimarySecondary = 1
    else:
        Atapi.PrimarySecondary = Strtoi (PrimarySecondaryStr)

    if SlaveMasterStr == 'Master':
        Atapi.SlaveMasterStr = 0
    elif SlaveMasterStr == 'Slave':
        Atapi.SlaveMasterStr = 1
    else:
        Atapi.SlaveMasterStr = Strtoi (SlaveMasterStr)

    Atapi.Lun = Strtoi (LunStr)
    return Atapi

def DevPathFromTextScsi(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Scsi = SCSI_DEVICE_PATH()
    PunStr = GetNextParamStr (TextDeviceNode)
    LunStr = GetNextParamStr (TextDeviceNode)
    Scsi.Header = CreateDeviceNode (MESSAGING_DEVICE_PATH,MSG_SCSI_DP,sizeof (SCSI_DEVICE_PATH))
    Scsi.Pun = Strtoi (PunStr)
    Scsi.Lun = Strtoi (LunStr)
    return Scsi

def DevPathFromTextFibre(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Fibre = FIBRECHANNEL_DEVICE_PATH()
    WWNStr = GetNextParamStr (TextDeviceNode)
    LunStr = GetNextParamStr (TextDeviceNode)
    Fibre.Header = CreateDeviceNode (MESSAGING_DEVICE_PATH,MSG_FIBRECHANNEL_DP,sizeof (FIBRECHANNEL_DEVICE_PATH))

    Fibre.Reserved = 0
    Fibre.WWN =Strtoi (WWNStr)
    Fibre.Lun =Strtoi (LunStr)
    return Fibre

def DevPathFromTextFibreEx(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    FibreEx = FIBRECHANNEL_DEVICE_PATH()
    WWNStr = GetNextParamStr (TextDeviceNode)
    LunStr = GetNextParamStr (TextDeviceNode)
    FibreEx.Header = CreateDeviceNode (MESSAGING_DEVICE_PATH,MSG_FIBRECHANNEL_DP,sizeof (FIBRECHANNEL_DEVICE_PATH))

    FibreEx.Reserved = 0
    FibreEx.WWN =Strtoi (WWNStr)
    FibreEx.Lun =Strtoi (LunStr)
    return FibreEx


def DevPathFromText1394(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    F1394DevPath = F1394_DEVICE_PATH()
    GuidStr = GetNextParamStr (TextDeviceNode)
    F1394DevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_1394_DP,sizeof (F1394_DEVICE_PATH))
    F1394DevPath.Reserved = 0
    F1394DevPath.Guid = Strtoi(GuidStr)
    return F1394DevPath


def DevPathFromTextUsb(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Usb = USB_DEVICE_PATH()
    PortStr = GetNextParamStr (TextDeviceNode)
    InterfaceStr = GetNextParamStr (TextDeviceNode)
    Usb.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_USB_DP,sizeof (USB_DEVICE_PATH))
    Usb.ParentPortNumber = Strtoi (PortStr)
    Usb.InterfaceNumber = Strtoi (InterfaceStr)
    return Usb


def DevPathFromTextI2O(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    I2ODevPath = I2O_DEVICE_PATH()
    TIDStr = GetNextParamStr (TextDeviceNode)
    I2ODevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_I2O_DP,sizeof (I2O_DEVICE_PATH))
    I2ODevPath.Tid = Strtoi (TIDStr)
    return I2ODevPath


def DevPathFromTextInfiniband(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    InfiniBand = INFINIBAND_DEVICE_PATH()
    FlagsStr   = GetNextParamStr (TextDeviceNode)
    GuidStr    = GetNextParamStr (TextDeviceNode)
    SidStr     = GetNextParamStr (TextDeviceNode)
    TidStr     = GetNextParamStr (TextDeviceNode)
    DidStr     = GetNextParamStr (TextDeviceNode)
    InfiniBand.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_INFINIBAND_DP,sizeof (INFINIBAND_DEVICE_PATH))
    InfiniBand.ResourceFlags = Strtoi (FlagsStr)
    InfiniBand.PortGid = StrToGuid(GuidStr)
    InfiniBand.ServiceId = Strtoi(SidStr)
    InfiniBand.TargetPortId = Strtoi(TidStr)
    InfiniBand.DeviceId = Strtoi(DidStr)


def DevPathFromTextVenMsg(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextVendor(TextDeviceNode,MESSAGING_DEVICE_PATH,MSG_VENDOR_DP)

gEfiPcAnsiGuid = EFI_GUID
{0xe0c14753, 0xf9be, 0x11d2, {0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}}
def DevPathFromTextVenPcAnsi(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiPcAnsiGuid
    return Vendor

gEfiVT100Guid = EFI_GUID
{0xdfa66065, 0xb419, 0x11d3, {0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}}
def DevPathFromTextVenVt100(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVT100Guid
    return Vendor


gEfiVT100PlusGuid = EFI_GUID
{0x7baec70b, 0x57e0, 0x4c76, {0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43 }}
def DevPathFromTextVenVt100Plus(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVT100PlusGuid
    return Vendor

gEfiVTUTF8Guid = EFI_GUID
{0xad15a0d6, 0x8bec, 0x4acf, {0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88}}
def DevPathFromTextVenUtf8(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vendor = VENDOR_DEVICE_PATH()
    Vendor.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (VENDOR_DEVICE_PATH))
    Vendor.Guid = gEfiVTUTF8Guid
    return Vendor


gEfiUartDevicePathGuid = EFI_GUID
{0x37499a9d, 0x542f, 0x4c89, {0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4 }}
def DevPathFromTextUartFlowCtrl(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UartFlowControl = UART_FLOW_CONTROL_DEVICE_PATH()
    ValueStr = GetNextParamStr (TextDeviceNode)
    UartFlowControl.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (UART_FLOW_CONTROL_DEVICE_PATH))
    UartFlowControl.Guid = gEfiUartDevicePathGuid
    if ValueStr == 'XonXoff':
        UartFlowControl.FlowControlMap = 2
    elif ValueStr == 'Hardware':
        UartFlowControl.FlowControlMap = 1
    else:
        UartFlowControl.FlowControlMap = 0
    return UartFlowControl


gEfiSasDevicePathGuid = EFI_GUID
{0x37499a9d, 0x542f, 0x4c89, {0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4 }}
def DevPathFromTextSAS(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Sas = SAS_DEVICE_PATH()
    AddressStr  = GetNextParamStr (TextDeviceNode)
    LunStr      = GetNextParamStr (TextDeviceNode)
    RTPStr      = GetNextParamStr (TextDeviceNode)
    SASSATAStr  = GetNextParamStr (TextDeviceNode)
    LocationStr = GetNextParamStr (TextDeviceNode)
    ConnectStr  = GetNextParamStr (TextDeviceNode)
    DriveBayStr = GetNextParamStr (TextDeviceNode)
    ReservedStr = GetNextParamStr (TextDeviceNode)
    Sas.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (SAS_DEVICE_PATH))
    Sas.Guid = gEfiSasDevicePathGuid
    Sas.SasAddress = Strtoi(AddressStr)
    Sas.Lun = Strtoi(LunStr)
    Sas.RelativeTargetPort = Strtoi (RTPStr)

    if SASSATAStr == 'NoTopology':
        Info = 0x0
    elif SASSATAStr == 'SATA' or SASSATAStr == 'SAS':
        Uint16 = Strtoi (DriveBayStr)
        if Uint16 == 0:
            Info = 0x1
        else:
            Info = 0x2 | ((Uint16 - 1) << 8)
    
        if SASSATAStr == 'SATA':
            Info |= BIT4
        if LocationStr == 'External':
            Uint16 = 1
        elif LocationStr == 'Internal':
            Uint16 = 0
        else:
            Uint16 = Strtoi (LocationStr) & BIT0
        Info |= (Uint16 << 5)

        if ConnectStr == 'Expanded':
            Uint16 = 1
        elif ConnectStr == 'Direct':
            Uint16 = 0
        else:
            Uint16 = Strtoi (ConnectStr) & (BIT0 | BIT1)
        Info |= (Uint16 << 6)
    else:
        Info = Strtoi (SASSATAStr)
    Sas.DeviceTopology = Info
    Sas.Reserved = Strtoi (ReservedStr)
    return Sas


def DevPathFromTextSasEx(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    SasEx = SAS_DEVICE_PATH()
    AddressStr  = GetNextParamStr (TextDeviceNode)
    LunStr      = GetNextParamStr (TextDeviceNode)
    RTPStr      = GetNextParamStr (TextDeviceNode)
    SASSATAStr  = GetNextParamStr (TextDeviceNode)
    LocationStr = GetNextParamStr (TextDeviceNode)
    ConnectStr  = GetNextParamStr (TextDeviceNode)
    DriveBayStr = GetNextParamStr (TextDeviceNode)

    SasEx.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_SASEX_DP,sizeof (SAS_DEVICE_PATH))
    #SasEx.Guid = gEfiSasDevicePathGuid
    SasEx.SasAddress = Strtoi(AddressStr)
    SasEx.Lun = Strtoi(LunStr)
    SasEx.RelativeTargetPort = Strtoi (RTPStr)

    if SASSATAStr == 'NoTopology':
        Info = 0x0
    elif SASSATAStr == 'SATA' or SASSATAStr == 'SAS':
        Uint16 = Strtoi (DriveBayStr)
        if Uint16 == 0:
            Info = 0x1
        else:
            Info = 0x2 | ((Uint16 - 1) << 8)
    
        if SASSATAStr == 'SATA':
            Info |= BIT4

        if LocationStr == 'External':
            Uint16 = 1
        elif LocationStr == 'Internal':
            Uint16 = 0
        else:
            Uint16 = Strtoi (LocationStr) & BIT0
        Info |= (Uint16 << 5)

        if ConnectStr == 'Expanded':
            Uint16 = 1
        elif ConnectStr == 'Direct':
            Uint16 = 0
        else:
            Uint16 = Strtoi (ConnectStr) & (BIT0 | BIT1)
        Info |= (Uint16 << 6)
    else:
        Info = Strtoi (SASSATAStr)
    SasEx.DeviceTopology = Info
    return SasEx


def DevPathFromTextNVMe(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Nvme = NVME_NAMESPACE_DEVICE_PATH()
    NamespaceIdStr   = GetNextParamStr (TextDeviceNode)
    NamespaceUuidStr = GetNextParamStr (TextDeviceNode)
    Nvme.Header =  CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_NVME_NAMESPACE_DP,sizeof (NVME_NAMESPACE_DEVICE_PATH))
    Nvme.NamespaceId = Strtoi (NamespaceIdStr)
    Uuid = Nvme.NamespaceUuid
    Index = int(sizeof (Nvme.NamespaceUuid) / sizeof (c_uint8))
    while Index - 1 != 0:
        str(Uuid)[Index] = SplitStr (NamespaceUuidStr, '-')
    return Nvme


def DevPathFromTextUfs(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Ufs = UFS_DEVICE_PATH()
    PunStr = GetNextParamStr (TextDeviceNode)
    LunStr = GetNextParamStr (TextDeviceNode)
    Ufs.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_UFS_DP,sizeof (UFS_DEVICE_PATH))
    
    Ufs.Pun = Strtoi (PunStr)
    Ufs.Lun = Strtoi (LunStr)
    return Ufs


def DevPathFromTextSd(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Sd = SD_DEVICE_PATH()
    SlotNumberStr = GetNextParamStr (TextDeviceNode)
    Sd.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_SD_DP,sizeof (SD_DEVICE_PATH))
    Sd.SlotNumber = Strtoi (SlotNumberStr)
    return Sd


def DevPathFromTextEmmc(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Emmc = EMMC_DEVICE_PATH()
    SlotNumberStr = GetNextParamStr (TextDeviceNode)
    Emmc.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_EMMC_DP,sizeof (EMMC_DEVICE_PATH))
    Emmc.SlotNumber = Strtoi (SlotNumberStr)
    return Emmc

gEfiDebugPortProtocolGuid = EFI_GUID
{0xEBA4E8D2, 0x3858, 0x41EC, {0xA2, 0x81, 0x26, 0x47, 0xBA, 0x96, 0x60, 0xD0 }}
def DevPathFromTextDebugPort(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vend = VENDOR_DEVICE_PATH()
    Vend.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VENDOR_DP,sizeof (VENDOR_DEVICE_PATH))
    Vend.Guid = gEfiDebugPortProtocolGuid


def DevPathFromTextMAC(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    MACDevPath = MAC_ADDR_DEVICE_PATH()
    AddressStr    = GetNextParamStr (TextDeviceNode)
    IfTypeStr     = GetNextParamStr (TextDeviceNode)
    MACDevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_MAC_ADDR_DP,sizeof (MAC_ADDR_DEVICE_PATH))
    MACDevPath.IfType   =  Strtoi (IfTypeStr)
    Length = sizeof (EFI_MAC_ADDRESS)
    if MACDevPath.IfType == 0x01 or MACDevPath.IfType == 0x00:
        Length = 6
    return MACDevPath


def NetworkProtocolFromText(Text:str) -> int:
    if Text == 'UDP':
        return RFC_1700_UDP_PROTOCOL
    if Text == 'TCP':
        return RFC_1700_TCP_PROTOCOL
    return Strtoi (Text)

def DevPathFromTextIPv4(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    IPv4 = IPv4_DEVICE_PATH()
    RemoteIPStr           = GetNextParamStr (TextDeviceNode)
    ProtocolStr           = GetNextParamStr (TextDeviceNode)
    TypeStr               = GetNextParamStr (TextDeviceNode)
    LocalIPStr            = GetNextParamStr (TextDeviceNode)
    GatewayIPStr          = GetNextParamStr (TextDeviceNode)
    SubnetMaskStr         = GetNextParamStr (TextDeviceNode)
    IPv4.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_IPv4_DP,sizeof (IPv4_DEVICE_PATH))

    #StrToIpv4Address (RemoteIPStr, NULL, &IPv4->RemoteIpAddress, NULL)
    IPv4.RemoteIpAddress = Strtoi(RemoteIPStr)
    IPv4.Protocol = NetworkProtocolFromText (ProtocolStr)
    if TypeStr == 'Static':
        IPv4.StaticIpAddress = True
    else:
        IPv4.StaticIpAddress = False
    
    #StrToIpv4Address (LocalIPStr, NULL, &IPv4->LocalIpAddress, NULL)
    IPv4.LocalIpAddress = Strtoi(LocalIPStr)
    if IS_NULL(GatewayIPStr) ==0 and IS_NULL(SubnetMaskStr) ==0:
        #StrToIpv4Address (GatewayIPStr,  NULL, &IPv4->GatewayIpAddress, NULL)
        #StrToIpv4Address (SubnetMaskStr, NULL, &IPv4->SubnetMask,       NULL)
        IPv4.GatewayIpAddress = Strtoi(GatewayIPStr)
        IPv4.SubnetMask = Strtoi(SubnetMaskStr)
    else:
        #ZeroMem (&IPv4->GatewayIpAddress, sizeof (IPv4->GatewayIpAddress));
        #ZeroMem (&IPv4->GatewayIpAddress, sizeof (IPv4->SubnetMask));
        IPv4.GatewayIpAddress = '0.0.0.0.'
        IPv4.GatewayIpAddress = '0.0.0.0'
    IPv4.LocalPort       = 0
    IPv4.RemotePort      = 0
    return IPv4



def DevPathFromTextIPv6(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    IPv6 = IPv6_DEVICE_PATH()
    RemoteIPStr           = GetNextParamStr (TextDeviceNode)
    ProtocolStr           = GetNextParamStr (TextDeviceNode)
    TypeStr               = GetNextParamStr (TextDeviceNode)
    LocalIPStr            = GetNextParamStr (TextDeviceNode)
    PrefixLengthStr       = GetNextParamStr (TextDeviceNode)
    GatewayIPStr          = GetNextParamStr (TextDeviceNode)
    IPv6.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_IPv6_DP,sizeof (IPv6_DEVICE_PATH))

    #StrToIpv6Address (RemoteIPStr, NULL, &IPv6->RemoteIpAddress, NULL);
    IPv6.RemoteIpAddress = Strtoi(RemoteIPStr)
    IPv6.Protocol = NetworkProtocolFromText (ProtocolStr)
    if TypeStr == 'Static':
        IPv6.IpAddressOrigin = 0
    elif TypeStr == 'StatelessAutoConfigure':
        IPv6.IpAddressOrigin = 1
    else:
        IPv6.IpAddressOrigin = 2
    #StrToIpv6Address (LocalIPStr, NULL, &IPv6->LocalIpAddress, NULL);
    IPv6.LocalIpAddress = Strtoi(LocalIPStr)
    if IS_NULL(GatewayIPStr) ==0 and IS_NULL(PrefixLengthStr) ==0:
        #StrToIpv6Address (GatewayIPStr, NULL, &IPv6->GatewayIpAddress, NULL);
        IPv6.GatewayIpAddress = Strtoi(GatewayIPStr)
        IPv6.PrefixLength = Strtoi (PrefixLengthStr)
    else:
        IPv6.GatewayIpAddress = '0.0.0.0.0.0'
        IPv6 = PrefixLength = 0
    IPv6.LocalPort       = 0
    IPv6.RemotePort      = 0
    return IPv6

    
def DevPathFromTextUart(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Uart = UART_DEVICE_PATH()
    BaudStr         = GetNextParamStr (TextDeviceNode)
    DataBitsStr     = GetNextParamStr (TextDeviceNode)
    ParityStr       = GetNextParamStr (TextDeviceNode)
    StopBitsStr     = GetNextParamStr (TextDeviceNode)
    Uart.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_UART_DP,sizeof (UART_DEVICE_PATH))
    if BaudStr == 'DEFAULT':
        Uart.BaudRate = 115200
    else:
        Strtoi(BaudStr, Uart.BaudRate)
    Uart.DataBits = 8 if DataBitsStr == 'DEFAULT' else Strtoi (DataBitsStr)
    if ParityStr == 'D':
        Uart.Parity = 0
    elif ParityStr == 'N':
        Uart.Parity = 1
    elif ParityStr == 'E':
        Uart.Parity = 2
    elif ParityStr == 'O':
        Uart.Parity = 3
    elif ParityStr == 'M':
        Uart.Parity = 4
    elif ParityStr == 'S':
        Uart.Parity = 5
    else:
        Uart.Parity = Strtoi (ParityStr)
    if StopBitsStr == 'D':
        Uart.StopBits = 0
    elif StopBitsStr == '1':
        Uart.StopBits = 1
    elif StopBitsStr == '1.5':
        Uart.StopBits = 2
    else:
        Uart.StopBits = 3

    return Uart

def ConvertFromTextUsbClass(TextDeviceNode:str,UsbClassText:USB_CLASS_TEXT):
    UsbClass= USB_CLASS_DEVICE_PATH()
    VIDStr      = GetNextParamStr (TextDeviceNode)
    PIDStr      = GetNextParamStr (TextDeviceNode)
    if UsbClassText.ClassExist:
        ClassStr = GetNextParamStr (TextDeviceNode)
        if ClassStr == '\0':
            UsbClass.DeviceClass = 0xFF
        else:
            UsbClass.DeviceClass =  Strtoi (ClassStr)
    else:
        UsbClass.DeviceClass = UsbClassText.Class

    if UsbClassText.SubClassExist:
        SubClassStr = GetNextParamStr (TextDeviceNode)
        if SubClassStr == '\0':
            UsbClass.DeviceClass = 0xFF
        else:
            UsbClass.DeviceClass =  Strtoi (SubClassStr)
    else:
        UsbClass.DeviceSubClass = UsbClassText.SubClass

    ProtocolStr = GetNextParamStr (TextDeviceNode)
    if PIDStr == '\0':
        UsbClass.ProductId       = 0xFFFF
    else:
        UsbClass.ProductId       =  Strtoi (PIDStr)
    if ProtocolStr == '\0':
        UsbClass.DeviceProtocol  = 0xFF
    else:
        UsbClass.DeviceProtocol  =  Strtoi (ProtocolStr)
    return UsbClass




def DevPathFromTextUsbClass(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = True
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbAudio(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_AUDIO
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbCDCControl(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_CDCCONTROL
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbHID(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_HID
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbImage(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_IMAGE
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)



def DevPathFromTextUsbPrinter(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_PRINTER
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)



def DevPathFromTextUsbMassStorage(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_MASS_STORAGE
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbHub(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_HUB
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbCDCData(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_CDCDATA
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)



def DevPathFromTextUsbSmartCard(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_SMART_CARD
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbVideo(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_VIDEO
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbDiagnostic(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_DIAGNOSTIC
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbWireless(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_WIRELESS
    UsbClassText.SubClassExist = True
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbDeviceFirmwareUpdate(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass      = USB_SUBCLASS_FW_UPDATE
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbIrdaBridge(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass      = USB_SUBCLASS_IRDA_BRIDGE
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbTestAndMeasurement(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbClassText = USB_CLASS_TEXT()
    UsbClassText.ClassExist    = False
    UsbClassText.Class         = USB_CLASS_RESERVE
    UsbClassText.SubClassExist = False
    UsbClassText.SubClass      = USB_SUBCLASS_TEST
    return ConvertFromTextUsbClass (TextDeviceNode, UsbClassText)


def DevPathFromTextUsbWwid(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    UsbWwid = USB_WWID_DEVICE_PATH()
    VIDStr                   = GetNextParamStr (TextDeviceNode)
    PIDStr                   = GetNextParamStr (TextDeviceNode)
    InterfaceNumStr          = GetNextParamStr (TextDeviceNode)
    SerialNumberStr          = GetNextParamStr (TextDeviceNode)
    SerialNumberStrLen = len (SerialNumberStr)
    if SerialNumberStrLen >= 2 and SerialNumberStr[0] == '\"' and SerialNumberStr[SerialNumberStrLen - 1] == '\"':
        Index = SerialNumberStrLen - 1
        SerialNumberStr[Index] = '\0'
        Index += 1
        SerialNumberStrLen -= 2
    UsbWwid = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_USB_WWID_DP,sizeof (USB_WWID_DEVICE_PATH) + SerialNumberStrLen * sizeof (c_ushort))
    UsbWwid.VendorId        =  Strtoi (VIDStr)
    UsbWwid.ProductId       =  Strtoi (PIDStr)
    UsbWwid.InterfaceNumber =  Strtoi (InterfaceNumStr)
    return UsbWwid


def DevPathFromTextUnit(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    LogicalUnit = DEVICE_LOGICAL_UNIT_DEVICE_PATH()
    LunStr      = GetNextParamStr (TextDeviceNode)
    LogicalUnit.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_DEVICE_LOGICAL_UNIT_DP,sizeof (DEVICE_LOGICAL_UNIT_DEVICE_PATH))
    LogicalUnit.Lun  = Strtoi (LunStr)
    return LogicalUnit


def DevPathFromTextiSCSI(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    ISCSIDevPath = ISCSI_DEVICE_PATH_WITH_NAME()
    NameStr           = GetNextParamStr (TextDeviceNode)
    PortalGroupStr    = GetNextParamStr (TextDeviceNode)
    LunStr            = GetNextParamStr (TextDeviceNode)
    HeaderDigestStr   = GetNextParamStr (TextDeviceNode)
    DataDigestStr     = GetNextParamStr (TextDeviceNode)
    AuthenticationStr = GetNextParamStr (TextDeviceNode)
    ProtocolStr       = GetNextParamStr (TextDeviceNode)
    ISCSIDevPath.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_ISCSI_DP,sizeof (ISCSI_DEVICE_PATH_WITH_NAME) + len (NameStr))
    ISCSIDevPath.TargetName  = NameStr
    ISCSIDevPath.TargetPortalGroupTag = Strtoi (PortalGroupStr)
    ISCSIDevPath.Lun = LunStr
    Options = 0x0000
    if HeaderDigestStr == 'CRC32C':
        Options |= 0x0002
    if DataDigestStr == 'CRC32C':
        Options |= 0x0008
    if AuthenticationStr == 'None':
        Options |= 0x0800
    if AuthenticationStr == 'CHAP_UNI':
        Options |= 0x1000
    ISCSIDevPath.LoginOption = Options


    if IS_NULL(ProtocolStr) or ProtocolStr == 'TCP':
        ISCSIDevPath.NetworkProtocol = 0
    else:
        ISCSIDevPath.NetworkProtocol = 1
    return ISCSIDevPath


def DevPathFromTextVlan(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Vlan = VLAN_DEVICE_PATH()
    VlanStr = GetNextParamStr (TextDeviceNode)
    Vlan.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_VLAN_DP,sizeof (VLAN_DEVICE_PATH))
    Vlan.VlanId = Strtoi (VlanStr)
    return Vlan


def DevPathFromTextDns(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    DnsDeviceNode = DNS_DEVICE_PATH()
    DeviceNodeStr = UefiDevicePathLibStrDuplicate (TextDeviceNode)
    if DeviceNodeStr == None:
        return None
    DeviceNodeStrPtr = DeviceNodeStr
    DnsServerIpCount = 0
    for ch in DeviceNodeStrPtr:
        if DeviceNodeStrPtr != None and ch != '\0':
            GetNextParamStr (DeviceNodeStrPtr)
            DnsServerIpCount += 1
    if DnsServerIpCount == 0:
        return None
    DnsDeviceNodeLength = sizeof (EFI_DEVICE_PATH_PROTOCOL) + sizeof + DnsServerIpCount * sizeof (EFI_IP_ADDRESS)
    DnsDeviceNode = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_DNS_DP,DnsDeviceNodeLength)
    if DnsDeviceNode == None:
        return None
    DeviceNodeStrPtr = TextDeviceNode
    for ch in DeviceNodeStrPtr:
        while IS_NULL(ch):
            if ch == '.':
                DnsDeviceNode.IsIPv6 = 0x00
                break
        if ch == ':':
            DnsDeviceNode.IsIPv6 = 0x01
            break
    
    for DnsServerIpIndex in range(DnsServerIpIndex):
        DnsServerIp = GetNextParamStr (TextDeviceNode)
        if DnsDeviceNode.IsIPv6 == 0x00:
            DnsDeviceNode.DnsServerIp[DnsServerIpIndex].v4 = DnsServerIp
        else:
            DnsDeviceNode.DnsServerIp[DnsServerIpIndex].v6 = DnsServerIp
    return DnsDeviceNode


def DevPathFromTextUri(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Uri = URI_DEVICE_PATH()
    UriStr = GetNextParamStr (TextDeviceNode)
    UriLength = len (UriStr, MAX_UINT16 - sizeof (URI_DEVICE_PATH))
    Uri.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_URI_DP,sizeof (URI_DEVICE_PATH) + UriLength)
    while UriLength - 1 != 0:
        Uri.Uri[UriLength] = UriStr[UriLength]
        UriLength -= 1
    return Uri


def DevPathFromTextBluetooth(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    BluetoothDp = BLUETOOTH_DEVICE_PATH()
    BluetoothStr = GetNextParamStr (TextDeviceNode)
    BluetoothDp.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_BLUETOOTH_DP,sizeof (BLUETOOTH_DEVICE_PATH))
    BluetoothDp.BD_ADDR.Address = BluetoothStr.encode()
    return BluetoothDp


def DevPathFromTextWiFi(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    WiFiDp = WIFI_DEVICE_PATH()
    SSIdStr = GetNextParamStr (TextDeviceNode)
    WiFiDp.header =  CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_WIFI_DP,sizeof (WIFI_DEVICE_PATH))
    if SSIdStr != None:
        DataLen = len (SSIdStr)
        if len (SSIdStr) > 32:
            SSIdStr[32] = '\0'
            DataLen     = 32
        SSIdStr = SSIdStr.encode()
        for i in range(DataLen):
            WiFiDp.SSId[i] = SSIdStr[i]
    return WiFiDp


def DevPathFromTextBluetoothLE(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    BluetoothLeDp = BLUETOOTH_LE_DEVICE_PATH()
    BluetoothLeAddrStr     = GetNextParamStr (TextDeviceNode)
    BluetoothLeAddrTypeStr = GetNextParamStr (TextDeviceNode)
    BluetoothLeDp.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_BLUETOOTH_LE_DP,sizeof (BLUETOOTH_LE_DEVICE_PATH))
    BluetoothLeDp.Address.Type = Strtoi (BluetoothLeAddrTypeStr)
    BluetoothLeAddrStr = BluetoothLeAddrStr.encode()
    for i in range(len(BluetoothLeAddrStr)):
        BluetoothLeDp.Address.Address[i] = BluetoothLeAddrStr[i]
    return BluetoothLeDp


def DevPathFromTextMediaPath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath (MEDIA_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextHD(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Hd = HARDDRIVE_DEVICE_PATH()
    PartitionStr        = GetNextParamStr (TextDeviceNode)
    TypeStr             = GetNextParamStr (TextDeviceNode)
    SignatureStr        = GetNextParamStr (TextDeviceNode)
    StartStr            = GetNextParamStr (TextDeviceNode)
    SizeStr             = GetNextParamStr (TextDeviceNode)
    Hd.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_HARDDRIVE_DP,sizeof (HARDDRIVE_DEVICE_PATH))
    Hd.PartitionNumber = Strtoi (PartitionStr)
    Hd.Signature = [0]*16
    Hd.MBRType = 0
    if TypeStr == 'MBR':
        Hd.SignatureType = SIGNATURE_TYPE_MBR
        Hd.MBRType       = 0x01
        Signature32 = Strtoi (SignatureStr)
        for i in range(len(SignatureStr)):
            Hd.Signature[i] = Signature32[i]
    elif TypeStr == 'GPT':
        Hd.SignatureType = SIGNATURE_TYPE_GUID
        Hd.MBRType       = 0x02
        Hd.Signature = StrToGuid(SignatureStr)
    else:
        Hd.SignatureType = Strtoi (TypeStr)
    Hd.PartitionStart = Strtoi(StartStr)
    Hd.PartitionSize = Strtoi(SizeStr)
    return Hd


def DevPathFromTextCDROM(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    CDROMDevPath = CDROM_DEVICE_PATH()
    EntryStr              = GetNextParamStr (TextDeviceNode)
    StartStr              = GetNextParamStr (TextDeviceNode)
    SizeStr               = GetNextParamStr (TextDeviceNode)
    CDROMDevPath.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_CDROM_DP,sizeof (CDROM_DEVICE_PATH))
    CDROMDevPath.BootEntry = Strtoi (EntryStr)
    CDROMDevPath.PartitionStart = Strtoi(StartStr)
    CDROMDevPath.PartitionSize = Strtoi(SizeStr)


def DevPathFromTextVenMedia(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return ConvertFromTextVendor(TextDeviceNode,MEDIA_DEVICE_PATH,MEDIA_VENDOR_DP)


def DevPathFromTextMedia(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Media = MEDIA_PROTOCOL_DEVICE_PATH()
    GuidStr = GetNextParamStr (TextDeviceNode)
    Media.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_PROTOCOL_DP,sizeof (MEDIA_PROTOCOL_DEVICE_PATH))
    Media.Protocol = StrToGuid(GuidStr)
    return Media


def DevPathFromTextFv(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Fv = MEDIA_FW_VOL_DEVICE_PATH()
    GuidStr = GetNextParamStr (TextDeviceNode)
    Fv.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_PIWG_FW_VOL_DP,sizeof (MEDIA_FW_VOL_DEVICE_PATH))
    Fv.FvName = StrToGuid(GuidStr)
    return Fv


def DevPathFromTextFvFile(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    FvFile = MEDIA_FW_VOL_FILEPATH_DEVICE_PATH()
    GuidStr = GetNextParamStr (TextDeviceNode)
    FvFile.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_PIWG_FW_FILE_DP,sizeof (MEDIA_FW_VOL_DEVICE_PATH))
    FvFile.FvName = StrToGuid(GuidStr)
    return FvFile


def DevPathFromTextRelativeOffsetRange(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Offset = MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH()
    StartingOffsetStr = GetNextParamStr (TextDeviceNode)
    EndingOffsetStr   = GetNextParamStr (TextDeviceNode)
    Offset.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RELATIVE_OFFSET_RANGE_DP,sizeof (MEDIA_RELATIVE_OFFSET_RANGE_DEVICE_PATH))
    Offset.StartingOffset = Strtoi(StartingOffsetStr)
    Offset.EndingOffset = Strtoi(EndingOffsetStr)


def DevPathFromTextRamDisk(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr = GetNextParamStr (TextDeviceNode)
    EndingAddrStr   = GetNextParamStr (TextDeviceNode)
    InstanceStr     = GetNextParamStr (TextDeviceNode)
    TypeGuidStr     = GetNextParamStr (TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RAM_DISK_DP,sizeof (MEDIA_RAM_DISK_DEVICE_PATH))
    StartingAddrStr = Strtoi(StartingAddrStr)
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = StrToGuid (TypeGuidStr)
    return RamDisk


gEfiVirtualDiskGuid = EFI_GUID
{0x77AB535A, 0x45FC, 0x624B, {0x55, 0x60, 0xF7, 0xB2, 0x81, 0xD1, 0xF9, 0x6E }}
def DevPathFromTextVirtualDisk(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr = GetNextParamStr (TextDeviceNode)
    EndingAddrStr   = GetNextParamStr (TextDeviceNode)
    InstanceStr     = GetNextParamStr (TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RAM_DISK_DP,sizeof (MEDIA_RAM_DISK_DEVICE_PATH))
    StartingAddrStr = Strtoi(StartingAddrStr)
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = gEfiVirtualDiskGuid
    return RamDisk


gEfiVirtualCdGuid = EFI_GUID
{0x3D5ABD30, 0x4175, 0x87CE, {0x6D, 0x64, 0xD2, 0xAD, 0xE5, 0x23, 0xC4, 0xBB }}
def DevPathFromTextVirtualCd(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr = GetNextParamStr (TextDeviceNode)
    EndingAddrStr   = GetNextParamStr (TextDeviceNode)
    InstanceStr     = GetNextParamStr (TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RAM_DISK_DP,sizeof (MEDIA_RAM_DISK_DEVICE_PATH))
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = gEfiVirtualCdGuid
    return RamDisk


gEfiPersistentVirtualDiskGuid = EFI_GUID
{0x5CEA02C9, 0x4D07, 0x69D3, {0x26, 0x9F ,0x44, 0x96, 0xFB, 0xE0, 0x96, 0xF9 }}
def DevPathFromTextPersistentVirtualDisk(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr = GetNextParamStr (TextDeviceNode)
    EndingAddrStr   = GetNextParamStr (TextDeviceNode)
    InstanceStr     = GetNextParamStr (TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RAM_DISK_DP,sizeof (MEDIA_RAM_DISK_DEVICE_PATH))
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = gEfiPersistentVirtualDiskGuid
    return RamDisk


gEfiPersistentVirtualCdGuid = EFI_GUID
{ 0x08018188, 0x42CD, 0xBB48, {0x10, 0x0F, 0x53, 0x87, 0xD5, 0x3D, 0xED, 0x3D }}
def DevPathFromTextPersistentVirtualCd(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    RamDisk = MEDIA_RAM_DISK_DEVICE_PATH()
    StartingAddrStr = GetNextParamStr (TextDeviceNode)
    EndingAddrStr   = GetNextParamStr (TextDeviceNode)
    InstanceStr     = GetNextParamStr (TextDeviceNode)
    RamDisk.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_RAM_DISK_DP,sizeof (MEDIA_RAM_DISK_DEVICE_PATH))
    RamDisk.StartingAddr = StartingAddrStr
    EndingAddrStr = Strtoi(EndingAddrStr)
    RamDisk.Instance = EndingAddrStr
    RamDisk.TypeGuid = gEfiPersistentVirtualCdGuid
    return RamDisk


def DevPathFromTextBbsPath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    return DevPathFromTextGenericPath (BBS_DEVICE_PATH, TextDeviceNode)


def DevPathFromTextBBS(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Bbs = BBS_BBS_DEVICE_PATH()
    TypeStr   = GetNextParamStr (TextDeviceNode)
    IdStr     = GetNextParamStr (TextDeviceNode)
    FlagsStr  = GetNextParamStr (TextDeviceNode)
    Bbs.Header = CreateDeviceNode(BBS_DEVICE_PATH,BBS_BBS_DP,sizeof (BBS_BBS_DEVICE_PATH) + len(IdStr))
    if TypeStr == 'Floppy':
        Bbs.DeviceType = BBS_TYPE_FLOPPY
    elif TypeStr == 'HD':
        Bbs.DeviceType = BBS_TYPE_HARDDRIVE
    elif TypeStr == 'CDROM':
        Bbs.DeviceType = BBS_TYPE_CDROM
    elif TypeStr == 'PCMCIA':
        Bbs.DeviceType = BBS_TYPE_PCMCIA
    elif TypeStr == 'USB':
        Bbs.DeviceType = BBS_TYPE_USB
    elif TypeStr == 'Network':
        Bbs.DeviceType = BBS_TYPE_EMBEDDED_NETWORK
    else:
        Bbs.DeviceType = Strtoi (TypeStr)
    Bbs.String[0] = IdStr
    Bbs.StatusFlag = Strtoi (TypeStr)
    return Bbs


def DevPathFromTextSata(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    Sata = SATA_DEVICE_PATH()
    Param1 = GetNextParamStr (TextDeviceNode)
    Param2 = GetNextParamStr (TextDeviceNode)
    Param3 = GetNextParamStr (TextDeviceNode)
    Sata.Header = CreateDeviceNode(MESSAGING_DEVICE_PATH,MSG_SATA_DP,sizeof (SATA_DEVICE_PATH))
    Sata.HBAPortNumber =  Strtoi (Param1)
    if Param2 == '\0':
        Sata.PortMultiplierPortNumber = 0xFFFF
    else:
        Sata.PortMultiplierPortNumber =  Strtoi (Param2)
    Sata.Lun = Strtoi (Param3)
    return Sata









mUefiDevicePathLibDevPathFromTextTable = DEVICE_PATH_FROM_TEXT_TABLE
{
    {"Path",DevPathFromTextPath},
    {"HardwarePath",DevPathFromTextHardwarePath},
    {"Pci",DevPathFromTextPci},
    {"PcCard",DevPathFromTextPcCard},
    {"MemoryMapped",DevPathFromTextMemoryMapped},
    {"VenHw",DevPathFromTextVenHw},
    {"Ctrl",DevPathFromTextCtrl},
    {"BMC",DevPathFromTextBmc},
    
    {"AcpiPath",DevPathFromTextAcpiPath},
    {"Acpi",DevPathFromTextAcpi},
    {"PciRoot",DevPathFromTextPciRoot},
    {"PcieRoot",DevPathFromTextPcieRoot},
    {"Floppy",DevPathFromTextFloppy},
    {"Keyboard",DevPathFromTextKeyboard},
    {"Serial",DevPathFromTextSerial},
    {"ParallelPort",DevPathFromTextParallelPort},
    {"AcpiEx",DevPathFromTextAcpiEx},
    {"AcpiExp",DevPathFromTextAcpiExp},
    {"AcpiAdr",DevPathFromTextAcpiAdr},
    
    {"Msg",                     DevPathFromTextMsg                     },
    {"Ata",                     DevPathFromTextAta                     },
    {"Scsi",                    DevPathFromTextScsi                    },
    {"Fibre",                   DevPathFromTextFibre                   },
    {"FibreEx",                 DevPathFromTextFibreEx                 },
    {"I1394",                   DevPathFromText1394                    },
    {"USB",                     DevPathFromTextUsb                     },
    {"I2O",                     DevPathFromTextI2O                     },
    {"Infiniband",              DevPathFromTextInfiniband              },
    {"VenMsg",                  DevPathFromTextVenMsg                  },
    {"VenPcAnsi",               DevPathFromTextVenPcAnsi               },
    {"VenVt100",                DevPathFromTextVenVt100                },
    {"VenVt100Plus",            DevPathFromTextVenVt100Plus            },
    {"VenUtf8",                 DevPathFromTextVenUtf8                 },
    {"UartFlowCtrl",            DevPathFromTextUartFlowCtrl            },
    {"SAS",                     DevPathFromTextSAS                     },
    {"SasEx",                   DevPathFromTextSasEx                   },
    {"NVMe",                    DevPathFromTextNVMe                    },
    {"UFS",                     DevPathFromTextUfs                     },
    {"SD",                      DevPathFromTextSd                      },
    {"eMMC",                    DevPathFromTextEmmc                    },
    {"DebugPort",               DevPathFromTextDebugPort               },
    {"MAC",                     DevPathFromTextMAC                     },
  
    {"IPv4",                    DevPathFromTextIPv4                    },
    {"IPv6",                    DevPathFromTextIPv6                    },
    {"Uart",                    DevPathFromTextUart                    },
    {"UsbClass",                DevPathFromTextUsbClass                },
    {"UsbAudio",                DevPathFromTextUsbAudio                },
    {"UsbCDCControl",           DevPathFromTextUsbCDCControl           },
    {"UsbHID",                  DevPathFromTextUsbHID                  },
    {"UsbImage",                DevPathFromTextUsbImage                },
    {"UsbPrinter",              DevPathFromTextUsbPrinter              },
    {"UsbMassStorage",          DevPathFromTextUsbMassStorage          },
    {"UsbHub",                  DevPathFromTextUsbHub                  },
    {"UsbCDCData",              DevPathFromTextUsbCDCData              },
    {"UsbSmartCard",            DevPathFromTextUsbSmartCard            },
    {"UsbVideo",                DevPathFromTextUsbVideo                },
    {"UsbDiagnostic",           DevPathFromTextUsbDiagnostic           },
    {"UsbWireless",             DevPathFromTextUsbWireless             },
    {"UsbDeviceFirmwareUpdate", DevPathFromTextUsbDeviceFirmwareUpdate },
    {"UsbIrdaBridge",           DevPathFromTextUsbIrdaBridge           },
    {"UsbTestAndMeasurement",   DevPathFromTextUsbTestAndMeasurement   },
    {"UsbWwid",                 DevPathFromTextUsbWwid                 },
    {"Unit",                    DevPathFromTextUnit                    },
    {"iSCSI",                   DevPathFromTextiSCSI                   },
    {"Vlan",                    DevPathFromTextVlan                    },
    {"Dns",                     DevPathFromTextDns                     },
    {"Uri",                     DevPathFromTextUri                     },
    {"Bluetooth",               DevPathFromTextBluetooth               },
    {"Wi-Fi",                   DevPathFromTextWiFi                    },
    {"BluetoothLE",             DevPathFromTextBluetoothLE             },
    {"MediaPath",               DevPathFromTextMediaPath               },
    {"HD",                      DevPathFromTextHD                      },
    {"CDROM",                   DevPathFromTextCDROM                   },
    {"VenMedia",                DevPathFromTextVenMedia                },
    {"Media",                   DevPathFromTextMedia                   },
    {"Fv",                      DevPathFromTextFv                      },
    {"FvFile",                  DevPathFromTextFvFile                  },
    {"Offset",                  DevPathFromTextRelativeOffsetRange     },
    {"RamDisk",                 DevPathFromTextRamDisk                 },
    {"VirtualDisk",             DevPathFromTextVirtualDisk             },
    {"VirtualCD",               DevPathFromTextVirtualCd               },
    {"PersistentVirtualDisk",   DevPathFromTextPersistentVirtualDisk   },
    {"PersistentVirtualCD",     DevPathFromTextPersistentVirtualCd     },

    {"BbsPath",                 DevPathFromTextBbsPath                 },
    {"BBS",                     DevPathFromTextBBS                     },
    {"Sata",                    DevPathFromTextSata                    },
    {None, None}
    
}

def IS_NULL(a):
    if a == '\0':
        return True
    else:
        return False
   
 
def IS_SLASH(a):
    if a == '/':
        return True
    else:
        return False
    
    
def IS_LEFT_PARENTH(a):
    if a == '(':
        return True
    else:
        return False


def IS_RIGHT_PARENTH(a):
    if a == ')':
        return True
    else:
        return False
    

def IS_COMMA(a):
    if a == ',':
        return True
    else:
        return False


#Ruturns the SubType field of device path node
#Returns the SubType field of the device path node specified by Node
#If Node is None, then assert
def DevicePathSubType(Node) -> int:
    assert(Node != None)
    Node = EFI_DEVICE_PATH_PROTOCOL()
    return Node.SubType


#Ruturns the SubType field of device path node
#Returns the SubType field of the device path node specified by Node
#If Node is None, then assert
def DevicePathType(Node) -> int:
    assert(Node != None)
    Node = EFI_DEVICE_PATH_PROTOCOL()
    return Node.Type


def IsDevicePathEndType(Node) -> bool:
    assert(Node != None)
    return DevicePathType (Node) == END_DEVICE_PATH_TYPE


def IsDevicePathEnd(Node) -> bool:
    assert(Node != None)
    return IsDevicePathEndType (Node) and DevicePathSubType(Node) == END_ENTIRE_DEVICE_PATH_SUBTYPE


def ReadUnaligned16(Buffer:int) -> int:
    assert(Buffer != None)
    return Buffer
    

#Returns the 16-bit Length field of a device path node.
def DevicePathNodeLength(Node) -> int:
    assert(Node != None)
    Node = EFI_DEVICE_PATH_PROTOCOL()
    return ReadUnaligned16(Node.Length[0])


#Returns a pointer to the next node in a device path.
def NextDevicePathNode(Node) -> EFI_DEVICE_PATH_PROTOCOL:
    assert(Node != None)
    return Node + DevicePathNodeLength(Node)


#Determine whether a given device path is valid
def IsDevicePathValid(DevicePath:EFI_DEVICE_PATH_PROTOCOL,MaxSize:int) -> bool:
    if DevicePath == None or (MaxSize > 0 and MaxSize < END_DEVICE_PATH_LENGTH):
        return False
    
    if MaxSize == 0:
        MaxSize = MAX_UINT32
        
    while IsDevicePathEnd (DevicePath) == 0:
        Size = 0
        NodeLength = DevicePathNodeLength(DevicePath)
        if NodeLength < sizeof (EFI_DEVICE_PATH_PROTOCOL):
            return False
        
        if NodeLength > MAX_UINT32 - Size:
            return False
        Size += NodeLength
        
        if Size > MaxSize - END_DEVICE_PATH_LENGTH:
            return False
        Count += 1
        if Count >= MAX_DEVICE_PATH_NODE_COUNT:
            return False
        
        DevicePath = NextDevicePathNode (DevicePath)
    
    return True if DevicePathNodeLength (DevicePath) == END_DEVICE_PATH_LENGTH else False
    

#Returns the size of a device path in bytes
def UefiDevicePathLibGetDevicePathSize(DevicePath:EFI_DEVICE_PATH_PROTOCOL) -> int:
    Start = EFI_DEVICE_PATH_PROTOCOL()
    if DevicePath == None:
        return 0
    if IsDevicePathValid(DevicePath,0) == 0:
        return 0
    
    Start = DevicePath
    while IsDevicePathEnd (DevicePath) == 0:
        DevicePath = NextDevicePathNode(DevicePath)
        
    return DevicePath - Start + DevicePathNodeLength(DevicePath)


#Returns the size of a device path in bytes.
def GetDevicePathSize(DevicePath:EFI_DEVICE_PATH_PROTOCOL) -> int:
    return UefiDevicePathLibGetDevicePathSize(DevicePath)


#Creates a new copy of an existing device path.
def UefiDevicePathLibDuplicateDevicePath(DevicePath:EFI_DEVICE_PATH_PROTOCOL) -> EFI_DEVICE_PATH_PROTOCOL:
    Size = GetDevicePathSize(DevicePath)
    if Size == 0:
        return None
    return Size


#Creates a new copy of an existing device path.
def DuplicateDevicePath(DevicePath:EFI_DEVICE_PATH_PROTOCOL) -> EFI_DEVICE_PATH_PROTOCOL:
    return UefiDevicePathLibDuplicateDevicePath(DevicePath)


#Creates a new device path by appending a second device path to a first device path.
def UefiDevicePathLibAppendDevicePath(FirstDevicePath:EFI_DEVICE_PATH_PROTOCOL,SecondDevicePath:EFI_DEVICE_PATH_PROTOCOL) -> EFI_DEVICE_PATH_PROTOCOL:
    
    #If there's only 1 path, just duplicate it
    if FirstDevicePath == None:
        return DuplicateDevicePath(SecondDevicePath if SecondDevicePath != None else mUefiDevicePathLibEndDevicePath)
    
    if SecondDevicePath == None:
        return DuplicateDevicePath (FirstDevicePath)
    
    if IsDevicePathValid(FirstDevicePath, 0) == 0 or IsDevicePathValid(FirstDevicePath, 0) == 0:
        return None
    
    #Allocate space for the combined device path. It only has one end node of
    #length EFI_DEVICE_PATH_PROTOCOL.
    Size1 = GetDevicePathSize(FirstDevicePath)
    Size2 = GetDevicePathSize(SecondDevicePath)
    Size = Size1 + Size2 - END_DEVICE_PATH_LENGTH
    
    NewDevicePath = Size
    if NewDevicePath != None:
        NewDevicePath = FirstDevicePath
        DevicePath2 = NewDevicePath + Size1 - END_DEVICE_PATH_LENGTH
        DevicePath2 = SecondDevicePath
        
    return NewDevicePath

def AppendDevicePath(FirstDevicePath:EFI_DEVICE_PATH_PROTOCOL,SecondDevicePath:EFI_DEVICE_PATH_PROTOCOL):
    return UefiDevicePathLibAppendDevicePath (FirstDevicePath, SecondDevicePath)


#Creates a new path by appending the device node to the device path.
def UefiDevicePathLibAppendDevicePathNode(DevicePath:EFI_DEVICE_PATH_PROTOCOL,DevicePathNode:EFI_DEVICE_PATH_PROTOCOL) -> EFI_DEVICE_PATH_PROTOCOL:
    if DevicePath == None:
        return DuplicateDevicePath(DevicePath if DevicePath != None else mUefiDevicePathLibEndDevicePath)
    
    #Build a Node that has a terminator on it
    NodeLength = DevicePathNodeLength(DevicePathNode)
    
    TempDevicePath = EFI_DEVICE_PATH_PROTOCOL()
    
    NextNode = NextDevicePathNode(TempDevicePath)
    SetDevicePathEndNode(NextNode)
    
    NewDevicePath = AppendDevicePath(DevicePath,TempDevicePath)
    
    return NewDevicePath


def AppendDevicePathNode(DevicePath:EFI_DEVICE_PATH_PROTOCOL,DevicePathNode:EFI_DEVICE_PATH_PROTOCOL) -> EFI_DEVICE_PATH_PROTOCOL:
    return UefiDevicePathLibAppendDevicePathNode(DevicePath,DevicePathNode)


#Fills in all the fields of a device path node that is the end of an entire device path 
def SetDevicePathEndNode(Node):
    assert(Node != None)
    Node = mUefiDevicePathLibEndDevicePath


#Duplicates a string
def UefiDevicePathLibStrDuplicate(Src:str) -> str:
    String = ''
    String = Src
    return String


#Get one device node from entire device path text
def GetNextDeviceNodeStr(DevicePath:str,IsInstanceEnd:bool):
    
    Str = DevicePath

    if IS_NULL(Str):
        return None
    length = len(Str)
    #Skip the leading '/','(',')' and ','
    for i in range(length):
        if IS_NULL(Str[i]) == 0:
            if IS_SLASH(Str[i])== False and IS_SLASH(Str[i]) == False and IS_LEFT_PARENTH (Str[i]) == False and IS_RIGHT_PARENTH (Str[i]) == False:
                break
            
    ReturnStr = Str[i:]
    
    length2 = len(ReturnStr)
    #Scan for the separator of this device node, '/' or ','
    ParenthesesStack = 0
    for i in range(length2):
        if IS_NULL(Str[i]) == False:
            if (IS_COMMA(Str[i]) or IS_SLASH (Str[i])) and ParenthesesStack == 0:
                break
            if IS_LEFT_PARENTH(Str[i]):
                ParenthesesStack = ParenthesesStack + 1
            elif IS_RIGHT_PARENTH(Str[i]):
                ParenthesesStack = ParenthesesStack - 1
    
    if ParenthesesStack != 0:
        #The '(' doesn't pair with ')', invalid device path
        return None
    
  
    if IS_COMMA(Str[i]):
        IsInstanceEnd = True
        Str[i] = '\0'
        i += 1
    else:
        IsInstanceEnd = False
        if IS_NULL(Str[i]) == 0:
            Str[i] = '\0'
            i += 1
            
    DevicePath = Str[i:]
    
    return ReturnStr,DevicePath


def GetParamByNodeName(Str:str,NodeName:str):
    NodeNameLength = len(NodeName)
    if Str[0:NodeNameLength] != NodeName[0:NodeNameLength]:
        return None
    if IS_LEFT_PARENTH(Str[NodeNameLength]) == 0:
        return None
    ParamStr = NodeNameLength + 1
    ParameterLength = 0
    StrPointer = ParamStr
    while IS_NULL(Str[StrPointer]) == 0:
        if IS_RIGHT_PARENTH (Str[StrPointer]):
            break
        StrPointer += 1
        ParameterLength += 1
    if IS_NULL (Str(StrPointer)):
        return None
    Str += '\0'
    ParamStr = Str
    return ParamStr
        
def DevPathFromTextFilePath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    File = FILEPATH_DEVICE_PATH()
    File.Header = CreateDeviceNode(MEDIA_DEVICE_PATH,MEDIA_FILEPATH_DP,sizeof (FILEPATH_DEVICE_PATH) + len(TextDeviceNode) * 2)
    File.PathName = TextDeviceNode[0:len(TextDeviceNode) + 1]
    return File


#Convert text to the binary representation of a device node
def UefiDevicePathLibConvertTextToDeviceNode(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    if TextDeviceNode == None or IS_NULL(TextDeviceNode):
        return None

    ParamStr = ''
    FromText = DEVICE_PATH_FROM_TEXT()
    DeviceNode = EFI_DEVICE_PATH_PROTOCOL()
    DeviceNodeStr = TextDeviceNode
    assert(DeviceNodeStr != None)
    Index = 0 
    while mUefiDevicePathLibDevPathFromTextTable[Index].Function != None:
        ParamStr = GetParamByNodeName(DeviceNodeStr, mUefiDevicePathLibDevPathFromTextTable[Index].DevicePathNodeText)
        if ParamStr != None:
            FromText = mUefiDevicePathLibDevPathFromTextTable[Index].Function
            break
        Index = Index + 1
        
    if FromText == None:
        FromText = DevPathFromTextFilePath
        DeviceNode = FromText (DeviceNodeStr)
    else:
        DeviceNode = FromText (ParamStr)
    
    return DeviceNode


