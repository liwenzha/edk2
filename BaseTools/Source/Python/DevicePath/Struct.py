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


class EFI_DEVICE_PATH_PROTOCOL(Structure):
    _pack_ = 1
    _fields_ = [
        ('Type',c_uint8),
        ('SubType',c_uint8),
        ('Length',ARRAY(c_uint8,2))
    ]


mUefiDevicePathLibEndDevicePath = EFI_DEVICE_PATH_PROTOCOL({END_DEVICE_PATH_TYPE,END_ENTIRE_DEVICE_PATH_SUBTYPE,{END_DEVICE_PATH_LENGTH,0}})
DEVICE_PATH_FROM_TEXT = EFI_DEVICE_PATH_PROTOCOL(Str = '')


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


def StrHexToBytes(String:c_char_p,Length:c_uint64,Buffer) -> int:
    pass

def DevPathFromTextGenericPath(Type:int,TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    SubtypeStr = GetNextParamStr(TextDeviceNode)
    DataStr = GetNextParamStr (TextDeviceNode)
    
    if DataStr == None:
        DataLength = 0
    else:
        DataLength =  len(DataStr) / 2
    
    Node = CreateDeviceNode(Type,c_uint8(SubtypeStr),sizeof (EFI_DEVICE_PATH_PROTOCOL) + DataLength)
    StrHexToBytes(DataStr, DataLength * 2, Node + 1, DataLength)
    return Node

#Converts a generic text device path node to device path structure.
def DevPathFromTextPath(TextDeviceNode:str) -> EFI_DEVICE_PATH_PROTOCOL:
    TypeStr = GetNextParamStr(TextDeviceNode)
    return DevPathFromTextGenericPath(TypeStr,TextDeviceNode)


def DevPathFromTextHardwarePath(TextDeviceNode:str):
    return DevPathFromTextGenericPath(HARDWARE_DEVICE_PATH, TextDeviceNode)


def SetDevicePathNodeLength(Node,Length:int) -> c_uint16:
    assert(Node != None)
    assert(Length >= sizeof (EFI_DEVICE_PATH_PROTOCOL) and Length < SIZE_64KB )
    return WriteUnaligned16
 
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
    DeviceStr   = GetNextParamStr (TextDeviceNode)
    FunctionStr = GetNextParamStr (TextDeviceNode)
    Pci = PCI_DEVICE_PATH().from_buffer_copy(CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_PCI_DP,sizeof (PCI_DEVICE_PATH)))
    Pci.Function = int(FunctionStr)
    Pci.Device = int(DeviceStr)
    
    
def DevPathFromTextPcCard(TextDeviceNode):
    Pccard = PCCARD_DEVICE_PATH()
    FunctionNumberStr = GetNextParamStr(TextDeviceNode)
    Pccard = PCCARD_DEVICE_PATH().from_buffer_copy(CreateDeviceNode(HARDWARE_DEVICE_PATH,HW_PCCARD_DP,sizeof (PCCARD_DEVICE_PATH)))
    

mUefiDevicePathLibDevPathFromTextTable = DEVICE_PATH_FROM_TEXT_TABLE{
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
    {NULL, NULL}
    
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


