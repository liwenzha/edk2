#@file
#  Definition for Device Path Tool.

#Copyright (c) 2017 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

#
import argparse
from Struct import *
import sys
import logging
import copy


STATUS_ERROR = 2
STATUS_SUCCESS = 0
END_DEVICE_PATH_TYPE = 0x7f
END_ENTIRE_DEVICE_PATH_SUBTYPE = 0xFF
END_INSTANCE_DEVICE_PATH_SUBTYPE = 0x01


parser = argparse.ArgumentParser(description="A Device Path Tool")
parser.add_argument("DevicePathString",dest="DevicePath",help="Device Path string is specified, no space character.Example: \"PciRoot(0)/Pci(0,0)")
parser.add_argument("-h","--help",dest="help",help="Show this help message and exit.")
parser.add_argument("--version", action="version", version='%(prog)s Version 1.0',
                    help="Show program's version number and exit.")


def PrintMem(Buffer:EFI_DEVICE_PATH_PROTOCOL,Count:int):
    Bytes = Buffer
    for Idx in range(Count):
        print("0x%02x" %Bytes[Idx])
        

#Write ascii string as unicode string format to FILE
def Ascii2UnicodeString(String:str,UniString:c_uint16) -> EFI_DEVICE_PATH_PROTOCOL:
    for i in range(len(String)):
        if String[i] != '\0':
            UniString[i] = c_uint16(String[i])
    Unistring +='\0'


#Convert text to the binary representation of a device path
def UefiDevicePathLibConvertTextToDevicePath(TextDevicePath:str):
    if TextDevicePath == None or IS_NULL(TextDevicePath):
        return None
    
    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    # SetDevicePathEndNode(DevicePath)
    DevicePathStr = TextDevicePath
    #DevicePathStr = copy.deepcopy(TextDevicePath)
    
    Str = DevicePathStr
    IsInstanceEnd = False
    res = GetNextDeviceNodeStr (Str,IsInstanceEnd)
    if res == None:
        DeviceNodeStr = None
    else:
        DeviceNodeStr = res[0]
        Str = res[1]

    while DeviceNodeStr != None:
        DeviceNode = UefiDevicePathLibConvertTextToDeviceNode (DeviceNodeStr)
        NewDevicePath = EFI_DEVICE_PATH_PROTOCOL()
        NewDevicePath = AppendDevicePathNode (DevicePath, DeviceNode)
        DevicePath = NewDevicePath
    
        if IsInstanceEnd:
            DeviceNode = EFI_DEVICE_PATH_PROTOCOL()
            SetDevicePathEndNode(DeviceNode)
            DeviceNode.SubType = END_INSTANCE_DEVICE_PATH_SUBTYPE
        
            NewDevicePath = EFI_DEVICE_PATH_PROTOCOL()
            NewDevicePath = AppendDevicePathNode(DevicePath, DeviceNode)
            DevicePath = NewDevicePath
    return DevicePath
    

    
def main():
    DevicePath = EFI_DEVICE_PATH_PROTOCOL()
    logger = logging.getLogger('DevicePath')
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        logger.error("Missing options", "No input options specified.")
        parser.print_help()
        return STATUS_ERROR

    
    # if args.version:
    #     pass
    
    Str = sys.argv[1]
    if Str == None:
        logger.error("Invalid option value, Device Path can't be NULL")
        return STATUS_ERROR
    #Str16 = ''
    #Ascii2UnicodeString(Str,Str16)
    DevicePath = UefiDevicePathLibConvertTextToDevicePath(Str)
    if DevicePath == None:
        logger.error("Convert fail, Cannot convert text to a device path")
        return STATUS_ERROR
    
    while (DevicePath.Type == END_DEVICE_PATH_TYPE)==0 and DevicePath.SubType == END_ENTIRE_DEVICE_PATH_SUBTYPE:
        PrintMem(DevicePath,DevicePath.Length[0] | DevicePath.Length[1] << 8)
        DevicePath = EFI_DEVICE_PATH_PROTOCOL(DevicePath + (DevicePath.Length[0] | DevicePath.Length[1] << 8))
    PrintMem(DevicePath, DevicePath.Length[0] | DevicePath.Length[1] << 8)
    return STATUS_SUCCESS


if __name__=="__main__":
    exit(main())