# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

from FirmwareStorageFormat.SectionHeader import *
import logging
from BaseTypes import *


#Compares to GUIDs
def CompareGuid(Guid1:EFI_GUID,Guid2:EFI_GUID):
    if Guid1 == Guid2:
        return 0
    else:
        return 1


#Determine if an integer represents character that is a hex digit
def isxdigit(c:int):
    return ('0' <= c and c <= '9') or ('a' <= c and c <= 'f') or ('A' <= c and c <= 'F')


#Converts a null terminated ascii string that represents a number into a UINT64 value.
def AsciiStringToUint64(AsciiString:str,IsHex:bool,ReturnValue:int):
    Value = 0
    Index = 0

    #Check input parameter
    if AsciiString == None or ReturnValue == None or len(AsciiString) > 0xff:
        return EFI_INVALID_PARAMETER
    while AsciiString[Index] == ' ':
        Index += 1

    #Add each character to the result

    #Skip first two chars only if the string starts with '0x' or '0X'
    if AsciiString[Index] == '0' and (AsciiString[Index + 1] == 'x' or AsciiString[Index + 1] == 'X'):
        IsHex = True
        Index += 2
    if IsHex:
        #Convert the hex string.
        while AsciiString[Index] != '\0':
            CurrentChar = AsciiString[Index]
            if CurrentChar == ' ':
                break
            
            #Verify Hex string
            if isxdigit(int(CurrentChar)) == 0:
                return EFI_ABORTED
            
            Value *= 16
            if CurrentChar >= '0' and CurrentChar <= '9':
                Value += CurrentChar - '0'
            elif CurrentChar >= 'a' and CurrentChar <= 'f':
                Value += CurrentChar - 'a' + 10
            elif CurrentChar >= 'A' and CurrentChar <= 'F':
                Value += CurrentChar - 'A' + 10
            Index += 1
        ReturnValue = Value
    else:
        #Convert dec string is a number
        while Index < len (AsciiString):
            CurrentChar = AsciiString[Index]
            if CurrentChar == ' ':
                break
            
            #Verify Dec string
            if isdigit(int(CurrentChar)) == 0:
                return EFI_ABORTED
            Value = Value * 10
            Value += CurrentChar - '0'
            Index += 1
        ReturnValue = Value
    return EFI_SUCCESS


def isdigit(c:int):
    return '0' <= c and c <= '9'
    

#Converts a string to an EFI_GUID.
def StringToGuid(AsciiGuidBuffer:str,GuidBuffer:EFI_GUID):
    Data4 = []*8
    logger =logging.getLogger('GenSec')
    if AsciiGuidBuffer == None or GuidBuffer == None:
        return EFI_INVALID_PARAMETER
    #Check Guid Format strictly xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Index = 0
    while AsciiGuidBuffer[Index] != '\0' and Index < 37:
        if Index == 8 or Index == 13 or Index == 18 or Index == 23:
            if AsciiGuidBuffer[Index] != '-':
                break
        else:
            if (AsciiGuidBuffer[Index] >= '0' and AsciiGuidBuffer[Index] <= '9') or\
                (AsciiGuidBuffer[Index] >= 'a' and AsciiGuidBuffer[Index] <= 'f') or\
                    (AsciiGuidBuffer[Index] >= 'A' and AsciiGuidBuffer[Index] <= 'F'):
                    continue
            else:
                break
        Index += 1

    if Index < 36 or AsciiGuidBuffer[36] != '\0':
        logger.error("Invalid option value")
        return EFI_ABORTED

    #Scan the guid string into the buffer
    if True:
       Data1 = AsciiGuidBuffer[0:8]
       Data2 = AsciiGuidBuffer[8:12]
       Data3 = AsciiGuidBuffer[12:16]
       Data4[0] = AsciiGuidBuffer[16:18]
       Data4[1] = AsciiGuidBuffer[18:20]
       Data4[2] = AsciiGuidBuffer[20:22]
       Data4[3] = AsciiGuidBuffer[22:24]
       Data4[4] = AsciiGuidBuffer[24:26]
       Data4[5] = AsciiGuidBuffer[26:28]
       Data4[6] = AsciiGuidBuffer[28:30]
       Data4[7] = AsciiGuidBuffer[30:32]
       if len(Data1 + Data2 + Data3+Data4[0]+Data4[1]+Data4[2]+\
            Data4[3]+Data4[4]+Data4[5]+Data4[6]+Data4[7]) != AsciiGuidBuffer:
            Index = 0
       else:
            Index = 11


    #Verify the correct number of items were scanned.
    if Index != 11:
        logger.error("Invalid option value")
        return EFI_ABORTED

    #Copy the data into our GUID.
    GuidBuffer.Data1     = Data1
    GuidBuffer.Data2     = Data2
    GuidBuffer.Data3     = Data3
    GuidBuffer.Data4[0]  = Data4[0]
    GuidBuffer.Data4[1]  = Data4[1]
    GuidBuffer.Data4[2]  = Data4[2]
    GuidBuffer.Data4[3]  = Data4[3]
    GuidBuffer.Data4[4]  = Data4[4]
    GuidBuffer.Data4[5]  = Data4[5]
    GuidBuffer.Data4[6]  = Data4[6]
    GuidBuffer.Data4[7]  = Data4[7]