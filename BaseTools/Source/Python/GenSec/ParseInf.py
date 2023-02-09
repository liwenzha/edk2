# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent

import sys
sys.path.append("..") 

from FirmwareStorageFormat.SectionHeader import *
import logging
from BaseTypes import *


#Compares to GUIDs
def CompareGuid(Guid1:EFI_GUID,Guid2:EFI_GUID):
    r = Guid1.Data1 - Guid2.Data1
    r += Guid1.Data2 - Guid2.Data2
    r += Guid1.Data3 - Guid2.Data3
    r += Guid1.Data4[0] - Guid2.Data4[0]
    r += Guid1.Data4[1] - Guid2.Data4[1]
    r += Guid1.Data4[2] - Guid2.Data4[2]
    r += Guid1.Data4[3] - Guid2.Data4[3]
    r += Guid1.Data4[4] - Guid2.Data4[4]
    r += Guid1.Data4[5] - Guid2.Data4[5]
    r += Guid1.Data4[6] - Guid2.Data4[6]
    r += Guid1.Data4[4] - Guid2.Data4[7]
    return r


#Determine if an integer represents character that is a hex digit
def isxdigit(c:c_char):
    return ('0' <= c and c <= '9') or ('a' <= c and c <= 'f') or ('A' <= c and c <= 'F')


#Converts a null terminated ascii string that represents a number into a UINT64 value.
#A hex number may be preceded by a 0x, but may not be
#succeeded by an h.A number without 0x or 0X is considered to be base 10
#unless the IsHex input is true.
def AsciiStringToUint64(AsciiString:str,IsHex:bool,ReturnValue:int):
    Value = 0
    #Index = 0

    #Check input parameter
    if AsciiString == None or ReturnValue == None or len(AsciiString) > 0xff:
        return EFI_INVALID_PARAMETER
    # while AsciiString[Index] == ' ':
    #     Index += 1

    #Add each character to the result

    #Skip first two chars only if the string starts with '0x' or '0X'
    if AsciiString[0] == '0' and (AsciiString[1] == 'x' or AsciiString[1] == 'X'):
        IsHex = True
        #Index += 2
    if IsHex:
        #Convert the hex string.
        AsciiString = AsciiString[2:]
        for ch in AsciiString:
            CurrentChar = ch
            if CurrentChar == ' ':
                break
            
            #Verify Hex string
            if isxdigit(ch) == 0:
                return EFI_ABORTED
        
        Value = int(AsciiString,16)
        ReturnValue = Value
    else:
        #Convert dec string is a number
        for ch in AsciiString:
            CurrentChar = ch
            if CurrentChar == ' ':
                break
            
            #Verify Dec string
            if isdigit(CurrentChar) == 0:
                return EFI_ABORTED
        Value = int(AsciiString)
        ReturnValue = Value
    Status = EFI_SUCCESS
    return Status,ReturnValue


def isdigit(c:c_char):
    return '0' <= c and c <= '9'
    

#Converts a string to an EFI_GUID.
def StringToGuid(AsciiGuidBuffer:str,GuidBuffer:EFI_GUID):
    Data4 = [0]*8
    logger =logging.getLogger('GenSec')
    
    if AsciiGuidBuffer == None or GuidBuffer == None:
        return EFI_INVALID_PARAMETER
    
    #Check Guid Format strictly xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    Index = 0
    while Index < 36:
        if Index == 8 or Index == 13 or Index == 18 or Index == 23:
            if AsciiGuidBuffer[Index] != '-':
                break
        else:
            if (AsciiGuidBuffer[Index] >= '0' and AsciiGuidBuffer[Index] <= '9') or\
                (AsciiGuidBuffer[Index] >= 'a' and AsciiGuidBuffer[Index] <= 'f') or\
                    (AsciiGuidBuffer[Index] >= 'A' and AsciiGuidBuffer[Index] <= 'F'):
                    Index += 1
                    continue
            else:
                break
        Index += 1
        continue

    if Index < 36:
        logger.error("Invalid option value")
        return EFI_ABORTED

    #Scan the guid string into the buffer
    Index = 11
    try:
        Data1 = int(AsciiGuidBuffer[0:8],16)
        Data2 = int(AsciiGuidBuffer[9:13],16)
        Data3 = int(AsciiGuidBuffer[14:18],16)
        Data4[0] = int(AsciiGuidBuffer[19:21],16)
        Data4[1] = int(AsciiGuidBuffer[21:23],16)
        Data4[2] = int(AsciiGuidBuffer[24:26],16)
        Data4[3] = int(AsciiGuidBuffer[26:28],16)
        Data4[4] = int(AsciiGuidBuffer[28:30],16)
        Data4[5] = int(AsciiGuidBuffer[30:32],16)
        Data4[6] = int(AsciiGuidBuffer[32:34],16)
        Data4[7] = int(AsciiGuidBuffer[34:36],16)
    except:
        logger.error("Invalid Data value!")
        Index = 0


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
    Status = EFI_SUCCESS
    
    return Status,GuidBuffer