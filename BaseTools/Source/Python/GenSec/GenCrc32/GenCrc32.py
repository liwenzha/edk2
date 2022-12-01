#@file
#Calculate Crc32 value and Verify Crc32 value for input data.
#
#Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#
#Import Modules
#
import io
import logging
import argparse
import os
import sys
from binascii import crc32



parser=argparse.ArgumentParser(description='''
Calculate Crc32 value and Verify Crc32 value for input data.
''')
parser.add_argument("-e","--encode",dest="inputfilename1",
                    help="Calculate andverify CRC32 value for the input file.")
parser.add_argument("-d","--decode",dest="inputfilename2",
                    help="Verify CRC32 value for the input file.")
parser.add_argument("-o","--output",dest="outputfilename",
                    help="Output file name.")
parser.add_argument("-s","--silent",help="Returns only the exit code;informational and error messages are not displayed.")                   
parser.add_argument("--version", action="version", version='%(prog)s Version 2.0',
                    help="Show program's version number and exit.")

group=parser.add_mutually_exclusive_group()
group.add_argument("-v","--verbose",action="store_true",
                    help="Print information statements")
group.add_argument("-q","--quiet",action="store_true",
                    help="Disable all messages except fatal errors")



#Calculate the Crc32 and store it in the file
def CalculateCrc32(inputfile:str, outputfile:str, filebytes=b''):
    logger=logging.getLogger('GenCrC32')
    status=0
    try:
        Crc=0xffffffff
        if filebytes != b'':
            temp = filebytes
            status=1
        else:
            with open(inputfile,'rb') as fin:             
                temp=fin.read()
                
        CrcOut = crc32(temp)
        CrcOut=CrcOut.to_bytes(4,byteorder="little")
        with open(outputfile,'wb') as fout:        
            if status==0:
                fout.write(CrcOut)
            fout.write(temp)
    except Exception as e:
        logger.error("Calculation failed!")
        raise(e)
    return CrcOut


#Verify the CRC and checkout if the file is correct
def VerifyCrc32(inputfile1:str,outputfile1:str):
    logger=logging.getLogger('GenCrC32')
    try:
        with open(inputfile1,'rb') as fin3:
            head=fin3.read()
            header=head[0:4]
            calres=CalculateCrc32('', outputfile1, head[4:])

        if calres==header:
            return calres
        else:
            logger.error("Invalid file!")
            raise(e)
    
    except Exception as e:
        logger.error("Verification failed!")
        raise(e)


def main():
    args=parser.parse_args()

    logger=logging.getLogger('GenCrc32')
    if args.quiet:
        logger.setLevel(logging.CRITICAL)
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    lh = logging.StreamHandler(sys.stdout)
    lf = logging.Formatter("%(levelname)-8s: %(message)s")
    lh.setFormatter(lf)
    logger.addHandler(lh)

    try:
        if len(sys.argv)==1:
            parser.print_help()
            logger.error("Missing options")
            raise(e)
        if args.inputfilename1:
            CalculateCrc32(args.inputfilename1,args.outputfilename)
        elif args.inputfilename2:
            VerifyCrc32(args.inputfilename2,args.outputfilename)
    except Exception as e:
        return 1
    return 0


if __name__=="__main__":
    exit(main())