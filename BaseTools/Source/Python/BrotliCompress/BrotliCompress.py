# @file
#  BrotliCompress Compress/Decompress tool (BrotliCompress)
#
#  Copyright (c) 2020, ByoSoft Corporation. All rights reserved.<BR>
#  SPDX-License-Identifier: BSD-2-Clause-Patent

#


#Import Modules
#

import io
import argparse
#import os
import sys
import logging
#import tempfile
import brotli
import numpy as np

BROTLI_MIN_WINDOW_BITS=10

parser=argparse.ArgumentParser(description='''
BrotliCompress Compress/Decompress tool (BrotliCompress)
''')
parser.add_argument("-v","--version", action="version", version='%(prog)s Version 1.0.9',
                    help="Show program's version number and exit.")
parser.add_argument("-e","--compress",dest="inputfilename1",
                    help="Compress the data of the inout file.")
parser.add_argument("-d","--decompress",dest="inputfilename2",
                    help="Decompress the data of the input file.")
parser.add_argument("-o","--output",dest="outputfilename",
                    help="Output file name.")

parser.add_argument("-q","--quality",dest="q_number",type=int,choices=list(range(0, 12)),
                    help="Compresion level.")
parser.add_argument("-g","--gap",dest="g_number",type=int,
                    help="Scratch memory gap level.")

def brotli_max_backward_limit(LgWin):
    return (1<<LgWin)-16

def getFileSize(filename):
    logger = logging.getLogger('BrotliCompress')
    length = 0
    try:
        with open(filename, "rb") as fin:
            fin.seek(0, io.SEEK_END)
            length = fin.tell()
    except Exception as e:
        logger.error("Access file failed: %s", filename)
        raise(e)

    return length
    
    

def CompressFile(inputfile,outputfile,qual=9):
    logger=logging.getLogger('BrotliCompress')
    LgWin=10
    size=getFileSize(inputfile)
    if size>=0:
        LgWin=10
        while brotli_max_backward_limit(LgWin)<size:
            LgWin=LgWin+1
            if LgWin==24:
                break
    try:
        try:
            with open(inputfile,"rb") as fin:
                data=fin.read()
        except Exception as e:
            logger.error("Cannot open file:%s",inputfile)
            raise(e)
        res=brotli.compress(data,quality=qual,lgwin=LgWin)

        with open(outputfile,"wb") as fout:
            fout.write(res)
    except Exception as e:
        logger.error("Compression failed!")
        raise(e)
    return res


def DecompressFile(inputfile1,outputfile1):
    logger=logging.getLogger("BrotliCompress")
    try:
        try:
            with open(inputfile1,"rb") as fin:
                data1=fin.read()
        except Exception as e:
            logger.error("Cannot open file:%s",inputfile1)
            raise(e)
        res1=brotli.decompress(data1)

        with open(outputfile1,"wb") as fout:
            fout.write(res1)
    except Exception as e:
        logger.error("Decompression failed!")
        raise(e)
    return res1



def main():
    args=parser.parse_args()
    status=0
    gap=1
    logger=logging.getLogger('BrotliCompress')

    try:
        if len(sys.argv)==1:
            parser.print_help()
            logger.error("Missing options")
            raise(e)


        if args.inputfilename1:        #Can add some outputfile filename parsing strategies later
            if args.q_number:
                CompressFile(args.inputfilename1,args.outputfilename,args.q_number)
            else:
                CompressFile(args.inputfilename1,args.outputfilename,11)
            
            #with tempfile.TemporaryFile() as tmp:
            #    DecompressFile(args.outputfilename,tmp)
            
            inputfile=args.inputfilename1
            inputsize=getFileSize(inputfile)
            inputsize1=np.int64(inputsize)
            #print(type(inputsize1))
            
            
            outputfile=args.outputfilename
            with open(outputfile,"rb+") as fout1:
                fout1.write(inputsize)
                if args.g_number:
                    gap=args.g_number
                ScratchBufferSize += gap * 0x1000
                kFileBufferSize  = 1 << 19
                ScratchBufferSize += kFileBufferSize * 2
                print(sys.getsizeof(ScratchBufferSize)) 
                fout1.write(ScratchBufferSize)
        elif args.inputfilename2:
            DecompressFile(args.inputfilename2,args.outputfilename)
    except Exception as e:
        status = 1
    return status



if __name__=="__main__":
    main()