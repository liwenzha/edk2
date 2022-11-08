# @file
#  BrotliCompress Compress/Decompress tool (BrotliCompress)
#
#  Copyright (c) 2020, ByoSoft Corporation. All rights reserved.<BR>
#  SPDX-License-Identifier: BSD-2-Clause-Patent

#


#Import Modules
#

#import io
import argparse
#import os
import sys
import logging
import brotli



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
#parser.add_argument("-g","--gap",dest="g_number",type=int,
#                    help="Scratch memory gap level.")



def CompressFile(inputfile,outputfile,qual=11):
    logger=logging.getLogger('BrotliCompress')
    try:
        try:
            with open(inputfile,"rb") as fin:
                data=fin.read()
        except Exception as e:
            logger.error("Cannot open file:%s",inputfile)
            raise(e)
        res=brotli.compress(data,quality=qual,lgwin=22)

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
        elif args.inputfilename2:
            DecompressFile(args.inputfilename2,args.outputfilename)
    except Exception as e:
        status = 1
    return status



if __name__=="__main__":
    main()