#@file
#Calculate Crc32 value and Verify Crc32 value for input data.
#
#Copyright (c) 2007 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

#Import Modules
import shutil
import unittest
import tempfile
import os
import GenCrc32.GenCrc32 as Gen
import filecmp
import struct as st



class TestGenCrc32(unittest.TestCase):
    def setUp(self):
        self.tmpdir=tempfile.mkdtemp()
        self.binary_file=os.path.join(self.tmpdir,"Binary.bin")
        self.create_inputfile()


    def tearDown(self):
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)


    def create_inputfile(self):
        with open(self.binary_file,"wb") as fout:
            for i in range(512):
                fout.write(st.pack("<H",i))




    def test_crc32encode(self):
        inputfile=[
            os.path.join("encode","demo.bin"),
            os.path.join("encode","PcdPeim.efi"),
            os.path.join("encode","S3Resume2Pei.efi")
        ]
        
        outputfile=[
            os.path.join("encode/encode_result","demo_crc_py"),
            os.path.join("encode/encode_result","PcdPeim_crc32_py"),
            os.path.join("encode/encode_result","S3Resume2Pei_crc32_py")
        ]
        
        
        expected_output=[
            os.path.join("encode","demo_crc"),
            os.path.join("encode","PcdPeim_crc32"),
            os.path.join("encode","S3Resume2Pei_crc32")
        ]
        for index,o in enumerate(inputfile):
            output=outputfile[index]
            try:
                Gen.CalculateCrc32(o,output)
                status=filecmp.cmp(output,expected_output[index])
            except Exception as e:
                self.assertTrue(False, msg="GenCrc32 encode function error")
            self.assertEqual(status,1)
                
           
        
    def test_crc32decode(self):
        inputfile=[
            os.path.join("decode","demo_crc"),
            os.path.join("decode","PcdPeim_crc32"),
            os.path.join("decode","S3Resume2Pei_crc32")
        ]
        
        
        outputfile=[
            os.path.join("decode/decode_result","demo_decode"),
            os.path.join("decode/decode_result","PcdPeim_decode"),
            os.path.join("decode/decode_result","S3Resume2Pei_decode")
        ]
        
        expected_output=[
            os.path.join("decode","demo"),
            os.path.join("decode","PcdPeim"),
            os.path.join("decode","S3Resume2Pei")
        ]
        for index,o in enumerate(inputfile):
            output=outputfile[index]
            try:
                Gen.VerifyCrc32(o,output)
                status=filecmp.cmp(output,expected_output[index])
            except Exception as e:
                self.assertTrue(False, msg="GenCrc32 decode function error")
            self.assertEqual(status,1)
        

            

    def test_CalculateCrc32_outputfile(self):
        output=[
            "Binary1",
            "Binary1.bin"
        ]


        expected_output=[
            os.path.join(os.getcwd(),"Binary1"),
            os.path.join(os.getcwd(),"Binary1.bin")
        ]

        for index,o in enumerate(output):
            try:
                Gen.CalculateCrc32(self.binary_file,o)
            except Exception as e:
                self.assertTrue(False,msg="GenCrc32 output file directory error")
            self.assertTrue(os.path.exists(expected_output[index]))
            



if __name__=="__main__":
    unittest.main()