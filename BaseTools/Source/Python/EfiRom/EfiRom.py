# @file
#  Utility program to create an EFI option ROM image from binary and EFI PE32 files.
#
#  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##


#Import modules
import argparse

parser = argparse.ArgumentParser(description='''
Utility program to create an EFI option ROM image from binary and EFI PE32 files.
''')
parser.add_argument("-o","--output",help = "Output Filename.File will be created to store the output content.")
parser.add_argument("-e",help = "EFI PE32 image files.")
parser.add_argument("-ec",help = "EfiFileName.EFI PE32 image files and will be compressed.")
parser.add_argument("-b",help = "Legacy binary files.")
parser.add_argument("-l","ClassCode.Hex ClassCode in the PCI data structure header.")
parser.add_argument("-r",help = "Rev.Hex Revision in the PCI data structure header.")
parser.add_argument("-n",help = "Not to automatically set the LAST bit in the last file.")
parser.add_argument("-f",help = "VendorId.Hex PCI Vendor ID for the device OpROM, must be specified")
parser.add_argument("-i",help = "DeviceId.One or more hex PCI Device IDs for the device OpROM, must be specified")
parser.add_argument("-p","--pci23",help = " Default layout meets PCI 3.0 specifications,specifying this flag will for a PCI 2.3 layout.")
parser.add_argument("-d","--dump",help = "Dump the headers of an existing option ROM image.")
parser.add_argument("-v","--verbose",dest="verbose",help="Turn on verbose output with informational messages.")
parser.add_argument("-q","--quiet",dest="quiet",help="Disable all messages except key message and fatal error")
parser.add_argument("-d","--debug",dest="debug_level",help="Enable debug messages, at input debug level.")
parser.add_argument("--version", action="version", version='%(prog)s Version 1.0',
                    help="Show program's version number and exit.")

