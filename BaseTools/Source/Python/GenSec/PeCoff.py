# @file
#Creates output file that is a properly formed section per the PI spec.

#Copyright (c) 2004 - 2018, Intel Corporation. All rights reserved.<BR>
#SPDX-License-Identifier: BSD-2-Clause-Patent


#Return status codes from the PE/COFF Loader services
IMAGE_ERROR_IMAGE_READ = 1


#Support old names for backward compatible
EFI_IMAGE_DOS_SIGNATURE = 0x5A4D    # MZ
EFI_IMAGE_NT_SIGNATURE = 0x00004550 # PE00