from ctypes import *


EFI_SUCCESS = 0
mDst = None
mDstUpperLimit = None


#Put a dword to output stream
def PutDword(Data:c_uint32):
    if mDst < mDstUpperLimit:
        mDst = Data & 0xff
        mDst = mDst + 1
        
    if mDst < mDstUpperLimit:
        mDst = Data >> 0x08 & 0xff
        mDst = mDst + 1
        
    if mDst < mDstUpperLimit:
        mDst = Data >> 0x10 & 0xff
        mDst = mDst + 1
        
    if mDst < mDstUpperLimit:
        mDst = Data >> 0x18 & 0xff
        mDst = mDst + 1


#The main compression routine.
def EfiCompress(SrcBuffer:c_uint8,SrcSize:c_uint32,DstBuffer:c_uint8,DstSize:c_uint32) -> c_uint64:
    Status = EFI_SUCCESS
    mSrc = SrcBuffer
    mSrcUpperLimit = mSrc[SrcSize:]
    mDst = DstBuffer
    mDstUpperLimit = mDst + DstSize
    
    PutDword(0)
    PutDword(0)
    
    
    
