from ctypes import *


EFI_SUCCESS = 0
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
WNDBIT = 13
WNDSIZ = 1 << WNDBIT
THRESHOLD = 3
mMatchPos = None


mDst = None
mDstUpperLimit = None
mCrcTable = []
INIT_CRC = 0
CRCPOLY = 0xA001


def EFI_ERROR(A):
    if A < 0:
        return True
    else:
        return False


#Put a dword to output stream
def PutDword(Data:int):
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


def MakeCrcTable():
    for i in range(0xff + 1):
        r = i
        for j in range(8):
            if r & 1:
                r = (r >> 1) ^ CRCPOLY
            else:
                r >>= 1
        mCrcTable[i] = c_uint16(r)


#The main controlling routine for compression process.
def Encode() -> int:
    mText = b''
    InitSlide()
    HufEncodeStart()

    mRemainder = FreadCrc(mText[WNDSIZ], WNDSIZ + 256)
    mMatchLen = 0
    mPos = WNDSIZ
    InsertNode()
    if mMatchLen > mRemainder:
        mMatchLen = mRemainder
    while mRemainder > 0:
        LastMatchLen = mMatchLen
        LastMatchPos = mMatchPos
        GetNextMatch()
        if mMatchLen > mRemainder:
            mMatchLen = mRemainder

        if mMatchLen > LastMatchLen or LastMatchLen < THRESHOLD:
            Output(mText[mPos - 1], 0)
        else:
            Output(LastMatchLen + 0xff + 1 - THRESHOLD,(mPos - LastMatchPos - 2) & (WNDSIZ - 1))
            while LastMatchLen - 1 > 0:
                GetNextMatch()
            if mMatchLen > mRemainder:
                mMatchLen = mRemainder
    
    HufEncodeEnd()
    return EFI_SUCCESS


#The main compression routine.
def EfiCompress(SrcSize:int,DstSize:int,SrcBuffer = b'',DstBuffer = b'') -> c_uint64:
    
    Status = EFI_SUCCESS
    
    mSrc = SrcBuffer
    mSrcUpperLimit = mSrc[SrcSize:]
    mDst = DstBuffer
    mDstUpperLimit = mDst + DstSize
    
    PutDword(0)
    PutDword(0)
    
    MakeCrcTable()
    
    mOrigSize = mCompSize = 0
    mCrc = INIT_CRC
    
    #Compress it
    Status = Encode()
    if EFI_ERROR (Status):
        return EFI_OUT_OF_RESOURCES
    
    #Fill in compressed size and original size
    mDst = DstBuffer
    PutDword(mCompSize+1)
    PutDword(mOrigSize)
    
    #Return
    if mCompSize + 1 + 8 > DstSize:
        DstSize = mCompSize + 1 + 8
        return EFI_BUFFER_TOO_SMALL
    else:
        DstSize = mCompSize + 1 + 8
        return EFI_SUCCESS