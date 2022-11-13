from ctypes import *


EFI_SUCCESS = 0
EFI_OUT_OF_RESOURCES = 0x8000000000000000 | (9)
EFI_BUFFER_TOO_SMALL = 0x8000000000000000 | (5)
WNDBIT = 13
WNDSIZ = 1 << WNDBIT
THRESHOLD = 3
mMatchPos = None
UINT8_MAX = 0xff
MAX_HASH_VAL = 3 * WNDSIZ + (WNDSIZ / 512 + 1) * UINT8_MAX

mLevel = b''
mPosition = b''
mParent = b''
mNext = b''

MAXMATCH = 256
NC = UINT8_MAX + MAXMATCH + 2 - THRESHOLD
NP = WNDBIT + 1
mCFreq = []
mPFreq = []
UINT8_BIT = 8
mSubBitBuf = None


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
    for i in range(UINT8_MAX + 1):
        r = i
        for j in range(8):
            if r & 1:
                r = (r >> 1) ^ CRCPOLY
            else:
                r >>= 1
        mCrcTable[i] = c_uint16(r)


#Initialize String Info Log data structures
def InitSlide():
    for i in range(WNDSIZ, WNDSIZ + UINT8_MAX):
        mLevel[i] = 1
        mPosition[i] = 0
        
    for i in range(WNDSIZ, WNDSIZ*2):
        mParent[i] = 0
    mAvail = 1
    
    for i in range(WNDSIZ - 1):
        mNext[i]  = i + 1
        
    mNext[WNDSIZ - 1] = 0
    
    for i in range(MAX_HASH_VAL+1):
        mNext[i] = 0


#Count the number of each code length for a Huffman tree
def InitPutBits():
    mBitCount = UINT8_BIT
    mSubBitBuf = 0


def HufEncodeStart():
    for i in range(NC):
        mCFreq[i] = 0
    
    for i in range(NP):
        mPFreq[i] = 0
        
    mOutputPos = mOutputMask = 0
    InitPutBits()


def UPDATE_CRC(a):
    mCrc = mCrcTable[(mCrc ^ (a)) & 0xFF] ^ (mCrc >> UINT8_BIT)
    return mCrc


#Read in source data
def FreadCrc(p:int,n:int) -> int:
    i = 0
    while mSrc < mSrcUpperLimit and i < n:
        p = mSrc
        p += 1
        mSrc += 1
        i += 1
    n = i
    
    p -= n
    mOrigSize += n
    while i - 1 >= 0:
        UPDATE_CRC(p)
        p += 1
    return n


#Insert string info for current position into the String Info Log
def InsertNode():
    
    if mMatchLen >= 4:
        mMatchLen -= 1
        r = (mMatchPos + 1) | WNDSIZ
        q = mParent[r]
        while q == 0:
            r = mNext[r]
        while mLevel[q] >= mMatchLen:
            r = q
            q = mParent[q]
        t = q
        while mPosition[t] < 0:
            mPosition[t] = mPos
            t = mParent[t]
        if t < WNDSIZ:
            mPosition[t] = mPos | PERC_FLAG
    else:
         q = mText[mPos] + WNDSIZ
         c = mText[mPos + 1]
         r = Child(q, c)
         if r == 0:
            MakeChild(q, c, mPos)
            mMatchLen = 1
            return
        mMatchLen = 2
        
    while True:
        if r >= WNDSIZ:
            j = MAXMATCH
            mMatchPos = r
        else:
            j = mLevel[r]
            mMatchPos = mPosition[r] & ~PERC_FLAG
        if mMatchPos >= mPos:
            mMatchPos -= WNDSIZ
        index1= mPos + mMatchLen
        t1 = mText[index1]
        index2 = mMatchPos + mMatchLen
        t2 = mText[index2]
        while mMatchLen < j:
            if t1 != t2:
                Split(r)
                return
            mMatchLen += 1
            index1 += 1 
            index2 += 1
        if mMatchLen >= MAXMATCH:
            break
        mPosition[r] = mPos
        q = r
        r = Child(q, t1)
        if r == 0:
            MakeChild(q, *t1, mPos)
            return
        mMatchLen +=1
        t = mPrev[r]
        mPrev[mPos] = t
        mNext[t] = mPos
        t = mNext[r]
        mNext[mPos] = t
        mPrev[t] = mPos
        mParent[mPos] = q
        mParent[r] = 0

        mNext[r] = mPos


#Advance the current position (read in new data if needed).
#Delete outdated string info. Find a match string for current position.
def GetNextMatch():
    mRemainder -= 1
    if mPos + 1 == WNDSIZ * 2:
        pass



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
            Output(LastMatchLen + UINT8_MAX + 1 - THRESHOLD,(mPos - LastMatchPos - 2) & (WNDSIZ - 1))
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