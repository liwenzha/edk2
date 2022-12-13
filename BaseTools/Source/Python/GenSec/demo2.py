from ctypes import *
# class EFI_COMMON_SECTION_HEADER(Structure):
#     _pack_ = 1
#     _fields_ = [
#         ('Size',                     ARRAY(c_uint8, 3)),
#         ('Type',                     c_uint8),
#     ]
        
#     @property
#     def SECTION_SIZE(self) -> int:
#         return self.Size[0] | self.Size[1] << 8 | self.Size[2] << 16
    
#     #@property 
#     def SET_SECTION_SIZE(self,size):
#         self.Size[0] = size & 0xff
#         self.Size[1] = (size & 0xff00) >> 8
#         self.Size[2] = (size & 0xff0000) >>16

#     def Common_Header_Size(self) -> int:
#         return 4

# with open("text.txt","rb") as input:
#     data = input.read()
# TotalLength = len(data)
# CommonSect = EFI_COMMON_SECTION_HEADER()
# CommonSect.SET_SECTION_SIZE(TotalLength)
# #print(CommonSect.Size[0])
# # print(CommonSect.Size[1])
# # print(CommonSect.Size[2])
# a = c_uint32(CommonSect.Size)
# print(a)


# a = 'abc'

# # print(len(a))
# # print(type(ch[0]))

# def Ascii2UnicodeString(String:str):
#     unistr = ''
#     Enc = String.encode()
#     for ch in Enc:
#         unistr += str(ch)
#     return unistr

# print(int((Ascii2UnicodeString(a)),16))


a = 97
a = hex(a)
print(a)