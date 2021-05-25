#!/bin/python

import sys
import re
import xlrd
import types

debug=1
class dumpdata:
    addrrange={'start':0, 'end':0}
    op_mode=['byte']
    data=[]
    size=0
    empty=1
    def __init__(self, startAddress):
        self.addrrange['start']=startAddress      
        self.addrrange['end']=startAddress
        self.size=0
        self.empty=1
    def append(self, data):
        self.data.append(data)
        self.addrrange['end']=self.addrrange['end']+1
        self.size=self.size+1
    def __getitem__ (self, key):
        if key >= self.addrrange['start'] and key < self.addrrange['end']:
            return self.data[key]
        else : 
            return None
    def __setitem__ (self, key, value):
        if key >= self.addrrange['start'] and key < self.addrrange['end']:
            self.data[key]=value
        else : 
            return None
    def get_start_addr(self):
        return self.addrrange['start']
    def get_end_addr(self):
        return self.addrrange['end']
    def dumpRange(self, start, end):
        for i in range(end-start):
         print format(self.data[start+i],'2x'), 
        print ""
    def dumpDword(self, start):
        dword=0
        for i in range(4):
            dword=self.data[start+i]<<24|(dword>>8)
        print format(dword,'0=8x')
        return format(dword,'0=8x')


    def dumpDwordBit(self, start):
        dword=0
        for i in range(4):
            dword=self.data[start+i]<<24|(dword>>8)

        print format(dword,'0=8x')
        for i in range(32):
          print "Addr[",start,"], bit[",31-i,"]", (dword&0x80000000)>>31
          dword=dword<<1

class dumpSection:
    start_address=0 
    dump_file=''
    #otp_fuse=None
    def __init__(self, filename):
        self.start_address=0
        self.dump_file=filename

    def set_startaddr(set, address):
        self.start_address=address

    def get_section(self, number):
        cur_num=0
        otp_fuse=dumpdata(self.start_address)
        f = open(self.dump_file, 'r')                   
        for line in f.readlines():                          
              line = line.strip() 
              address_data=line.split(':')  
              address='' 
              if re.match(r'([0-9a-fA-f]+)h$',address_data[0]):
                print 'match' 
                address=re.match(r'([0-9a-fA-f]+)h$',address_data[0])
              else:
                print "Not match"
                address=re.match(r'([0-9a-fA-f]+)$',address_data[0])
              if debug :
                print line
                print address_data[0] 
                print address 
              
              if address:
                print "Matched : the matched address is ", address.group(1)
                intaddr=int(address.group(1), 16)

                if intaddr == start_address :
                    cur_num=cur_num+1
        
                if cur_num == number:
                    print line
                    data=address_data[1].strip().split(' ')
                    if intaddr == otp_fuse.get_end_addr():
                        for item in data:
                            dlen=len(item)
                            if(dlen==2):
                                otp_fuse.append(int(item,16)) # 16-> Hex
                                #print otp_fuse[otp_fuse.addrrange['end']-1]
                            else:
                              ivalue=(int(item,16))
                              print hex(ivalue), dlen
                              while(dlen>0):
                                print hex(ivalue&0xff)
                                otp_fuse.append(ivalue&0xff)
                                ivalue=ivalue>>8
                                dlen=dlen-2

                                
                    #print hex(intaddr), data
        
        f.close()
        return otp_fuse
#       

#a=bits(2,1,1)

print sys.argv[1]
dump_file='Panaccess_dump1.log'
dump_file=sys.argv[1]
start_address=0
log_num=1
cur_num=0

print "EX: dump_parsing.py Panaccess_dump4.log"

mydump=dumpSection(dump_file)
otp_fuse=mydump.get_section(1)
print "End address is ",  otp_fuse.get_end_addr()
#otp_fuse=dumpdata(start_address)
#
#f = open(dump_file, 'r')                   
#for line in f.readlines():                          
#      line = line.strip() 
#      address_data=line.split(':')    
#      address=re.match(r'([0-9a-fA-f]+)h$',address_data[0])
#      if address:
#        #print address.group(1)
#        intaddr=int(address.group(1), 16)
#        if intaddr == start_address :
#            cur_num=cur_num+1
#
#        if cur_num == log_num:
#            print line
#            data=address_data[1].strip().split(' ')
#            if intaddr == otp_fuse.get_end_addr():
#                for item in data:
#                    otp_fuse.append(int(item,16))
#                    #print otp_fuse[otp_fuse.addrrange['end']-1]
#            #print hex(intaddr), data
#       

#otp_fuse.dumpRange(0, int('0x1f',16))
print "zone0, ChipID 0"       
chipID=otp_fuse.dumpDword(0)
print "zone1, ChipID 1"       
chipID=otp_fuse.dumpDword(1*4)+chipID
print 'chip ID = ', chipID
print "zone2, The chip configuration flag"       
otp_fuse.dumpDword(2*4)
print "zone3, OTP Configuration Register 1"       
otp_fuse.dumpDwordBit(3*4)
print "zone4, Root Public Key"       
otp_fuse.dumpRange(int('0x4',16)*4, int('0x4d',16)*4)
print "zone5, Secret key 0"       
otp_fuse.dumpRange(int('0x4d',16)*4, int('0x51',16)*4)
print "zone6, Secret key 1"       
otp_fuse.dumpRange(int('0x51',16)*4, int('0x55',16)*4)
print "zone7, Secret key 2"       
otp_fuse.dumpRange(int('0x55',16)*4,   int('0x59',16)*4)
print "zone8, Secret key 3"       
otp_fuse.dumpRange(int('0x59',16)*4,   int('0x5d',16)*4)
print "zone9, EJTAG key"       
otp_fuse.dumpRange(int('0x5d',16)*4,   int('0x5f',16)*4)

print "zone10, OTP Configuration Register 0(0x5F)"       
otp_fuse.dumpDwordBit(int('0x5f',16)*4)
print "zone11, Secret key 4"       
otp_fuse.dumpRange(int('0x60',16)*4,   int('0x64',16)*4)
print "zone12, Secret key 5"       
otp_fuse.dumpRange(int('0x64',16)*4,   int('0x68',16)*4)
print "zone13, Secret key 6"       
otp_fuse.dumpRange(int('0x68',16)*4,   int('0x6c',16)*4)
print "zone14, Secret key 7"  
otp_fuse.dumpRange(int('0x6c',16)*4,   int('0x70',16)*4)
print "zone15, Application dependent"  
otp_fuse.dumpRange(int('0x70',16)*4,   int('0x80',16)*4)

print "New added APP Zone"
print "APP zone0[80], APPZONE Write Protection"
otp_fuse.dumpDwordBit(int('0x80',16)*4)
print "APP zone0[81], APPZONE Read Protection"
otp_fuse.dumpDwordBit(int('0x81',16)*4)
print "APP zone0[82], IO control"
otp_fuse.dumpDwordBit(int('0x82',16)*4)
print "APP zone0[83], Video Function"
otp_fuse.dumpDword(int('0x83',16)*4)
print "APP zone1[84], Chip information"
otp_fuse.dumpDword(int('0x84',16)*4)
print "APP zone1[85], BL, Analog information"
otp_fuse.dumpDword(int('0x85',16)*4)
print "TCF Device ID low 32 bits"
otp_fuse.dumpDword(int('0x86',16)*4)
print "TCF Device ID high 32 bits"
otp_fuse.dumpDword(int('0x87',16)*4)
print "PVR R1 Key"
otp_fuse.dumpRange(int('0x88',16)*4,   int('0x8c',16)*4)
print "Public key for SEE ROM digital signature verification"
otp_fuse.dumpRange(int('0x90' ,16)*4,   int('0xd4',16)*4)
print "OTP obfuscation Key 1 "
otp_fuse.dumpRange(int('0xd4',16)*4,   int('0xd6',16)*4)

print "APP_ZONE [22] "
otp_fuse.dumpRange(int('0xd8',16)*4,   int('0xdc',16)*4)
print "APP_ZONE [23] "
otp_fuse.dumpRange(int('0xdc',16)*4,   int('0xe0',16)*4)
print "APP_ZONE [24] "
otp_fuse.dumpRange(int('0xe0',16)*4,   int('0xe4',16)*4)
print "APP_ZONE [25] "
otp_fuse.dumpRange(int('0xe4',16)*4,   int('0xe8',16)*4)
print "APP_ZONE [26] "
otp_fuse.dumpRange(int('0xe8',16)*4,   int('0xec',16)*4)
print "APP_ZONE [27] "
otp_fuse.dumpRange(int('0xec',16)*4,   int('0xf0',16)*4)
print "APP_ZONE [28] "
otp_fuse.dumpRange(int('0xf0',16)*4,   int('0xf4',16)*4)
print "APP_ZONE [29] "
otp_fuse.dumpRange(int('0xf4',16)*4,   int('0xf8',16)*4)
print "APP_ZONE [30] "
otp_fuse.dumpRange(int('0xf8',16)*4,   int('0xfc',16)*4)
print "APP_ZONE [31] "
otp_fuse.dumpRange(int('0xfc',16)*4,   int('0x100',16)*4)


