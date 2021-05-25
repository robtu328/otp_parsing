#!/bin/python

import sys
import os
import re
import xlrd
import types
import StringIO
import getopt

debug = 0

class readLookUp:
    def __init__(self):
        return 
    def readDict(self, h, w):
        return

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
          #print hex(self.data[start+i]),
          print format(self.data[start+i],'2x'),
        print ""
    def dumpDword(self, start):
        dword=0
        for i in range(4):
            dword=self.data[start+i]<<24|(dword>>8)
        #print hex(dword)    
        print format(dword,'2x')    

    def dumpDwordBit(self, start):
        dword=0
        for i in range(4):
            dword=self.data[start+i]<<24|(dword>>8)

        print hex(dword)    
        for i in range(32):
          print "Addr[%d], bit[%2d], %d" %(start, 31-i, (dword&0x80000000)>>31)
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
              address=re.match(r'([0-9a-fA-f]+)h$',address_data[0])
              if address:
                #print address.group(1)
                intaddr=int(address.group(1), 16)
                if intaddr == self.start_address :
                    cur_num=cur_num+1
        
                if cur_num == number:
                    if debug :
                        print line
                    data=address_data[1].strip().split(' ')
                    if intaddr == otp_fuse.get_end_addr():
                        for item in data:
                            otp_fuse.append(int(item,16))
                            #print otp_fuse[otp_fuse.addrrange['end']-1]
                    #print hex(intaddr), data
        
        f.close()
        return otp_fuse
#       



class opensslWrapper:
    header=[0, 8, 0, 0]
    key=[]
    keysize=0
    exponent=[0]*32
    filename=''
    command=''

    def __init__(self, filename):
        keyRegion=False
        ExpRegion=False

        self.header=[0, 8, 0, 0]
        self.key=[]
        self.keysize=0
        self.exponent=[0]*32
        self.filename=filename
        self.command='openssl rsa -pubin -inform PEM -text -noout < '+self.filename
        #msg=os.system(self.command)
        msg=os.popen(self.command).read()
        buf=StringIO.StringIO(msg)
        for line in buf.readlines():
            if not keyRegion and not ExpRegion:
                text=re.match(r'^Public-Key: \((\d{4}) bit\)$', line)
                if text:
                    self.keysize=int(text.group(1))
                text=re.match(r'^Modulus:$', line)
                if text:
                    keyRegion=True
            elif keyRegion:
                mylist=line.strip().split(":")
                if mylist[0]=='Exponent':
                    string=mylist[1].strip().split(" ")
                    value=int(string[0])
                    index=31
                    while True:
                      self.exponent[index]=value&255
                      value=value>>8
                      index=index-1
                      if value==0:
                        break
                else :     
                    for element in mylist:
                        if element:
                            self.key.append(int(element,16))

        del self.key[0]

          #else :

        
#    def run(self):
        
    def get_key(self):
        return self.header+self.key+self.exponent
    def disp_key(self):
        for i in (self.header+self.key+self.exponent):
            print format(i,'2x'),
        print ""
    def get_exp(self):
        return self.exponent
    def get_header(self):
        return self.header



class bits:
    bitrange=None
    data=[]
    mask=0
    max_value=0
    description=''
    setSize=0
    owner='ali'
      
    def __init__(self, bit_range,zone='0', value=[0], description='', cpurw='R/W',seerw='R/W', owner='ali'):
        self.bitrange=bit_range
        self.data=[]
        self.mask=1<<self.bitrange['start']
        self.owner=owner
        self.indexmap={}
        if self.bitrange['start'] > self.bitrange['end']:
          self.data=None
          return
        
        self.max_value=1
        for i in range(self.bitrange['end']-self.bitrange['start']):
          self.mask=self.mask<<1 | 1<<self.bitrange['start'] 
          self.max_value=self.max_value<<1 | 1

        self.description=description
        #print "bit, check value -> ", value   
        if value:
            value = [int(item, 2) for item in value]
            self.setSize = len(value)
            for item in value:
                item=int(item)
                #print "value ->", item, " max_value->", self.max_value 
                if int(item) > self.max_value:
                    self.data=None
                    #print "ERROR!!!!"
                    return
                self.data.append(item)
            #self.data=value 
        #else:
            #value <=[0]
    def set_description(text):
        self.description=text        

    def get_description():
        return self.description

    def display(self):
        #print self.bitrange, self.data, format(self.mask,'x'), self.max_value, self.description
        print self.bitrange, self.data, format(self.mask,'x'), self.max_value, self.owner


class addr_map:
    listSize=0
    setSize=1
    addrmap=[]
    indexmap={}    
    address=None
    index=0
    def __init__(self):
        self.setSize=1
        self.listSize=0
        self.addrmap=[]
        self.address=None
        self.index=0
    def reset_index(self):
        self.index=0

    def pop_up(self):
        self.index=self.index+1
        if self.index > len(self.addrmap):
            return None
        else:
            return self.addrmap[self.index-1]
    def add(self, addr, value, zone='0'):
        if hasattr(value, "setSize") and value.setSize > self.setSize:
            self.setSize= value.setSize
            
        if self.address == None:
            self.address=addr
            self.addrmap.append(value)
        else:
            if self.address == addr:
                self.addrmap.append(value)
                return False
        self.listSize=self.listSize+1
        return True
    def getdefault(self, owner="ali"):
        if not self.addrmap:
            return False
        default=[]
        if not self.addrmap:
            return False

        if not hasattr(self.addrmap[0], "bitrange") :     #address set, not class bits
            return self.addrmap[0].data
        else:
            for count in range(self.setSize):
                itemp=0
                for item in self.addrmap:
                    if owner == item.owner or owner== "all":
                        if item.setSize == 1:
                            #print "item data", item.data[0]
                            itemp=itemp | item.data[0] <<item.bitrange['start'] 
                        elif item.setSize == self.setSize:
                            itemp=itemp | item.data[count]<<item.bitrange['start'] 
                        
                default.append(itemp)
            return default               
    def display(self):
        for i in self.addrmap:
            if isinstance(i, bits):
                i.display()
            else:
                print i
    def reset(self):
        addrmap=[]
        address=None
        #element={'addr':addr, 'value':value}
        #print "element ", element
        #self.addrmap.append(element)
    def set_check(self, bitrange, value, owner='aprd'):
        if not self.addrmap:
            return False

        if not hasattr(self.addrmap[0], "bitrange") :     #address set, not class bits
            return self.addrmap[0].data
        else:
            for item in self.addrmap:
                if item.bitrange == bitrange:
                    item.owner=owner
                    if item.data:
                        item.data[0]=value
                        item.setSize=1
                    else:
                        item.data.append(value)
                        
        return True
    def report_by_value(self, value):
        if not self.addrmap:
            return False

        if not hasattr(self.addrmap[0], "bitrange") :     #address set, not class bits
            return self.addrmap[0].data
        else:
            for item in self.addrmap:
                trim=(value & item.mask) >> item.bitrange['start']
                print "Description ", item.description, ", value  ", trim, ", mask = ", format(item.mask,'x')
        return True
    def report_difference(self, value, owner): 
        ownerlist=owner.split('+')
        if not self.addrmap:
            return False

        if not hasattr(self.addrmap[0], "bitrange") :     #address set, not class bits
            return self.addrmap[0].data
        else:
            for item in self.addrmap:
                trim=(value & item.mask) >> item.bitrange['start']
                if item.owner in ownerlist:
                    if trim != item.check:
                        print "Mismatch"
                else:
                    if trim != 0:
                        print "Mismatch"
                print "Description ", item.description, ", value  ", trim, ", mask = ", format(item.mask,'x')
        return True
    def create_index(self):
        self.indexmap={}
        for i in self.addrmap:
            if i.description.lower() != 'resvd':
                self.indexmap[i.description]=i
        return self.indexmap
        
    def get_index(self):
        return self.indexmap
 
class addr_list:
    addrlist=[]
    index=0
    def __init__(self):
        self.index=0
    def reset_index(self):
        index=0
    def len(self):
        return len(self.addrlist)
    def pop_up(self):
        self.index=self.index+1
        if self.index > len(self.addrlist):
            return None
        else:
            return self.addrlist[self.index-1]
    def add(self, item):
        self.addrlist.append(item)

        return
    def get_one(self, addr):
        for item in self.addrlist:
            if item.address.has_key('end'):
                if addr >= item.address['start'] and addr <= item.address['end']:
                    return item
            else:
                if addr == item.address['start']:
                    return item
        return False

    def replace_one(self, addr, new):
    
        for index, item in enumerate(self.addrlist):
            if addrlist[0]:
                return
    def sort(self, a):

        return


def is_number(text):
    hexstr=re.match(r'^0x([A-Fa-f0-9]+$)', text)
    decstr=re.match(r'\d+$',text)
    if hexstr :
        return int(hexstr.group(1),16)
    elif decstr:
        return int(text)
    else :
        return None

# Analysis address field, format = 0x0, 0x04 ~ 0x4C, return {'start':{num}, 'end':{num}}
def analyze_address(cell):
    start=-1
    end=-1
    cell_string=re.sub(r'\n',' ',cell)
    cell_string=cell_string.strip()
    addr_range=cell_string.split('~')
    addr_range[0]=addr_range[0].strip()
    start=is_number(addr_range[0])
    if len(addr_range) > 1:
        addr_range[1]=addr_range[1].strip()
        end=is_number(addr_range[1])
    
    #print start, end 
    addr={}
    if start !=None:
        addr['start']=start

    if end != -1 and end !=None:
        addr['end']=end

    return addr


#Analysis bit range, format bit[31:0], or [31:0], returen  {'start':{num}, 'end':{num}}
def analyze_range(cell):
    start=-1
    cell_string=re.sub(r'\n',' ',cell)
    cell_string=cell_string.strip().lower()
    text=re.match(r'bit\s*\[([\d:]+)]', cell_string)
    if not text:
        text=re.match(r'\[([\d:]+)]', cell_string)
        if not text :
            return None
    bit_range=text.group(1).split(':')
    bit_range[0]=bit_range[0].strip()
    end=is_number(bit_range[0])
    if len(bit_range) > 1:
        bit_range[1]=bit_range[1].strip()
        start=is_number(bit_range[1])
    
    #print start, end 
    addr={}
    addr['end']=end
    if start == -1:
        addr['start']=end
    else:
        addr['start']=start

    return addr

#analysis bitlength column
def analyze_bitlength(cell):
    start=-1
    end=-1
    cell_string=re.sub(r'\n',' ',cell)
    cell_string=cell_string.strip().lower()
    text=re.match(r'(\d+)\s*bit[s]?', cell_string)
    #print "bitlength ", cell, " ", text.group(1)
    if not text:
        return None
    length=int(text.group(1).strip())
    return length

#analysis value in check 
def analyze_value(cell):
    start=-1
    end=-1
    cell_string=re.sub(r'\n',' ',cell)
    cell_string=cell_string.strip().lower()

    #text=re.findall(r'([Vv]\(?[01]?\)?)', cell)   ####BUG?
    text=re.findall(r'([Vv]\(?[01]{1,}\)?)', cell)
    if debug:
        print "check value", cell, " ", text

    if not text:
        return None
    check=[]
    for i in text:
      value=re.match(r'[Vv]\((\s*\d{1,}\s*)\)', i)
      if debug :
        print "analyze_value", value, "group(1)=", value.group(1)
      if value:
        value=value.group(1).strip()
        if debug:
            print "analyze_value", value
        check.append(value)
      
    return check


def analyze_part_number(part_number):

    cell_string=re.sub(r'\n',' ',part_number)
    cell_string=cell_string.strip().upper()
    text=re.match(r'^(M\d{4}\w?)[_-](\w{4,5})[_-](\w{4})$', cell_string)
    print text.group(1).strip(), "_", text.group(2).strip(),"_", text.group(3).strip()
      



class otp_table:
    all_addrmap=None
    spreadsheet_name=''
    table_name=''
    workbook=''
    worksheet=''
    lu=[0,0]
    ld=[0,0]
    ru=[0,0]
    rd=[0,0]
    lu_sent='OTP Address'
    ru_sent='Zone'
    column_name=''
#    column_name={'address':'otp address',
#                 #'range':'content',   #C3503, C3281
#                 'range':'bits',       #C3821, C3921
#                 'length':'bit length',
#                 #'ali_set':'set by ali',
#                 'ali_set':'set by ali for cp', #M3527
#                 #'mfg_set':'set by customer',
#                 #'mfg_set':'set by stbm',
#                 #'mfg_set':'set by stb mfg',    #M3823, M3733
#                 'mfg_set':'set by stbm for cp',    #M3527
#                 'description':'description',
#                 'cpu':'cpu',
#                 'see':'see',
#                 'zone':'zone'}
#


    def __init__(self, spreadsheet, table, columnName):
        self.lu=[0,0]
        self.ld=[0,0]
        self.ru=[0,0]
        self.rd=[0,0]
        self.spreadsheet_name=spreadsheet
        self.table_name=table
        #Call Excel access library
        self.workbook=xlrd.open_workbook(self.spreadsheet_name)
        self.worksheet=self.workbook.sheet_by_name(self.table_name)
        self.column_name = columnName

    def set_lu_sentence(self, sent):
        self.lu_sent=sent
            
    def set_ru_sentence(self, sent): 
        self.ru_sent=sent
    def set_column_name(self, name):
        self.column_name=name

    def parse(self):
        found_lu=0
        num_rows = self.worksheet.nrows
        num_colum = self.worksheet.ncols
        #Identif worksheet boundary by keyword lu_sent, ru_sent
        if debug :
          print "num_colum =", num_colum
        for w in (range(num_colum)):
            for h in (range(num_rows)):
                cell_value=self.worksheet.cell_value(h,w)
                cell_string=re.sub(r'\n',' ',cell_value)
                cell_string=cell_string.strip()
                if cell_string.lower() == self.lu_sent.lower():
                    if debug:
                        print w, "  ", h
                    self.lu=[h,w]
                    found_lu=True
                    break
            if(found_lu==True):
                break
        for w in (range(num_colum)):
            cell_value=self.worksheet.cell_value(self.lu[0],w)
            cell_string=re.sub(r'\n',' ',cell_value)
            cell_string=cell_string.strip()
            if cell_string.lower() == self.ru_sent.lower():
                if debug :
                    print w
                self.ru=[self.lu[0],w]
                break

        for h in (range(self.lu[0], num_rows)):
            cell_value=self.worksheet.cell_value(h,self.lu[1])
            if cell_value.lower() == '':
                self.ld=[h,self.lu[1]]
                break
        self.rd=[self.ld[0], self.ru[1]]
        if debug:
            print "\n\nExcel Boundary"
            print "Upper Left =", self.lu
            print "Upper Right=", self.ru
            print "Down  Left =", self.ld
            print "Down  Right=", self.rd
        
        
        #interested column identification
        column_index={}
        if debug:
          print "\n\nColumn Strings Parsing"
        
        for w in (range(self.lu[1], self.ru[1]+1)):
            cell_value=self.worksheet.cell_value(self.lu[0],w)
            cell_string=re.sub(r'\n',' ',cell_value)
            #print cell_string
              
            cell_string=cell_string.strip()
            for tag in self.column_name.keys():
            #print cell_string.lower(), " ", tag," ", column_name[tag]
                if cell_string.lower() == self.column_name[tag]:
                    column_index[tag]=w
                    if debug:
                        print tag, " = ", column_index[tag]
                           
        self.lu=[self.lu[0]+1, self.lu[1]]
        self.ru=[self.ru[0]+1, self.ru[1]]
        if debug :
          print "first row =", self.lu[0], " last_row= ", self.ld[0]
        pre_addr={'start':-1}
        new_addr=None
        self.all_addrmap=addr_list()
        #Parse interested fields in each row.  
        for h in (range(self.lu[0], self.ld[0])):
            cellString= self.worksheet.cell_value(h,column_index['description'])
            cellString=re.sub(r'\n',' ',cellString)
            cellString=cellString.encode('ascii','replace')
            SAli=False
            SStb=False
            cell_value=self.worksheet.cell_value(h,column_index['address'])
            #print cell_value
            addr=analyze_address(cell_value)
            if debug:
                print "addr ", addr


            cell_value=self.worksheet.cell_value(h,column_index['range'])
            #print cell_value
            bit_range=analyze_range(cell_value)
            if debug:
                print "bit_range ", bit_range


            cell_value=self.worksheet.cell_value(h,column_index['length'])
            #print cell_value
            length=analyze_bitlength(cell_value)


            cell_value=self.worksheet.cell_value(h,column_index['ali_set'])
            #print cell_value
            final_check=[]
            owner=None
            check=analyze_value(cell_value)
            if check!=None:
                SAli=True
                owner='ali'
                final_check=check
                #print "ALi Check ", check


            cell_value=self.worksheet.cell_value(h,column_index['mfg_set'])
            #print cell_value
            check=analyze_value(cell_value)
            if check!=None:
                SStb=True
                owner='stb'
                final_check=check

            if debug:
                print "Owner = ", owner
             
            cell_value=self.worksheet.cell_value(h,column_index['zone'])
            if cell_value!='':
                #zone=int(cell_value)
                zone=str(cell_value)
             #   print "Zone", int(cell_value) 
            
            partial_addr=None
            
            if debug :
                print addr, " ", pre_addr, " range", bit_range
            if addr == pre_addr :   # same as previous, new_addr should be created already
                partial_addr=bits(bit_range,zone,final_check,cellString, "R/W", "R/W", owner) # no need to keep
                #partial_addr.display()
                #print "insert one, same addr, partial" 
                new_addr.add(addr, partial_addr)    
                #new_addr.display()
            else:
                if new_addr != None:
                    #new_addr.display()
                    #print "New addr, save old"
                    self.all_addrmap.add(new_addr)
                #print "New new_addr" 
                new_addr=addr_map()     #Save to all_adrmap, renew it

                if addr.has_key('end') or length==32  : #full, check if new_addr None or not, 
                    #print "insert to new_addr->full 32 bit, or multiple addr"
                    tmpstring=self.worksheet.cell_value(h,column_index['description'])
                    tmpstring=tmpstring.encode('ascii','ignore')
                    new_addr.add(addr, tmpstring)
                     
                    #new_addr.add(addr, self.worksheet.cell_value(h,column_index['description']))
                    #print "insert to all_addrmap-> bit length=32 or addr range" 
                    #if addr['start'] < 3:
                    #    new_addr.display()
                    self.all_addrmap.add(new_addr)
                    new_addr=None

                else:               # partial, no add all_addrmap.
                    if debug :
                        print "First bit in the same address"
                    partial_addr=bits(bit_range,zone,final_check, cellString, "R/W", "R/W", owner) # no need to keep
                    #partial_addr.display()
                    #print "insert to new_addr[diff addr]->partial",
                    #print addr, "bitrange", partial_addr.bitrange 
                    new_addr.add(addr, partial_addr)
                    #new_addr.display()
                #new_addr=addr_map
            if debug:
                print "****************************************"    
            pre_addr=addr

    def return_map(self): 
            return self.all_addrmap 
        
        
def save_csv(otplist):
    print "Fuse-nr;bit-index;size;value;mask;comparison-mask;mode;"
    while True:
        element=otplist.pop_up()    #Go through each address
        if element==None:
            break
        else:
            if len(element.address)==1:
                #print "address",element.address['start'], 
                #element.display()
                element1=element.pop_up()
                if hasattr(element1, 'bitrange'):
                    print hex(element.address['start']).rstrip("L"),';',   #addr      
                    print element1.bitrange['start'],';',      #bit-index
                    print (element1.bitrange['end']-element1.bitrange['start'])+1,';', #size
                    if len(element1.data)!=0:
                        print hex(element1.data[0]<<int(element1.bitrange['start'])).rstrip("L"),';', #mask
                    else:
                        print ";",
                    print hex(element1.mask).rstrip("L"),';',              #mask
                    print hex(element1.mask).rstrip("L"),';',              #compare mask
                    print 'X',';'
                    #element1.display()
                    while True:
                      element1=element.pop_up()
                      if element1==None:
                        break
                      print hex(element.address['start']).rstrip("L"),';',   #addr      
                      print element1.bitrange['start'],';',      #bit-index
                      print (element1.bitrange['end']-element1.bitrange['start'])+1,';', #size
                      if len(element1.data)!=0:
                        print hex(element1.data[0]<<int(element1.bitrange['start'])).rstrip("L"),';', #mask
                      else:
                        print ";",
                      print hex(element1.mask).rstrip("L"),';',              #mask
                      print hex(element1.mask).rstrip("L"),';',              #compare mask
                      if  len(element1.data)==0:
                        print '-',';'
                      elif element.address['start']==3 and  element1.bitrange['start']==1:
                        print 'S',';'
                      elif element.address['start']==0x3 and  element1.bitrange['start']==25:
                        print 'J',';'
                      elif element.address['start']==0xdd and  element1.bitrange['start']==2:
                        print 'J',';'
                      elif element.address['start']==3 and  element1.bitrange['start']==30:
                        print 'P',';'
                      elif element.address['start']==0xdd and  element1.bitrange['start']==3:
                        print 'P',';'
                      else:
                        print 'X',';'
                        
                      #element1.display()
                else:
                  #print "string", 
                  print hex(element.address['start']),';',   #addr
                  if(element.address['start']==2):
                    print '0;32;;0xffffffff;0xffffffff;M;'
                  else:
                    print '0;32;;0xffffffff;0xffffffff;-;'

            else:
                #print "address",element.address['start'], " ",element.address['end'] 
                for i in range(element.address['start'], element.address['end']+1):
                    print hex(i),';',   #addr                                                          
                    print '0;32;;0xffffffff;0x00000000;-;'



       

if __name__ == '__main__':
    
    args = sys.argv[1:]
    optlist,args = getopt.getopt(args, 'i:t:d:g')
    InputFile = 'OTP Table_full.xlsx'
    Tabname = 'OTP Table'
    CfgName = 'otptable.cfg'
    DumpFile =''
    column_name={'address':'otp address',
                 'range':'bits',       
                 'length':'bit length',
                 'ali_set':'set by ali for cp', 
                 'mfg_set':'set by stbm for cp',    
                 'description':'description',
                 'cpu':'cpu',
                 'see':'see',
                 'zone':'zone'}

    column_tmp={}

    for o, a in optlist:
#        print o
        if o == "-i":
            InputFile = a
        elif o in ("-t"):
            Tabname = a
        elif o in ("-d"):
            DumpFile = a
        elif o == "-g":
            debug = 1
        else:
           print "Use Pre-define File name and tab name"

    if debug:
        print "*********************************************************************************"
        print "**************                Config file  Parse       **************************"
        print "*********************************************************************************"
    readFile = open(CfgName, 'r')
    stringInput = 'start'
    
    while len(stringInput):
        stringInput = readFile.readline()
    	stringList=stringInput[:-1].split('=')
        for i in range(len(stringList)):
          stringList[i]=stringList[i].strip()

        if debug :
            print stringList

    	if stringList == ['']:
    	    break 
    	if stringList[0][0]=='#' or stringList[0][0]=='*' or len(stringList)!= 2:
    		continue
    	else :
            column_tmp[stringList[0]]=stringList[1]
    readFile.close()
    
    if debug : 
        print column_tmp
    column_name=column_tmp 

    
    if debug : 
        print "*********************************************************************************"
        print "**************                Excel Parse              **************************"
        print "*********************************************************************************"
        print "Filename = ", InputFile, " Table Name = ", Tabname  

                                                                                                                                                 
    
    
    
    #mytable=otp_table('OTP Table_full.xlsx', 'OTP Table')
    mytable=otp_table(InputFile, Tabname, column_name)
    mytable.parse()
    all_addrmap=mytable.return_map()
    
    addr_3 = all_addrmap.get_one(3)
    bitrange={}
    bitrange['start']=28
    bitrange['end']=28
    
    print ""
    #print addr_3.display()
    default_addr_3=addr_3.getdefault('ali')
    
    
    for item in default_addr_3:
        print "A ddress 3 default value : ", format(item, 'x'),
    
  
   
    addr_82= all_addrmap.get_one(int(0x82))
                
    print   
                             
    print addr_82
    #addr_81.display()
    #default_addr_80=addr_82.getdefault('ali')
    #for item in default_addr_80:
    #    print "A ddress 81 default value : ", format(item,'x'),
                                              
    print "END"
                                                                                                               
 



    if os.path.isfile('PCAM_RSA_Root_Pub_Key_M3281.PEM'):
        publickey=opensslWrapper('PCAM_RSA_Root_Pub_Key_M3281.PEM')
        publickey.disp_key()
   
        #publickey=opensslWrapper('Public_ALi_M3515_key0.PEM')
        #publickey.disp_key()
        

