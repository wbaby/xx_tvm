from idaapi import *
import idc


HandleTableAdd = 0x1400DB5AA
HandleNum = 0xc8
DllBase = 0x140000000
V_RIP_Name = "[rbp+8]"
V_REG_P_Name = "r10"
HANDEL_END_Name = "jnb"
HANDEL_END_Name2 = "int"
NOP_Name = "nop"
V_END_Name = "retn"             
TRACK_MAX_LINE = 200            #最大跟踪行数

class TVMASM:
    Asm = 0
    Next = None
    def __init__(self,asm):
        self.Asm = asm

class TVMASMALL:
    DataHead = None
    Count = 0
    def insterASM(self,asm):
        ls = self.DataHead
        add = TVMASM(asm)
        add.Next = ls
        self.DataHead = add
        self.Count +=1
    
    def out(self):
        Cu = self.DataHead
        for i in range(self.Count):
            asm = Cu.Asm
            print(" %x "%asm,end="")
            Cu = Cu.Next
        print("\n")
        return
    
    def get(self,f):#从0开始
        if(f<=0 and f >= self.Count):
            return 0x00
        Cu = self.DataHead
        for i in range(f):
            Cu = Cu.Next
        return Cu.Asm
        
def GetNextRip(ea):
    if("jmp" in idc.GetDisasm(ea)):
        Type = idc.get_operand_type(ea,0)
        if(Type == o_reg):
            return 0
        Tage = idc.get_operand_value(ea,0)
        create_insn(Tage)
        return Tage
    else:
        return idc.find_code(ea,SEARCH_DOWN)

class TVMHANDLE:
    Offset = 0
    
    Next = None
    def __init__(self,Offset):
        self.Offset = Offset
        self.TvmHandleASM = TVMASMALL()
    
    def find(self,Offset):
        ls = self
        while ls is not None:
            if(ls.Offset == Offset):
                return ls
            ls = ls.Next
        return None
    
    def inster(self,Node):
        ls = self
        while ls.Next is not None:
            ls = ls.Next
        ls.Next = Node

    def Out(self):
        Cu = self
        while Cu is not None:
            if(Cu.Offset == 0):
                Cu = Cu.Next
                continue
            Add = DllBase + Cu.Offset
            print("%x :"%Add,end="")
            Cu.TvmHandleASM.out()
            Cu = Cu.Next
        return
    
    def OutTrackFileOne(self):
        #filename = "HandleTrack/"               #输出目录
        filename = hex(self.TvmHandleASM.get(0))
        filename = filename + ".txt"
        with open(filename, "w") as file:
            for i in range(self.TvmHandleASM.Count):
                file.write(hex(self.TvmHandleASM.get(i)))
                file.write(" ")
            file.write("\n\n----------------------------------------\n\n")
            End = 0
            line = 0
            Tage = self.Offset + DllBase
            create_insn(Tage)
            while 1:
                out = idc.GetDisasm(Tage)
                if(NOP_Name in out):
                    Tage = GetNextRip(Tage)
                    continue
                if(HANDEL_END_Name in out):
                    End = 1
                if(HANDEL_END_Name2 in out):
                    End = 1
                if(V_END_Name in out):
                    End = 1
                file.write(hex(Tage))
                file.write(" : ")
                file.write(out.ljust(40))
                file.write("\n")
                line +=1
                if(End == 1):
                    return
                Tage = GetNextRip(Tage)
                if(Tage == 0):
                    return 
                if(line >= TRACK_MAX_LINE):
                    print("error: %s"%filename)
        Tage = self.Offset + DllBase




TVMhandleTableHead = TVMHANDLE(0)
TVMHandleCount = 0


def main():
    Current = HandleTableAdd
    global TVMHandleCount
    for i in range(HandleNum):
        Current = HandleTableAdd+i*8
        find = TVMhandleTableHead.find(get_64bit(Current))
        if(None == find):
            find = TVMHANDLE(get_64bit(Current))
            TVMhandleTableHead.inster(find)
            TVMHandleCount +=1
        find.TvmHandleASM.insterASM((i+1)^0x5d)

    TVMhandleTableHead.Out()
    Tage = TVMhandleTableHead
    while Tage is not None:
        if(Tage.Offset == 0):
            Tage = Tage.Next
            continue
        Tage.OutTrackFileOne()
        Tage = Tage.Next


    return



if __name__ == "__main__":
    main()