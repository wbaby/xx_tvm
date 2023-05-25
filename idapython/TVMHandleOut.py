from idaapi import *
import idc
from unicorn import *
import capstone
import keystone
import idautils
import os
HEX2ASM = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
ASM2HEX = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)

HandleTableAdd = 0x1400db5aa
HandleNum = 0xc8
DllBase = 0x140000000
V_RIP_Name = "[rbp+8]"
V_REG_P_Name = "r10"
HANDEL_END_Name = "jnb"
HANDEL_END_Name2 = "int"
NOP_Name = "nop"
V_END_Name = "retn"             
TRACK_MAX_LINE = 200            #最大跟踪行数
REG = ["rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rflag"]

handleOutPath = "handleout"
os.makedirs(handleOutPath)

def memset(x, val, len):
    for i in range(len):
        patch_byte(x+i,val)

def memcpy(x,val,len):
    for i in range(len):
        patch_byte(x + i,val[i])

def setDword(num):
    mask = (1 << 32) - 1
    return num & mask

def nopInsn(Add):
    create_insn(Add)
    size = idautils.DecodeInstruction(Add).size
    memset(Add,0x90,size)
    return

class TVMASM:
    def __init__(self,asm):
        self.Asm = asm
        self.Next = None

class TVMASMALL:
    def __init__(self) -> None:
        self.DataHead = None
        self.Count = 0

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
            print(" %02x "%asm,end="")
            Cu = Cu.Next
        print("")
        return
    
    def get(self,f):#从0开始
        if(f<=0 and f >= self.Count):
            return 0x00
        Cu = self.DataHead
        for i in range(f):
            Cu = Cu.Next
        return Cu.Asm
        
class tvmFunTask:
    global_s_push = "push"
    global_s_jmp = "jmp"
    global_s_pop = "pop"
    global_s_mov = "mov"
    global_s_lea = "lea"
    global_s_add = "add"
    global_s_r11 = "r11"
    global_s_call = "call"
    global_s_ret = "retn"
    def __init__(self,FunStart,tvm0base):
        self.FunStart = FunStart
        self.VStart = 0             #r11
        self.tvm0base = tvm0base
        return
    
    def GetmovOrLea(self,add):
        s_reg = idc.print_operand(add,0)
        Tage = add
        isMov = False
        isLea = False
        for i in range(5):
            Tage = find_code(Tage,SEARCH_DOWN)
            cs = idc.GetDisasm(Tage)
            if(tvmFunTask.global_s_mov in cs):
                isMov = True
            if(tvmFunTask.global_s_lea in cs):
                isLea = True
            
            if(isMov == True and idc.print_operand(Tage,0) == s_reg):
                return Tage
            elif(isLea == True and idc.print_operand(Tage,0) == s_reg):
                return Tage
            else:
                continue
        return False

    def GetJmpAdd(self,add):
        s_reg = idc.print_operand(add,0)
        Tage = add
        isJmp = False
        for i in range(10):
            Tage = idc.find_code(Tage,SEARCH_DOWN)
            cs = idc.GetDisasm(Tage)
            if(tvmFunTask.global_s_jmp in cs):
                isJmp = True
            if(isJmp == True and idc.print_operand(Tage,0) == s_reg):
                return Tage
            else:
                continue
        return False

    def GetTrueAdd(self,add):
        s_reg = idc.print_operand(add,0)
        cs = idc.GetDisasm(add)
        isMov = False
        isLea = False
        ass = idc.get_operand_value(add,1)
        if(tvmFunTask.global_s_mov in cs):
            isMov = True
        if(tvmFunTask.global_s_lea in cs):
            isLea = True
        Tage = add
        if(isMov==True):
            for i in range(5):
                Tage = find_code(Tage,SEARCH_DOWN)
                if(tvmFunTask.global_s_add in idc.GetDisasm(Tage) and s_reg in idc.print_operand(add,0)):
                    return ass + idc.get_operand_value(Tage,1)
        elif(isLea == True):
            for i in range(5):
                Tage = find_code(Tage,SEARCH_DOWN)
                if(tvmFunTask.global_s_lea in idc.GetDisasm(Tage) and s_reg in idc.print_operand(add,0)):
                    return ass + idc.get_operand_value(Tage,1)
        return False

    def setQword(self,num):
        mask = (1 << 64) - 1
        return num & mask
   
    def getBlockStartandEnd(self,add):
        block_start = get_func(add).start_ea
        for item in FlowChart(get_func(block_start)):
            if item.start_ea <= add <= item.end_ea:
                block_start = item.start_ea
                break
        block_end = get_func(add).end_ea
        for item in FlowChart(get_func(block_end)):
            if item.start_ea <= add <= item.end_ea:
                block_end = item.end_ea
                break
        return block_start,block_end

    def find_next_insn(self,add):
        Tage = find_code(add,SEARCH_DOWN)
        if(tvmFunTask.global_s_push in idc.GetDisasm(Tage)):
            movOrlea = self.GetmovOrLea(Tage)
            movOrlea = self.setQword(movOrlea)
            if(movOrlea == False):
                return Tage
            JmpAdd = self.GetJmpAdd(Tage)
            JmpAdd = self.setQword(JmpAdd)
            if(JmpAdd == False):
                return Tage
            TrueAdd = self.GetTrueAdd(movOrlea)
            TrueAdd = self.setQword(TrueAdd)
            if(TrueAdd == False):
                return Tage
            create_insn(TrueAdd)
            return find_code(TrueAdd,SEARCH_DOWN)
        return Tage

    def mabe_3_4(self,add):
        Tage = add
        if(tvmFunTask.global_s_push in idc.GetDisasm(Tage)):
            movOrlea = self.GetmovOrLea(Tage)
            movOrlea = self.setQword(movOrlea)
            if(movOrlea == False):
                return Tage
            JmpAdd = self.GetJmpAdd(Tage)
            JmpAdd = self.setQword(JmpAdd)
            if(JmpAdd == False):
                return Tage
            TrueAdd = self.GetTrueAdd(movOrlea)
            TrueAdd = self.setQword(TrueAdd)
            if(TrueAdd == False):
                return Tage
            create_insn(TrueAdd)
            size = find_code(JmpAdd,SEARCH_DOWN)-Tage
            memset(Tage,0x90,size)
            
            size = find_code(TrueAdd,SEARCH_DOWN)-TrueAdd
            memset(TrueAdd,0x90,size)

            str = "jmp " + hex(TrueAdd)
            HEX,_ = ASM2HEX.asm(str,addr=Tage)
            memcpy(Tage,HEX,HEX.__len__())

            return 
        return 
    
    def mabe_1(self,add):
        not_reg = idc.print_operand(add,0)
        xchg_1_add = self.find_next_insn(add)
        xchg_1_disasm = idc.GetDisasm(xchg_1_add)
        if("xchg" not in xchg_1_disasm or not_reg not in xchg_1_disasm):
            return
        True_reg = idc.print_operand(xchg_1_add,0)
        if(True_reg == not_reg):
            True_reg = idc.print_operand(xchg_1_add,1)
        mov_add = self.find_next_insn(xchg_1_add)
        mov_disasm = idc.GetDisasm(mov_add)
        if("mov"not in mov_disasm or  not_reg not in mov_disasm):
            return
        not_2_add = self.find_next_insn(mov_add)
        not_2_disasm = idc.GetDisasm(not_2_add)
        if("not"not in not_2_disasm or True_reg != idc.print_operand(not_2_add,0)):
            return
        xchg_2_add = self.find_next_insn(not_2_add)
        xchg_2_disasm = idc.GetDisasm(xchg_2_add)
        if("xchg" not in xchg_2_disasm or True_reg not in xchg_2_disasm or not_reg not in xchg_2_disasm):
            return
        dis = HEX2ASM.disasm_lite(get_bytes(mov_add,idautils.DecodeInstruction(mov_add).size),mov_add)
        insnInfo = None
        for insn in dis:
            insnInfo = insn
        czs = insnInfo[3]
        p = czs[:czs.find(not_reg)]
        s = czs[czs.find(not_reg)+len(not_reg):]
        asm = insnInfo[2] + " " + p + True_reg + s
        HEX,_ = ASM2HEX.asm(asm,addr=mov_add)
        nopInsn(add)
        nopInsn(xchg_1_add)
        nopInsn(mov_add)
        nopInsn(not_2_add)
        nopInsn(xchg_2_add)
        memcpy(mov_add,HEX,HEX.__len__())

    def mabe_2(self,add):
        xchg_1_add = add
        xchg_1_disasm = idc.GetDisasm(xchg_1_add)
        mov_add = self.find_next_insn(xchg_1_add)
        mov_disasm = idc.GetDisasm(mov_add)
        if("mov" not in mov_disasm):
            return
        not_1_add = self.find_next_insn(mov_add)
        not_1_disasm = idc.GetDisasm(not_1_add)
        if("not"not in not_1_disasm):
            return
        xchg_2_add = self.find_next_insn(not_1_add)
        xchg_2_disasm = idc.GetDisasm(xchg_2_add)
        if("xchg"not in xchg_2_disasm):
            return
        not_2_add = self.find_next_insn(xchg_2_add)
        not_2_disasm = idc.GetDisasm(not_2_add)
        if("not" not in not_2_disasm):
            return
        dis = HEX2ASM.disasm_lite(get_bytes(mov_add,idautils.DecodeInstruction(mov_add).size),mov_add)
        insnInfo = None
        for insn in dis:
            insnInfo = insn
        czs = insnInfo[3]
        True_reg = idc.print_operand(not_2_add,0)
        not_reg = idc.print_operand(not_1_add,0)
        if(True_reg not in xchg_1_disasm or not_reg not in xchg_1_disasm):
            return
        if(not_reg not in mov_disasm or not_reg not in xchg_2_disasm):
            return
        if(True_reg not in xchg_2_disasm):
            return
        p = czs[:czs.find(not_reg)]
        s = czs[czs.find(not_reg)+len(not_reg):]
        asm = insnInfo[2] + "  " + p + True_reg + s
        try:
            HEX,_ = ASM2HEX.asm(asm,addr=mov_add)
        except:
            print("error!  %s"%asm)
            HEX,_ = ASM2HEX.asm(asm,addr=mov_add)    
        nopInsn(xchg_1_add)
        nopInsn(mov_add)
        nopInsn(not_1_add)
        nopInsn(xchg_2_add)
        nopInsn(not_2_add)
        memcpy(mov_add,HEX,HEX.__len__())

test = tvmFunTask(0,0)

class TVMHANDLE:
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
    
    def find_next_code(self,Add):
        if("jmp" in idc.GetDisasm(Add)):
            return idc.get_operand_value(Add,0)
        return find_code(Add,SEARCH_DOWN)

    def OutTrackFileOne(self):
        filename = hex(self.TvmHandleASM.get(0))
        filename = handleOutPath + "/" + filename + ".txt"
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
                    Tage = self.find_next_code(Tage)
                    continue
                if("not" in out):
                    test.mabe_1(Tage)
                if("xchg" in out):
                    test.mabe_2(Tage)
                if("push" in out):
                    test.mabe_3_4(Tage)
                create_insn(Tage)
                out = idc.GetDisasm(Tage)    
                if(NOP_Name in out):
                    Tage = self.find_next_code(Tage)
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
                Tage = self.find_next_code(Tage)
                if(Tage == 0):
                    return 
                if(line >= TRACK_MAX_LINE):
                    print("error: %s"%filename)
                    return 

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
    print("%d"%TVMHandleCount)
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