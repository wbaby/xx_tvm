from idaapi import *
import idc
from unicorn import *
import capstone
import keystone
import idautils
HEX2ASM = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
ASM2HEX = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)


Old_reg_values = {
    UC_X86_REG_RAX: 0,
    UC_X86_REG_RBX: 0,
    UC_X86_REG_RCX: 0,
    UC_X86_REG_RDX: 0,
    UC_X86_REG_RSI: 0,
    UC_X86_REG_RDI: 0,
    UC_X86_REG_RBP: 0,
    UC_X86_REG_RSP: 0,
    UC_X86_REG_R8: 0,
    UC_X86_REG_R9: 0,
    UC_X86_REG_R10: 0,
    UC_X86_REG_R11: 0,
    UC_X86_REG_R12: 0,
    UC_X86_REG_R13: 0,
    UC_X86_REG_R14: 0,
    UC_X86_REG_R15: 0,
    UC_X86_REG_RFLAGS:0,
}
New_reg_values = {
    UC_X86_REG_RAX: 0,
    UC_X86_REG_RBX: 0,
    UC_X86_REG_RCX: 0,
    UC_X86_REG_RDX: 0,
    UC_X86_REG_RSI: 0,
    UC_X86_REG_RDI: 0,
    UC_X86_REG_RBP: 0,
    UC_X86_REG_RSP: 0,
    UC_X86_REG_R8: 0,
    UC_X86_REG_R9: 0,
    UC_X86_REG_R10: 0,
    UC_X86_REG_R11: 0,
    UC_X86_REG_R12: 0,
    UC_X86_REG_R13: 0,
    UC_X86_REG_R14: 0,
    UC_X86_REG_R15: 0, 
    UC_X86_REG_RFLAGS:0, 
}

REG = ["rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rflag"]

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
def readReg(uc):
    for reg in New_reg_values.keys():
        New_reg_values[reg] = uc.reg_read(reg)
        if(New_reg_values[reg] != Old_reg_values[reg]):
            if(reg == UC_X86_REG_RAX):
                print(" ,RAX ",end="")
            elif(reg == UC_X86_REG_RBX):
                print(" ,RBX ",end="")
            elif(reg == UC_X86_REG_RCX):
                print(" ,RCX ",end="")
            elif(reg == UC_X86_REG_RDX):
                print(" ,RDX ",end="")
            elif(reg == UC_X86_REG_RSI):
                print(" ,RSI ",end="")
            elif(reg == UC_X86_REG_RDI):
                print(" ,RDI ",end="")
            elif(reg == UC_X86_REG_RBP):
                print(" ,RBP ",end="")
            elif(reg == UC_X86_REG_RSP):
                print(" ,RSP ",end="")
            elif(reg == UC_X86_REG_R8):
                print(" ,R8 ",end="")
            elif(reg == UC_X86_REG_R9):
                print(" ,R9 ",end="")
            elif(reg == UC_X86_REG_R10):
                print(" ,R10 ",end="")
            elif(reg == UC_X86_REG_R11):
                print(" ,R11 ",end="")
            elif(reg == UC_X86_REG_R12):
                print(" ,R12 ",end="")
            elif(reg == UC_X86_REG_R13):
                print(" ,R13 ",end="")
            elif(reg == UC_X86_REG_R14):
                print(" ,R14 ",end="")
            elif(reg == UC_X86_REG_R15):
                print(" ,R15 ",end="")
            elif(reg == UC_X86_REG_RFLAGS):
                print(" ,RF ",end="")
            print("<-- %x "%New_reg_values[reg],end="")
    for reg in New_reg_values.keys():
        Old_reg_values[reg] = New_reg_values[reg]
    
def callback_optimize(uc,rip,size,user_data):
    s = idc.GetDisasm(rip)
    if("nop" in s):
        return
    if("not" in s):
        test.mabe_1(rip)
    if("xchg" in s):
        test.mabe_2(rip)
    if("push" in s):
        test.mabe_3_4(rip)
    # s = idc.GetDisasm(rip)
    # if("nop" in s):
    #     return
    # readReg(uc)
    # print(" ")
    # print("%x : "%rip,end="")
    # print(s.ljust(40),end=" ")
    
    #

def unicorn_optimize(strat,end):
# 获取二进制文件代码段的起始地址和大小
    text_start = get_segm_by_name(".text").start_ea
    text_size = get_segm_by_name(".text").size()

    tvm0_start =  get_segm_by_name(".tvm0").start_ea
    tvm0_size =  get_segm_by_name(".tvm0").size()

    stack_start = 0x1000
    stack_size = 0x1000
    rsp = stack_start+0x800
    # 初始化一个 Unicorn 引擎实例，并进行一些必要的配置
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(text_start, text_size)
    uc.mem_write(text_start, get_bytes(text_start, text_size))

    uc.mem_map(tvm0_start, tvm0_size)
    uc.mem_write(tvm0_start, get_bytes(tvm0_start, tvm0_size))

    uc.mem_map(stack_start,stack_size)
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX,rsp+0x50)
    # 使用 Unicorn 引擎模拟执行指定代码段
    try:
        uc.hook_add(UC_HOOK_CODE,callback_optimize)
        uc.emu_start(strat,end)
    except UcError as e:
        print("Unicorn Error: %s" % e)
        #uc.reg_read(reg)

def callback_Trace(uc,rip,size,user_data):
    s = idc.GetDisasm(rip)
    if("nop" in s):
        return
    readReg(uc)
    print(" ")
    print("%x : "%rip,end="")
    print(s.ljust(40),end=" ")

def Trace(strat,end):
    text_start = get_segm_by_name(".text").start_ea
    text_size = get_segm_by_name(".text").size()

    tvm0_start =  get_segm_by_name(".tvm0").start_ea
    tvm0_size =  get_segm_by_name(".tvm0").size()

    stack_start = 0x1000
    stack_size = 0x1000
    rsp = stack_start+0x800
    # 初始化一个 Unicorn 引擎实例，并进行一些必要的配置
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(text_start, text_size)
    uc.mem_write(text_start, get_bytes(text_start, text_size))

    uc.mem_map(tvm0_start, tvm0_size)
    uc.mem_write(tvm0_start, get_bytes(tvm0_start, tvm0_size))

    uc.mem_map(stack_start,stack_size)
    uc.reg_write(UC_X86_REG_RSP, rsp)
    uc.reg_write(UC_X86_REG_RCX,rsp+0x50)
    # 使用 Unicorn 引擎模拟执行指定代码段
    try:
        uc.hook_add(UC_HOOK_CODE,callback_Trace)
        uc.emu_start(0x140086EFA, 0x140086EFF)
    except UcError as e:
        
        print("Unicorn Error: %s" % e)
        #uc.reg_read(reg)


def main():
    unicorn_optimize(0x140086EFA, 0x140086EFF)
    Trace(0x140086EFA, 0x140086EFF)



if(__name__ ==  "__main__"):
    main()


