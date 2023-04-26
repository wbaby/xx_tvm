from idaapi import *
import idc
from TVMunicorn import *
from unicorn.x86_const import *
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
    
def callback(uc,rip,size,user_data):
    s = idc.GetDisasm(rip)
    if("nop" in s):
        return
    readReg(uc)
    print(" ")
    print("%x : "%rip,end="")
    print(s.ljust(40),end=" ")
    
    #

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
    uc.hook_add(UC_HOOK_CODE,callback)
    uc.emu_start(0x140086EFA, 0x140086EFF)
except UcError as e:
    
    print("Unicorn Error: %s" % e)
    uc.reg_read(reg)


