#from Tasm_init import TVMTABEL
import idc
from idaapi import *
import copy
import idautils
import capstone
import keystone


ENDOPCODE = ["int3","jmp","ret"]
WORKINGREG = {"PO_rax",
             "PO_rbx",
             "PO_rcx",
             "PO_rdx",
             "PO_rsp",
             "PO_rbp",
             "PO_rsi",
             "PO_rdi",
             "PO_r8",
             "PO_r9",
             "PO_r10",
             "PO_r11",
             "PO_r12",
             "PO_r13",
             "PO_r14",
             "PO_r15",
             "PO_rf"}
XXREGNAME = {"PO_rax":0x08,
             "PO_rbx":0x10,
             "PO_rcx":0x18,
             "PO_rdx":0x20,
             "PO_rsp":0x28,
             "PO_rbp":0x30,
             "PO_rsi":0x38,
             "PO_rdi":0x40,
             "PO_r8":0x48,
             "PO_r9":0x50,
             "PO_r10":0x58,
             "PO_r11":0x60,
             "PO_r12":0x68,
             "PO_r13":0x70,
             "PO_r14":0x78,
             "PO_r15":0x80,
             "PO_rf":0x88}
REG = ["rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15","rflag"]
HEX2ASM = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
ASM2HEX = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
tvm0base = get_segm_by_name(".tvm0").start_ea


def getSegmEnd():
    Num = get_segm_qty()
    maxx = 0
    for i in range(Num+1):
        if(i == 0):
            continue
        size = get_segm_by_sel(i).end_ea
        if(size >= maxx):
            maxx = size
    return maxx

detvmSegmBase = getSegmEnd() + 0x1000

def Ic_add_segment(start, end, name):
    ls = get_segm_by_sel(1)
    seg = segment_t()
    seg.bitness = ls.bitness
    seg.start_ea = start
    seg.end_ea = end
    seg.align = ls.align
    seg.comb = ls.comb
    seg.sel = setup_selector(0)
    seg.flags = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC
    seg.type = ls.type
    seg.sclass = ls.sclass
    seg.orgbase = ls.orgbase
    add_segm_ex(seg, name, "CODE", 1)
    seg.flags = SEGPERM_READ | SEGPERM_WRITE | SEGPERM_EXEC

def getOregName(Vregname,bytewide):
    V_RAX = {8:"rax",4:"eax",2:"ax",1:"al"}
    V_RBX = {8:"rbx",4:"ebx",2:"bx",1:"bl"}
    V_RCX = {8:"rcx",4:"ecx",2:"cx",1:"cl"}
    V_RDX = {8:"rdx",4:"edx",2:"dx",1:"dl"}
    V_RSI = {8:"rsi",4:"esi",2:"si",1:"sil"}
    V_RDI = {8:"rdi",4:"edi",2:"di",1:"dil"}
    V_RSP = {8:"rsp",4:"esp",2:"sp",1:"spl"}
    V_RBP = {8:"rbp",4:"ebp",2:"bp",1:"bpl"}
    V_R8 = {8:"r8",4:"r8d",2:"r8w",1:"r8b"}
    V_R9 = {8:"r9",4:"r9d",2:"r9w",1:"r9b"}
    V_R10 = {8:"r10",4:"r10d",2:"r10w",1:"r10b"}
    V_R11 = {8:"r11",4:"r11d",2:"r11w",1:"r11b"}
    V_R12 = {8:"r12",4:"r12d",2:"r12w",1:"r12b"}
    V_R13 = {8:"r13",4:"r13d",2:"r13w",1:"r13b"}
    V_R14 = {8:"r14",4:"r14d",2:"r14w",1:"r14b"}
    V_R15 = {8:"r15",4:"r15d",2:"r15w",1:"r15b"}
    if(Vregname == "PO_rax" or Vregname == "rax"):
        return V_RAX[bytewide]
    elif(Vregname == "PO_rbx" or Vregname == "rbx"):
        return V_RBX[bytewide]
    elif(Vregname == "PO_rcx"or Vregname == "rcx"):
        return V_RCX[bytewide]
    elif(Vregname == "PO_rdx"or Vregname == "rdx"):
        return V_RDX[bytewide]
    elif(Vregname == "PO_rsi"or Vregname == "rsi"):
        return V_RSI[bytewide]
    elif(Vregname == "PO_rdi"or Vregname == "rdi"):
        return V_RDI[bytewide]
    elif(Vregname == "PO_rsp"or Vregname == "rsp"):
        return V_RSP[bytewide]
    elif(Vregname == "PO_rbp"or Vregname == "rbp"):
        return V_RBP[bytewide]
    elif(Vregname == "PO_r8"or Vregname == "r8"):
        return V_R8[bytewide]
    elif(Vregname == "PO_r9"or Vregname == "r9"):
        return V_R9[bytewide]
    elif(Vregname == "PO_r10"or Vregname == "r10"):
        return V_R10[bytewide]
    elif(Vregname == "PO_r11"or Vregname == "r11"):
        return V_R11[bytewide]
    elif(Vregname == "PO_r12"or Vregname == "r12"):
        return V_R12[bytewide]
    elif(Vregname == "PO_r13"or Vregname == "r13"):
        return V_R13[bytewide]
    elif(Vregname == "PO_r14"or Vregname == "r14"):
        return V_R14[bytewide]
    elif(Vregname == "PO_r15"or Vregname == "r15"):
        return V_R15[bytewide]
    else:
        return Vregname #数字

def getxxreg(xx):
    for key, x in XXREGNAME.items():
        if x == xx:
            return key
    return None

def setQword(num):
        mask = (1 << 64) - 1
        return num & mask

def addressingConversion(num):
    if(num > 0x7FFFFFFF):
        b = ~num
        b = setQword(b)
        return b+1
    else:
        return num

def getDisAsmInsn(byte, traceRip):
    dis = HEX2ASM.disasm_lite(byte, traceRip)
    insnInfo = None
    for insn in dis:
        insnInfo = insn
    insnInfo = list(insnInfo)
    for info_i in range(insnInfo.__len__()):
        if(info_i < 2):
            continue
        if("rip" in insnInfo[info_i]):
            strartAdd = insnInfo[0]
            AsmByteCount = insnInfo[1]
            s = insnInfo[info_i]
            prefix = s[:s.find("[")]
            suffisso = s[s.find("]")+1:]
            s = s[s.find("0x"):s.find("]")]
            innt = int(s,16)
            handle = 0 #0 加法  1 减法
            if("-" in insnInfo[info_i]):
                handle = 1
            if(handle == 0):
                EndAdd =  strartAdd + AsmByteCount + innt
            else:
                EndAdd =  strartAdd + AsmByteCount - innt
            prefix = prefix + "[" + hex(EndAdd) + "]" + suffisso
            insnInfo[info_i] = prefix
    return insnInfo
                      
def memcpy(x,val,len):
    for i in range(len):
        idc.patch_byte(x + i,val[i])

class tvmAsm:
    def __init__(self,name,opcode,xor):
        if(isinstance(opcode,list) != 1):
            opcode = [opcode]
        self.name = name
        self.opcodename = list(name.split("_"))[1:2]
        self.opcode = []
        self.opcode.extend(opcode)
        self.xor = xor
        self.type = list(name.split("_"))[2:]
        self.next = None
        return
    
    def getopcode(self):
        return self.opcode
    
    def getXor(self):
        return self.xor
    
    def gettype(self):
        return self.type

    def getname(self):
        return self.name
    
    def getopcodename(self):
        return self.opcodename
    
class tvmAsmTable:
    def __init__(self) -> None:
        self.Table = None
        self.Count = 0
        return
    
    def append(self,name,opcode,xor):
        Node = tvmAsm(name,opcode,xor)
        if self.Table == None:
            self.Table = Node
        else:
            Node.next = self.Table
            self.Table = Node
        self.Count += 1
        return
    
    def getTvmAsm(self,opcode):
        Tage = self.Table
        while Tage is not None:
            if(opcode in Tage.opcode):
                return Tage
            Tage = Tage.next
        return None
TVMTABEL = tvmAsmTable()

class tvmPara:
    def __init__(self,name,type):
        self.name = name
        self.type = type
        self.byteWide = 0
        if("ll" in self.type):
            self.byteWide = 8
        elif("l" in self.type):
            self.byteWide = 4
        elif("w" in self.type):
            self.byteWide = 2
        elif("b" in self.type):
            self.byteWide = 1
        elif("ip" in self.type):
            self.byteWide = 8
        elif("x" in self.type):
            self.byteWide = 0
        else:
            print("tvmPara byteWide error")
        
class traceCode:
    def __init__(self,Add,tvmAsm):
        self.Add = Add
        self.tvmAsm = tvmAsm  #tvmPara
        self.paraAll = list()
        self.working = False
        #self.about = 0          #仅用于转换ASM时，区分此traceCode是推导哪个操作数的
        return
    
    def addPara(self,P,type):
        ls = tvmPara(P,type)
        # if(ls.byteWide == 0):
        #     self.print()
        self.paraAll.append(ls)
        
        return
    
    def setWorking(self):
        self.working = True
        return
    
    def print(self):
        print(" %x : "%self.Add,end = "")
        print(self.tvmAsm.getname().ljust(35),end="")
        print("( ",end="")
        for i in range(self.paraAll.__len__()):
            print(self.paraAll[i].type.ljust(6),":",end="")
            print(self.paraAll[i].name.ljust(15),end = "")
            if(i+1<self.paraAll.__len__()):
                print(",",end="")
        print(" );",end="")
        if(self.working == True):
            print("<----------------------------------".rjust(10))
        else:
            print("")
    
    def getStr(self):
        str = ""
        str += " %x : "%self.Add
        str += self.tvmAsm.getname().ljust(35)
        str += "( "
        for i in range(self.paraAll.__len__()):
            str += self.paraAll[i].type.ljust(6)
            str += ":"
            str += self.paraAll[i].name.ljust(15)
            if(i+1<self.paraAll.__len__()):
                str += ","
        str += " );"
        if(self.working == True):
            str += " <----------------------------------"
        return str

    def getMiniWide(self):#获取这条指令最小的字节宽度
        mini = 8
        for tvmPara_i in range(self.paraAll.__len__()):
            if(tvmPara_i == 3 or ("o" in self.paraAll[tvmPara_i].type and tvmPara_i>0)): #不用管O_rf
                continue
            wide = self.paraAll[tvmPara_i].byteWide
            if(wide != None and wide <= mini):
                mini = wide
        return mini

    def getMaxWide(self):
        max = 0
        for tvmPara_i in range(self.paraAll.__len__()):
            if(tvmPara_i == 3 or ("o" in self.paraAll[tvmPara_i].type and tvmPara_i>0)): #不用管O_rf
                continue
            wide = self.paraAll[tvmPara_i].byteWide
            if(wide != None and wide >= max):
                max = wide
        return max
    #def getOreg

class traceCodeAll:
    def __init__(self) -> None:
        self.traceCodeAll = list()
        return
    
    def addtraceCode(self,traceCode):
        self.traceCodeAll.append(traceCode)
        return
    
    def out(self):
        for traceCode in self.traceCodeAll:
            traceCode.print()
        return
    
    def TCsorted(self):
        self.traceCodeAll = sorted(self.traceCodeAll, key=lambda x: x.Add, reverse=False)

class traceTaskReg:
    def __init__(self,traceCode,tvmPara):
        self.tvmPara = tvmPara
        self.traceCode = traceCode
        self.label = None       #两个用法
        self.next = None
        return 

class traceTaskRegList:
    def __init__(self,tvmPara,traceCode):
        self.Head = traceTaskReg(traceCode,tvmPara)
        self.tvmPara = tvmPara
        self.Count = 1
        return 
    
    def AddtraceTaskReg(self,traceCode,tvmPara):
        ls = traceTaskReg(traceCode,tvmPara)
        ls.next = self.Head
        self.Head = ls
        self.Count +=1
        return ls
    
    def findRecent(self,traceCode):#找到最近一次定义 的 traceTaskReg
        ls = self.Head
        while(ls.traceCode.Add >= traceCode.Add):
            ls = ls.next
            if(ls == None):
                return None
        return ls
    
class traceTaskRegTable:
    def __init__(self):
        self.traceTaskRegTable = list()
        return
    
    def addRegdefine(self,tvmPara,traceCode):
        Finsh = False
        if (tvmPara.name in WORKINGREG):
            return True
        for ls in self.traceTaskRegTable:
            if(ls.tvmPara.name == tvmPara.name):
                kk = ls.AddtraceTaskReg(traceCode,tvmPara)
                Finsh = True
                return kk
        if(Finsh == False):
            ls = traceTaskRegList(tvmPara,traceCode)
            self.traceTaskRegTable.append(ls)
            Finsh = True
            return ls.Head
        # print(tvmPara.name,end="")
        # print(" %x "%traceCode.Add,end="")
        # print("<<---------------------")
        
    def gettraceTaskRegList(self,tvmPara):
        for ls in self.traceTaskRegTable:
            if(ls.tvmPara.name == tvmPara.name):
                return ls
        return None

    def gettraceTaskRegLabel(self,tvmPara,traceCode):#获取临时标记（某个寄存器？）
        RegList = self.gettraceTaskRegList(tvmPara)
        if(RegList == None):
            return None
        traceTaskReg = RegList.findRecent(traceCode)
        if(traceTaskReg == None):
            return None
        return traceTaskReg.label
        
    def settraceTaskRegLabel(self,tvmPara,traceCode,setOtvmPara):
        RegList = self.gettraceTaskRegList(tvmPara)
        if(RegList == None):
            return None
        traceTaskReg = RegList.findRecent(traceCode)
        if(traceTaskReg == None):
            return None
        # new = "_New"
        # newla = copy.deepcopy(setOtvmPara)
        # newla.name = newla.name + new
        # traceTaskReg.label = newla
        if("mov" in traceTaskReg.traceCode.tvmAsm.name and "PO" in traceTaskReg.traceCode.paraAll[1].name):
            traceTaskReg.label = traceTaskReg.traceCode.paraAll[1]
            return 
        if(traceTaskReg.label == None):
            traceTaskReg.label = setOtvmPara

    def findLastDefine(self,traceCode,useLabel):#传入一条 mov...   指令，返回所引用参数在此之前的最后一次定义的 traceTaskReg list
        findPara = list()       #需要查询的VREG
        findDefinePara = list() 
        for i in range(traceCode.paraAll.__len__()):
            cn = False
            if("o" in traceCode.paraAll[i].type or "reg" not in traceCode.paraAll[i].type or "PO" in traceCode.paraAll[i].name):
                continue
            for kk in findPara:
                if(kk.name == traceCode.paraAll[i].name):
                    cn = True
                    break
            if(cn == True):
                continue
            if(i == 0 and "mov" in traceCode.tvmAsm.getname() and "ip" not in traceCode.paraAll[i].type):
                continue
            if(useLabel == True):
                label = self.gettraceTaskRegLabel(traceCode.paraAll[i],traceCode)
                if(label != None):
                    traceCode.paraAll[i] = label
                    continue
            findPara.append(traceCode.paraAll[i])
        
        if(findPara.__len__()==0):
            return findDefinePara
        for ipara in findPara:
            RegList = self.gettraceTaskRegList(ipara)
            if(RegList == None):
                return findDefinePara
            #print(ipara.name,end="")
            traceTaskReg = RegList.findRecent(traceCode)
            if(traceTaskReg != None):
                findDefinePara.append(traceTaskReg)
        return findDefinePara

    def getLastDefine(self,traceCode,tvmPara):
        paralist = self.gettraceTaskRegList(tvmPara)
        if(paralist == None):
            return None
        traceTaskReg = paralist.findRecent(traceCode)
        if(traceTaskReg == None):
            return None
        return traceTaskReg

class defineRecordAll:
    def __init__(self) -> None:
        self.defineRecord = list()
        self.Count = 0
        return
    def addRecord(self,traceTaskReg):
        self.defineRecord.append(traceTaskReg)
        self.Count +=1

class AsmPara:
    def __init__(self,name,order):
        self.name = name
        self.order = order

class AsmSpecial:
    def __init__(self):
        self.valid = False  #是否有效 ）
        self.oadd = 0       #地址（要算偏移 例如 lock cmpxchg cs:dword_14000DEA4, ebx）
        self.byte = None    #字节码
        self.insn = None    #翻译成ASM  HEX2ASM.disasm_lite(bytea, 0x1400C8BF0)

class Asm:
    def __init__(self) -> None:
        self.opcode = None
        self.byteWide = 0        #1 2 4 8
        self.asmParaAll = list()        #v_jcc 也属于特殊，但不用AsmSpecial()
        self.jmp_Special = AsmSpecial() #v_jmp 属于特殊处理
        self.jcc_Tage = None            #作为jcc跳转的目标
        self.jcc_Special = None         #一条vjcc指令可以翻译成两句 ASM 这里放着另外一句jmp
        self.HEXAdd = 0
        self.HEX = None
        self.HEXLen = 0

    def addAsmPara(self,name,order):
        ls = AsmPara(name,order)
        self.asmParaAll.append(ls)

    def getStr(self):
        out = ""
        if(self.jcc_Tage !=None):
            out += self.jcc_Tage + ":\n"
        if(self.jmp_Special.valid == True):
            Count = self.jmp_Special.insn.__len__()
            for str_i in range(Count):
                if(str_i <2):
                    continue
                if(str_i == 2):
                    out = out + self.jmp_Special.insn[str_i] + "  "
                    continue
                if(str_i>2):
                    out +=self.jmp_Special.insn[str_i]
                    if(str_i+1<Count):
                        out +=","
        elif(self.opcode != None):
            out = out + self.opcode + "  "
            paraCount = self.asmParaAll.__len__()
            for asmPara_i in range(paraCount):
                out +=self.asmParaAll[asmPara_i].name
                if(asmPara_i != paraCount - 1):
                    out +=","
        if(self.jcc_Special != None):
            out = out +"\n" +self.jcc_Special
        return out

    def print(self):
        ostr = self.getStr()
        print(ostr)

    def setJcctage(self):
        if(self.jcc_Tage == None):
            self.jcc_Tage = "ic" +  hex(id(self))
        return self.jcc_Tage
    
    def AsmToHex(self,baseAdd):#本来批量就可以，可是不行 keystone 有BUG  。
        if(self.HEX != None):
            return self.HEXAdd + self.HEXLen
        if(self.HEXAdd == 0):
            self.HEXAdd = baseAdd
        else:
            baseAdd = self.HEXAdd
        if(self.opcode!= None and "mov" == self.opcode):
            asmP2 = self.asmParaAll[1].name
            if("qword ptr[" in asmP2):
                asmP2int = asmP2[asmP2.find("[")+1:]
                asmP2int = asmP2int[:asmP2int.find("]")]
                if("r" not in asmP2int):
                    asmP2int = int(asmP2int,16)
                    ripadd = baseAdd + 7 - asmP2int
                    newasmPara2name = "qword ptr[rip - " + hex(ripadd) + "]"
                    self.asmParaAll[1].name = newasmPara2name
        Str = self.getStr()
        try:
            HEX,_ = ASM2HEX.asm(Str,addr=baseAdd)
        except:
            print("AsmToHex Error %s"%self.opcode)
            return baseAdd
        if(HEX == None):
            return baseAdd
        self.HEX = HEX
        self.HEXLen = HEX.__len__()
        return self.HEXLen + baseAdd #返回 这一句ASM的结束地址（下一句的起始）

    def AsmWrite(self):
        if(self.HEXAdd == None):
            return
        memcpy(self.HEXAdd,self.HEX,self.HEXLen)

class tvmToAsmPara:
    def __init__(self,PO_reg,handle,usedRF):
        self.PO_reg = PO_reg
        self.handle = handle
        self.usedRF = usedRF

class tvmToAsm:#一句 ASM
    asmOpcode = [
        "sar",
        "or",
        "ror",
        "xor",
        "shr",
        "shl",
        "movsxd",
        "movsx",
        "movzx",
        "dec",
        "inc",
        "test",
        "cmp",
        "rep stosb",
        "sbb",
        "int3"
    ]
    def __init__(self):
        self.BLink = None
        self.FLink = None
        self.traceCodeAll = list()      #相关的traceCode深度拷贝
        self.TvmParaTable = traceTaskRegTable()
        self.workingAddList=list()
        self.tvmToAsmAll = None
        self.asm = Asm()
        return
    
    def setNextDefineTraceCode(self,startTraceCode,findtvmPara,settvmPara):#优化用到的子函数
        End = False
        for i in range(self.traceCodeAll.__len__()):
            if(End == True):
                return
            traceCode = self.traceCodeAll[i]
            if(traceCode.Add <= startTraceCode.Add):
                continue
            for tvmPara_i in range(traceCode.paraAll.__len__()):
                tvmPara = traceCode.paraAll[tvmPara_i]
                if("o" in tvmPara.type and tvmPara.name == findtvmPara.name and "ip" not in tvmPara.type ):
                    End = True
                    continue
                if("mov" in traceCode.tvmAsm.getopcodename() and tvmPara_i == 0 and tvmPara.name == findtvmPara.name and "ip" not in tvmPara.type):
                    End = True
                    continue
                if(tvmPara.name == findtvmPara.name):
                    tvmPara.name = settvmPara.name
                    if("ip" not in tvmPara.type):
                        tvmPara.type = settvmPara.type
                        tvmPara.byteWide = settvmPara.byteWide
            
    def optimize(self):#优化，到达定值 和 变量拷贝
        RemoveTraceCode = list()
        for traceCode_i in range(self.traceCodeAll.__len__()):
            traceCode = self.traceCodeAll[traceCode_i]
            Continuef = False
            if("je"in traceCode.tvmAsm.getopcodename()):
                traceCode.paraAll[1].name = hex(setQword(int(traceCode.paraAll[1].name,16)+traceCode.Add+1+2+8+8))
                traceCode.paraAll[2].name = hex(setQword(int(traceCode.paraAll[2].name,16)+traceCode.Add+1+2+8+8))
            if(traceCode.working == True):
                self.workingAddList.append(traceCode.Add)
                Continuef = True
            if("mov_" not in traceCode.tvmAsm.getname()):
                Continuef = True
            for para in traceCode.paraAll:
                if(para.type == "ipreg"):
                    Continuef = True
            if(Continuef == True):
                continue
            if(traceCode.paraAll[1].name in WORKINGREG or "reg" not in traceCode.paraAll[1].type):
                self.setNextDefineTraceCode(traceCode,traceCode.paraAll[0],traceCode.paraAll[1])
                RemoveTraceCode.append(traceCode)
        for re in RemoveTraceCode:
            self.traceCodeAll.remove(re)
        
    def print(self):
        for traceCode in self.traceCodeAll:
            traceCode.print()
    
    def getTvmToAsmStr(self):
        tvmToAsmStr = ""
        for traceCode in self.traceCodeAll:
            tvmToAsmStr=tvmToAsmStr + traceCode.getStr() + "\n"
        return tvmToAsmStr + "\n"

    def getWorkingTraceCode(self):
        for traceCode in self.traceCodeAll:
            if(traceCode.working == True):
                return traceCode
            
    def getVoperandAboutTraceCode(self,n):#获取 working 指令第n个操作数的引用指令集合（从0开始）
        workingTvmPara = self.getWorkingTraceCode().paraAll[n]
        for traceCode in self.traceCodeAll:
            return
        
    #处理 tvmcode 有 jmp 的  AsmSpecial
    def vjmp_handle(self,traceCode):
        #print("a")
        if("ll" not  in traceCode.tvmAsm.getname()):
            self.asm.opcode= "jmp"
            if("R11" in traceCode.tvmAsm.getname()):
                self.asm.addAsmPara("r11",0)
            elif("R10" in traceCode.tvmAsm.getname()):
                self.asm.addAsmPara("r10",0)
            else:
                self.asm.addAsmPara("rax",0)
            return
        traceRip = int(traceCode.paraAll[0].name,16)
        create_insn(traceRip)
        tvm0base = get_segm_by_name(".tvm0").start_ea
        jl = traceRip
        lstace = tvmFunTask(0,tvm0base)
        for ii in range(100):
            s = idc.GetDisasm(traceRip)
            if("mov" in s and "rsp,"in s and "[rsp" in s):
                #if("rsp" in idc.GetDisasm(lstace.next_rip(lstace.next_rip(traceRip)))):
                traceRip = lstace.next_rip(traceRip)
                if(traceRip == None):
                    ii = 99
                    break
                byte=idc.get_bytes(traceRip,idautils.DecodeInstruction(traceRip).size)
                self.asm.jmp_Special.byte = byte
                # dis = HEX2ASM.disasm_lite(byte, traceRip)
                # for insn in dis:
                #     self.asm.jmp_Special.insn = insn
                self.asm.jmp_Special.insn = getDisAsmInsn(byte, traceRip)
                self.asm.jmp_Special.oadd = traceRip
                self.asm.jmp_Special.valid = True
                #print("--->%x : "%traceRip,end="")
                #print(f"{self.asm.jmp_Special.insn.mnemonic} {self.asm.jmp_Special.insn.op_str}")
                break
            traceRip = lstace.next_rip(traceRip)
            if(traceRip == None):
                ii = 99
                break
        
        if(ii >=99):
            print("--------------------------------------------------------------error------->%x : "%jl)

    def vjcc_handle_tool1(self,traceCodeAll,flagAll):
        
        for traceCode in traceCodeAll:
            if("and" in traceCode.tvmAsm.getname()):
                flagAll.append(int(traceCode.paraAll[1].name,16))
                continue
            if("sub" in traceCode.tvmAsm.getname()):
                flagAll.append(int(traceCode.paraAll[2].name,16))
                continue
            if("je" in traceCode.tvmAsm.getname()):
                return int(traceCode.paraAll[1].name,16),int(traceCode.paraAll[2].name,16)
        return 0,0
    
    def vjcc_handle_tool2(self,flagAll):
        q,s = self.vjcc_handle_tool1(self.traceCodeAll,flagAll)
        if(q ==0x0 and s == 0x0):
            return q,s
        elif(q == s):
            return q,s
        while(True):
            flstarck = traceTask(0,tvm0base)
            flstarck.VStart = s
            flstarck.track(1)
            flstarck.VRegRecord(True)
            flstarck.tvmToAsmAll.optimizeAll()
            if(flstarck.tvmToAsmAll.tvmToAsmHead != None and "je" in flstarck.tvmToAsmAll.tvmToAsmHead.getWorkingTraceCode().tvmAsm.getopcodename()):
                flagAll_bf = []
                qs,ss = self.vjcc_handle_tool1(flstarck.tvmToAsmAll.tvmToAsmHead.traceCodeAll,flagAll_bf)
                if(qs == q and qs!= 0 and ss != 0):
                    s = ss
                    self.tvmToAsmAll.removeTvmToAsm(flstarck.tvmToAsmAll.tvmToAsmHead.workingAddList[0])
                    flagAll.extend(flagAll_bf)
                else:
                    break
            else:
                break
        return q,s

    def vjcc_handle(self):
        IsNop = False
        Isjmp = False
        flagAll = []
        q,s = self.vjcc_handle_tool2(flagAll)
        if(q ==0x0 and s == 0x0):
            IsNop = True
        elif(q == s):
            Isjmp = True

        if(IsNop == True):
            self.asm.opcode = "nop"
            #self.printAsm()
            return
        
        if(Isjmp == True):
            self.asm.opcode = "jmp"
            self.asm.addAsmPara(hex(q),0)
            self.asm.addAsmPara(hex(q),1)
            #self.printAsm()
            return

        if(flagAll.__len__() == 2):
            if(flagAll[0] == 0x40 and flagAll[1] == 0x40):#je jz
                self.asm.opcode = "je"
            elif(flagAll[0] == 0x40 and flagAll[1] == 0x0):#jne jnz
                self.asm.opcode = "jne"
            elif(flagAll[0] == 0x1 and flagAll[1] == 0x1):#jc jb jnae
                self.asm.opcode = "jc"
            elif(flagAll[0] == 0x1 and flagAll[1] == 0x0):#jnc jnb jae
                self.asm.opcode = "jnc"
            elif(flagAll[0] == 0x80 and flagAll[1] == 0x80):#js 
                self.asm.opcode = "js"
            elif(flagAll[0] == 0x80 and flagAll[1] == 0x00):#jns
                self.asm.opcode = "jns"
            elif(flagAll[0] == 0x41 and flagAll[1] == 0x00):#ja jnbe
                self.asm.opcode = "ja"            
            elif(flagAll[0] == 0x800 and flagAll[1] == 0x800):#jo
                self.asm.opcode = "jo"
            elif(flagAll[0] == 0x800 and flagAll[1] == 0x0):#jno
                self.asm.opcode = "jno"
            elif(flagAll[0] == 0x4 and flagAll[1] == 0x4):#jp jpe 
                self.asm.opcode = "jp"
            elif(flagAll[0] == 0x4 and flagAll[1] == 0x00):#jnp jpo
                self.asm.opcode = "jnp"
            else:
                print("errpo2")
                for fl in flagAll:
                    print("%x "%fl,end=" ")
                print("")
                self.print()
                return
        elif(flagAll.__len__() == 4):
            if(flagAll[0] == 0x41 and flagAll[1] == 0x1 and flagAll[2] == 0x41 and flagAll[3] == 0x40):#jbe jna
                self.asm.opcode = "jbe"
            elif(flagAll[0] == 0x880 and flagAll[1] == 0x0 and flagAll[2] == 0x880 and flagAll[3] == 0x880):#jge jnl
                self.asm.opcode = "jge"
            elif(flagAll[0] == 0x880 and flagAll[1] == 0x800 and flagAll[2] == 0x880 and flagAll[3] == 0x80):#jl jnge
                self.asm.opcode = "jnge"
            elif(flagAll[0] == 0x8c0 and flagAll[1] == 0x0 and flagAll[2] == 0x8c0 and flagAll[3] == 0x880):#jg jnle
                self.asm.opcode = "jg"
            else:
                print("errpo4")
                for fl in flagAll:
                    print("%x "%fl,end=" ")
                print("")
                self.print()
                return
        elif(flagAll.__len__() == 12):
            self.asm.opcode = "jng"
        else:
            print("errpo vjcc")
            for fl in flagAll:
                print("%x "%fl,end=" ")
            print("")
            self.print()
            return
            
        self.asm.addAsmPara(hex(q),0)    
        self.asm.addAsmPara(hex(s),1)  
        #self.printAsm()
        
        return

    def printAsm(self):
        self.asm.print()
    
    def uk_simplify(self,label):
        ls = []
        if(label.__len__() == 3):# not + add + not  组成 sub
            if(label[0].handle == "not" and label[1].handle == "add" and label[2].handle == "not"):
                ls.append(tvmToAsmPara(label[0].PO_reg,None,False))
                ls.append(tvmToAsmPara(label[1].PO_reg,"sub",label[1].usedRF))
            elif(label[0].handle == "not" and label[1].handle == "sub" and label[2].handle == "not"):
                ls.append(tvmToAsmPara(label[0].PO_reg,None,False))
                ls.append(tvmToAsmPara(label[1].PO_reg,"add",label[1].usedRF))
        return ls
    
    def uk_not_handle(self,traceCode):
        traceTaskReg = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[1])
        definetraceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[0],traceCode)
        if(traceTaskReg == None):
            label =  list()
            label.append(tvmToAsmPara(traceCode.paraAll[1],"not",True)) 
        else:
            label =copy.copy(traceTaskReg.label) 
            label.append(tvmToAsmPara(None,"not",True))
            newLabel = self.uk_simplify(label)
            if(newLabel.__len__()!=0):
                #print("xixi")
                label = newLabel
        definetraceTaskReg.label = label
        
    def uk_add_handle(self,traceCode):
        traceTaskReg_1 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[1])
        traceTaskReg_2 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[2])
        traceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[0],traceCode)
        usedRF = False
        if(traceCode.paraAll.__len__() == 4):
            usedRF = True
        if(traceTaskReg_1 == None and traceTaskReg_2 == None):#避免出现 lea  rcx,[rax + 0xffffffffffffffd0] 这种情况 实际是 lea  rcx,[rax - 0x30]
            
            if("reg" in traceCode.paraAll[2].type):
                traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(traceCode.paraAll[2],"add",usedRF)]
            else:
                sj = int(traceCode.paraAll[2].name,16)
                yh = addressingConversion(sj)
                if(sj == yh):
                    traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(traceCode.paraAll[2],"add",usedRF)]
                else:
                    if(usedRF == False):
                        traceCode.paraAll[2].name = hex(yh)
                        traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(traceCode.paraAll[2],"sub",usedRF)]
                    else:
                        traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(traceCode.paraAll[2],"add",usedRF)]
            return
        if(traceTaskReg_1 != None and traceTaskReg_2 != None):
            label_1 = traceTaskReg_1.label
            label_2 = traceTaskReg_2.label
            label = label_1 +[tvmToAsmPara(None,"add",usedRF)]+ label_2
            traceTaskReg.label = label
            return
        if(traceTaskReg_1 == None):
            usedTraceTaskReg = traceTaskReg_2
            usedTvmPara = traceCode.paraAll[1]
        else:
            usedTraceTaskReg = traceTaskReg_1
            usedTvmPara = traceCode.paraAll[2]
        label = copy.copy(usedTraceTaskReg.label)
        traceTaskReg.label = label
        traceTaskReg.label.append(tvmToAsmPara(usedTvmPara,"add",usedRF))

    def uk_and_handle(self,traceCode):
        traceTaskReg_1 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[1])
        traceTaskReg_2 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[2])
        traceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[0],traceCode)
        usedRF = False
        if(traceCode.paraAll.__len__() == 4):
            usedRF = True
        if(traceTaskReg_1 != traceTaskReg_2 and traceTaskReg_1 != None and traceTaskReg_2 != None):
            print("and error<----------------")
            self.print()
            label_1 = traceTaskReg_1.label
            label_2 = traceTaskReg_2.label
            label = label_1 +[tvmToAsmPara(None,"and",usedRF)]+ label_2
            traceTaskReg.label = label
            return
        elif(traceTaskReg_1 == traceTaskReg_2 and traceTaskReg_1 != None):
            traceTaskReg.label = copy.copy(traceTaskReg_1.label)
            return 
        elif(traceTaskReg_1 == None and traceTaskReg_2 == None):
            traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(traceCode.paraAll[2],"and",usedRF)]

    def uk_xor_handle(self,traceCode):
        traceTaskReg_1 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[1])
        traceTaskReg_2 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[2])
        traceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[0],traceCode)
        if(traceTaskReg == True):
            return
        if(traceTaskReg_1 == None and traceTaskReg_2 == None):
            traceTaskReg.label = [tvmToAsmPara(traceCode.paraAll[1],None,True),tvmToAsmPara(traceCode.paraAll[2],"xor",True)]
            return
        elif(traceTaskReg_1 != None and traceTaskReg_2 == None):
            label_1 = traceTaskReg_1.label
            traceTaskReg.label = label_1 + [tvmToAsmPara(traceCode.paraAll[2],"xor",True)]
            #self.print()
        elif(traceTaskReg_1 == None and traceTaskReg_2 != None):
            label_2 = traceTaskReg_2.label
            traceTaskReg.label = label_2 + [tvmToAsmPara(traceCode.paraAll[1],"xor",True)]
        
    def uk_mov_handle(self,traceCode):
        traceTaskReg_1 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[1])
        traceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[0],traceCode)
        if(traceTaskReg == True):
            return
        if("ip" in traceCode.paraAll[1].type):
            if(traceTaskReg_1 == None):
                babel = [tvmToAsmPara(traceCode.paraAll[1],None,False),tvmToAsmPara(None,"mem",False)]#
            else:
                babel =  copy.copy(traceTaskReg_1.label)
                babel.append(tvmToAsmPara(None,"mem",False))
            traceTaskReg.label = babel
            return
        else:
            if(traceTaskReg_1 != None):
                babel =  copy.copy(traceTaskReg_1.label)
            elif("reg" in traceCode.paraAll[1].type):
                babel =  [tvmToAsmPara(traceCode.paraAll[1],None,False)]
            traceTaskReg.label = babel  
            traceCode.paraAll[0].type = traceCode.paraAll[1].type
            traceCode.paraAll[0].byteWide = traceCode.paraAll[1].byteWide
            
        return

    def uk_mul_handle(self,traceCode):
        traceTaskReg_1 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[2])
        traceTaskReg_2 = self.TvmParaTable.getLastDefine(traceCode,traceCode.paraAll[3])
        traceTaskReg = self.TvmParaTable.addRegdefine(traceCode.paraAll[1],traceCode)#只用低位
        if(traceTaskReg_1 == None and traceTaskReg_2 == None):
            label = [tvmToAsmPara(traceCode.paraAll[2],None,False),tvmToAsmPara(traceCode.paraAll[3],"mul",False)]
            traceTaskReg.label = label
        else:
            print("mul error<------------------------")

    def record_tage(self):
        for traceCode in self.traceCodeAll:
            if(traceCode.working == True):
                continue
            if(traceCode.tvmAsm.getopcodename()[0] == "not"):
                self.uk_not_handle(traceCode)
            elif(traceCode.tvmAsm.getopcodename()[0] == "add"):
                self.uk_add_handle(traceCode)
            elif(traceCode.tvmAsm.getopcodename()[0] == "and"):
                self.uk_and_handle(traceCode)
            elif("mov" in traceCode.tvmAsm.getopcodename()[0]):
                self.uk_mov_handle(traceCode)
            elif(traceCode.tvmAsm.getopcodename()[0] == "xor"):
                self.uk_xor_handle(traceCode)
            elif(traceCode.tvmAsm.getopcodename()[0] == "mul"):
                self.uk_mul_handle(traceCode)

    def setParaPrefix(self,name,bytewide):
        if(bytewide == 1):
            return "byte ptr" + name
        elif(bytewide == 2):
            return "word ptr" + name
        elif(bytewide == 4):
            return "dword ptr" + name
        elif(bytewide == 8):
            return "qword ptr" + name
        else:
            return "xxxxxx" + name #这出错

    def get_mov_ll_p(self,p):#避免类似于这种情况 xor  rcx,0x7b7cb7791af9656b 之前必有一个 mov reg,0x7b7cb7791af9656b
        ls = self.FLink
        while(ls != None):
            if(ls.asm.opcode != None and "mov" in ls.asm.opcode  and ls.asm.asmParaAll[1].name == p):
                return ls.asm.asmParaAll[0].name
            ls = ls.FLink
        return None

    def GetAsmPara(self,TraceCode,tvmPara,SpecialByteWide = 0):
        traceTaskReg = self.TvmParaTable.getLastDefine(TraceCode,tvmPara)
        if(traceTaskReg == None):
            if("ip" in tvmPara.type):
                return "[" + getOregName(tvmPara.name,tvmPara.byteWide) + "]"
            else:
                if(SpecialByteWide == 0):
                    return getOregName(tvmPara.name,tvmPara.byteWide)
                else:
                    return getOregName(tvmPara.name,SpecialByteWide)
        jl = ""
        labelAll = traceTaskReg.label
        for label in labelAll:
            if(label.handle != None):
                if(label.handle == "add"):
                    jl += " + "
                elif(label.handle == "sub"):
                    jl += " - "
                elif(label.handle == "mem"):
                    jl = "[" + jl + "]"
                elif(label.handle == "mul"):
                    jl += " * "
                else:
                    print("error GetAsmPara")
            if(label.PO_reg != None):
                if("r" not in label.PO_reg.type and int(label.PO_reg.name,16) > 0xFFFFFFFF):
                    p1 = self.get_mov_ll_p(label.PO_reg.name)
                    if(p1 == None):
                        jl += getOregName(label.PO_reg.name,label.PO_reg.byteWide)
                    else:
                        jl += p1
                else:
                    jl += getOregName(label.PO_reg.name,label.PO_reg.byteWide)
        if("ip" in TraceCode.paraAll[0].type and "[" not in jl):
            jl = "[" + jl + "]"
        tvmPara.type = traceTaskReg.tvmPara.type
        tvmPara.byteWide = traceTaskReg.tvmPara.byteWide
        return jl
    
    def xxx_handle(self,opcode): #xor sar shr shl sbb ror or and
        bytewide = 0
        for traceCode in self.traceCodeAll:
            if(opcode in traceCode.tvmAsm.getopcodename()):
                p1 = self.GetAsmPara(traceCode,traceCode.paraAll[2])
                if("reg" not in traceCode.paraAll[2].type and int(p1,16) > 0xFFFFFFFF):
                    p1 = self.get_mov_ll_p(p1)
                    if(p1 == None):
                        #print("get_mov_ll_p Error")
                        p1 = self.GetAsmPara(traceCode,traceCode.paraAll[2])
                bytewide = traceCode.paraAll[1].byteWide
                if("[" in p1):
                    p1 = self.setParaPrefix(p1, bytewide)
            elif(traceCode.working == True):
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[0],bytewide)
                if("[" in p0):
                    p0 = self.setParaPrefix(p0, bytewide)
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)
        
    def cmp_test_handle(self):
        bytewide = 0
        workingTraceCode = self.getWorkingTraceCode()
        p0 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[0])
        bytewide = workingTraceCode.paraAll[0].byteWide
        if("[" in p0):
            p0 = self.setParaPrefix(p0, bytewide)
        p1 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[1])
        if("reg" not in workingTraceCode.paraAll[1].type and int(p1,16) > 0xFFFFFFFF):
            p1 = self.get_mov_ll_p(p1)
            if(p1 == None):
                p1 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[1])
        if("[" in p1):
            p1 = self.setParaPrefix(p1, bytewide)
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)

    def add_sub_handle(self):
        for traceCode in self.traceCodeAll:
            if("add" in traceCode.tvmAsm.getopcodename() and traceCode.paraAll.__len__()==4):
                p1 = self.GetAsmPara(traceCode,traceCode.paraAll[2])
                if("reg" not in traceCode.paraAll[2].type and int(p1,16) > 0xFFFFFFFF):
                    p1 = self.get_mov_ll_p(p1)
                    if(p1 == None):
                        p1 = self.GetAsmPara(traceCode,traceCode.paraAll[2])
                bytewide = traceCode.paraAll[1].byteWide
                if("[" in p1):
                    p1 = self.setParaPrefix(p1, bytewide)
            elif(traceCode.working == True):
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[0],bytewide)
                if("[" in p0):
                    p0 = self.setParaPrefix(p0, bytewide)
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)
        return
    
    def inc_dec_handle(self,opcode):
        for traceCode in self.traceCodeAll:
            if(opcode in traceCode.tvmAsm.getopcodename()):
                bytewide = traceCode.paraAll[0].byteWide
            elif(traceCode.working == True):
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[0],bytewide)
                if("[" in p0):
                    p0 = self.setParaPrefix(p0, bytewide)
        self.asm.addAsmPara(p0,0)
        return

    def mov_handle(self):
        workingTraceCode = self.getWorkingTraceCode()
        # if("reg" in workingTraceCode.paraAll[1].type or "ip" in workingTraceCode.paraAll[0].type):
        #     bytewide = workingTraceCode.paraAll[1].byteWide
        # else:
        #     bytewide = workingTraceCode.paraAll[0].byteWide
        p1 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[1])
        bytewide = workingTraceCode.paraAll[1].byteWide
        if("[" in p1):
            p1 = self.setParaPrefix(p1, bytewide)
       
        p0 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[0],bytewide)
        if("[" in p0):
            p0 = self.setParaPrefix(p0, bytewide)
        
        
        
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)
        return

    def movzx_movsx_movsxd_handle(self,opcode):
        for traceCode in self.traceCodeAll:
            if(opcode in traceCode.tvmAsm.getopcodename()):
                bytewide1 = traceCode.paraAll[1].byteWide
            elif(traceCode.working == True):
                bytewide0 = traceCode.paraAll[0].byteWide
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[0],bytewide0)
                p1 = self.GetAsmPara(traceCode,traceCode.paraAll[1],bytewide1)
                if("[" in p1):
                    p1 = self.setParaPrefix(p1, bytewide1)
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)
        return

    def lea_handle(self):
        workingTraceCode = self.getWorkingTraceCode()
        byteWide = workingTraceCode.paraAll[0].byteWide
        p0 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[0],byteWide)
        p1 = self.GetAsmPara(workingTraceCode,workingTraceCode.paraAll[1],byteWide)
        p1 = "[" + p1 + "]"
        self.asm.addAsmPara(p0,0)
        self.asm.addAsmPara(p1,1)
        return 
    
    def push_handle(self):
        for traceCode in self.traceCodeAll:
            if(traceCode.working == True and "rsp" not in traceCode.paraAll[0].name):
                bytewide = traceCode.paraAll[1].byteWide
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[1])
                if("[" in p0):
                    p0 = self.setParaPrefix(p0, bytewide)
                break
        self.asm.addAsmPara(p0,0)

    def pop_handle(self):
        for traceCode in self.traceCodeAll:
            if(traceCode.working == True and "rsp" not in traceCode.paraAll[0].name):
                bytewide = traceCode.paraAll[1].byteWide
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[0])
                if("[" in p0):
                    p0 = self.setParaPrefix(p0, bytewide)
                break
        self.asm.addAsmPara(p0,0)

    def jcc_handle(self):
        if("r" in self.asm.asmParaAll[0].name):
            return
        jccVadd = int(self.asm.asmParaAll[0].name,16)
        jmpVadd = int(self.asm.asmParaAll[1].name,16)
        jccTageName = None
        jmpTageName = None
        tvmToAsmAll = self.tvmToAsmAll
        ls = tvmToAsmAll.tvmToAsmHead
        while(ls != None):
            if(jccTageName !=None  and jmpTageName!=None):
                break
            if(jccVadd > ls.workingAddList[0] and jmpVadd > ls.workingAddList[0]):
                ls = ls.BLink
                continue
            if(jccVadd <= ls.workingAddList[0] and jccTageName == None):
                jccTageName = ls.asm.setJcctage()
            if(jmpVadd <= ls.workingAddList[0] and jmpTageName == None):
                jmpTageName = "jmp  " + ls.asm.setJcctage()
            ls = ls.BLink
        self.asm.asmParaAll = []
        if(jccVadd == jmpVadd):
            self.asm.addAsmPara(jccTageName,0)
        else:
            self.asm.addAsmPara(jccTageName,0)
            self.asm.jcc_Special = jmpTageName
            #print("%s <----------------------"%jmpTageName)

    def not_handle(self):
        for traceCode in self.traceCodeAll:
            if("not" in traceCode.tvmAsm.getname()):
                p0 = self.GetAsmPara(traceCode,traceCode.paraAll[1])
        self.asm.addAsmPara(p0,0)

    def tvmAsmToAsm(self):
        if(self.asm.opcode == "mov"):
            self.mov_handle()
        elif(self.asm.opcode == "cmp" or self.asm.opcode == "test"):
            self.cmp_test_handle()
        elif(self.asm.opcode !=None and "j" in self.asm.opcode):
            self.jcc_handle()
        elif(self.asm.opcode == "add" or self.asm.opcode == "sub"):
            self.add_sub_handle()
        elif(self.asm.opcode == "lea"):
            self.lea_handle()
        elif(self.asm.opcode == "push"):
            self.push_handle()
        elif(self.asm.opcode == "pop"):
            self.pop_handle()
        elif(self.asm.opcode == "xor"or self.asm.opcode == "and" or self.asm.opcode == "or" or self.asm.opcode == "sar" or self.asm.opcode == "shr" or self.asm.opcode == "shl" or self.asm.opcode == "sbb" or self.asm.opcode == "ror"):
            self.xxx_handle(self.asm.opcode)
        elif(self.asm.opcode == "inc" or self.asm.opcode == "dec"):
            self.inc_dec_handle(self.asm.opcode)
        elif(self.asm.opcode == "movzx" or self.asm.opcode == "movsx" or self.asm.opcode == "movsxd"):
            self.movzx_movsx_movsxd_handle(self.asm.opcode)
        elif(self.asm.opcode == "not"):
            self.not_handle()

    def setASMOpcode_2(self):#只处理 mov lea add sub
        if(self.asm.opcode != None or self.asm.jmp_Special.valid == True):
            return 
        WorkingTraceCode = self.getWorkingTraceCode()
        Flag = 0 #0 lea ,1 mov ,2 add ,3 sub
        isOreg = 0
        for tvmPara in WorkingTraceCode.paraAll:
            traceTaskReg = self.TvmParaTable.getLastDefine(WorkingTraceCode,tvmPara)
            if(traceTaskReg == None):
                isOreg +=1
                continue
            labelAll = traceTaskReg.label
            if(labelAll == None):
                print("setASMOpcode_2 errpr")
                self.print()
                return
            for tvmToAsmPara in labelAll:
                if(tvmToAsmPara.handle == "add" and tvmToAsmPara.usedRF == True):
                    Flag = 2
                    break
                if(tvmToAsmPara.handle == "sub" and tvmToAsmPara.usedRF == True):
                    Flag = 3
                    break
                if(tvmToAsmPara.handle == "mem"):
                    Flag = 1
        if("ip" in WorkingTraceCode.paraAll[0].type and Flag == 0):# 有add [],xxx 这种，所以不能无脑mov
            Flag = 1
        if(isOreg == 2): #mov reg,reg
            Flag = 1
        if(Flag == 0):
            #print("lea")
            self.asm.opcode = "lea"
        elif(Flag == 1):
            #print("mov")
            self.asm.opcode = "mov"
        elif(Flag == 2):
            #print("add")
            self.asm.opcode = "add"
        elif(Flag == 3):
            #print("sub")
            self.asm.opcode = "sub"

    def setASMOpcode_1(self):
        #处理 asmOpcode 和  and  not
        if(self.asm.opcode != None or self.asm.jmp_Special.valid == True):
            return 
        Finsh = False
        haveand = False
        haveadd = False
        addhaveRf = False
        havenot = False
        for traceCode in self.traceCodeAll:
            if("jmp" in traceCode.tvmAsm.getopcodename()):
                self.vjmp_handle(traceCode)
                return
            if("je"in traceCode.tvmAsm.getopcodename()):
                self.vjcc_handle()
                return
            if("ret"in traceCode.tvmAsm.getopcodename()):
                self.asm.opcode = "ret"
                return
            if("and" in traceCode.tvmAsm.getopcodename()):
                haveand = True
                continue
            if("add" in traceCode.tvmAsm.getopcodename()):
                haveadd = True
                if(traceCode.paraAll.__len__()==4):
                    addhaveRf = True
                continue
            if("not" in traceCode.tvmAsm.getopcodename()):
                havenot = True
                continue
            for opcode in tvmToAsm.asmOpcode:
                if(opcode == traceCode.tvmAsm.getopcodename()[0]):
                    self.asm.opcode = opcode
                    return
        if((haveand == True and haveadd == False and havenot == False) or(haveand == True and haveadd==True and addhaveRf == False)):
            self.asm.opcode = "and"
        elif(haveand == False and haveadd == False and havenot == True):
            self.asm.opcode = "not"
        return True

class tvmToAsmAll:#一个函数全部的 ASM
    def __init__(self):
        self.tvmToAsmHead = None
        self.tvmToAsmEnd = None
        self.Count = 0
        self.HEX = None
        self.HEXBaseAdd = 0
        self.HEXCount = 0
        self.HEXEndAdd = 0

    def AddtvmToAsm(self,tvmToAsm):
        if(self.Count == 0):
            self.tvmToAsmHead = self.tvmToAsmEnd = tvmToAsm
            self.Count +=1
        else:
            tvmToAsm.FLink = self.tvmToAsmEnd
            self.tvmToAsmEnd.BLink = tvmToAsm
            self.tvmToAsmEnd = tvmToAsm
            self.Count +=1
        tvmToAsm.tvmToAsmAll = self

    def printAll(self):
        ls = self.tvmToAsmHead
        while(ls != None):
            ls.print()
            print("")
            ls = ls.BLink

    def optimizeAll(self):
        self.removePO_rf()#不处理关于 PO_rf 的一切操作
        self.findPushAndPop()
        ls = self.tvmToAsmHead
        while(ls != None):
            ls.optimize()
            ls = ls.BLink

    def outerror(self):#输出重复引用 （最后发现仅 pop 时对 rsp 的重复引用，特殊处理即可）
        bj = list()
        bjls = list()
        error = list()
        ls = self.tvmToAsmHead
        while(ls != None):
            bjls = set(bj).intersection(set(ls.traceCodeAll))
            if(len(bjls) == 0):
                bj = set(bj).union(set(ls.traceCodeAll))
            else:
                error = set(error).union(set(bjls))
            ls = ls.BLink
        
        for out in error:
            if("mov" not in out.tvmAsm.getopcodename() or "PO" not in out.paraAll[1].name):
                continue
            IsModify = False
            ls = self.tvmToAsmHead
            while(ls != None):
                if(out in ls.traceCodeAll):
                    if(IsModify == True):
                        out.print() #修改后又引用，会出错
                    for traceCode in ls.traceCodeAll:
                        if(traceCode.working == True):
                            if(traceCode.paraAll[0].name == out.paraAll[1].name):
                                IsModify = True
                ls = ls.BLink

    def findPushAndPop(self):#找到全部的push和pop 并修改
        tvmToAsmls = self.tvmToAsmHead
        while(tvmToAsmls != None):
            bjls = []
            All = []
            flag1 = False
            flag2 = False
            findWorkAdd = 0x0
            tvmToAsmlsNext = tvmToAsmls.BLink
            if(tvmToAsmlsNext == None):
                return
            bjls = set(tvmToAsmls.traceCodeAll).intersection(set(tvmToAsmlsNext.traceCodeAll))
            if(len(bjls) == 0):
                tvmToAsmls = tvmToAsmls.BLink
                continue
            All = set(tvmToAsmls.traceCodeAll).union(set(tvmToAsmlsNext.traceCodeAll))
            All = sorted(All, key=lambda x: x.Add, reverse=False) #排序
            for traceCode in All:
                if("mov" in traceCode.tvmAsm.getopcodename() and "PO_rsp" in traceCode.paraAll[0].name):
                    flag1 = True
                if("ipreg" in traceCode.tvmAsm.gettype()):
                    flag2 = True
                if(traceCode.working == True):
                    if(findWorkAdd == 0x0):
                        findWorkAdd = traceCode.Add
                        continue
                    if(traceCode.Add - findWorkAdd <= 0x10):
                        if(flag1 == True and flag2 == True):
                            if(traceCode.paraAll[0].name == "PO_rsp"):
                                tvmToAsmls.asm.opcode = "push"
                            else:
                                tvmToAsmls.asm.opcode = "pop"
                            tvmToAsmls.traceCodeAll = All
                            tvmToAsmls.BLink = tvmToAsmlsNext.BLink
                            tvmToAsmlsNext.BLink.FLink = tvmToAsmls
                            self.Count -=1
            tvmToAsmls = tvmToAsmls.BLink
            continue

    def removePO_rf(self):
        ls = self.tvmToAsmHead
        while ls != None:
            WorkTraceCode = ls.getWorkingTraceCode()
            if(WorkTraceCode.paraAll.__len__() !=0 and "PO_rf" in WorkTraceCode.paraAll[0].name):
                fl = ls.FLink
                bl = ls.BLink
                if(fl == None and bl == None):
                    self.tvmToAsmHead = None
                    self.tvmToAsmEnd = None
                elif(fl == None):
                    self.tvmToAsmHead = bl
                elif(bl == None):
                    fl.BLink = None
                    self.tvmToAsmEnd = fl
                else:
                    fl.BLink = bl
                    bl.FLink = fl
                self.Count -=1
            ls = ls.BLink

    def printAsmAll(self):
        ls = self.tvmToAsmHead
        while ls != None:
            ls.printAsm()
            ls = ls.BLink

    def reSetJccTage(self,jccTage,Add):
        ls = self.tvmToAsmHead
        while ls != None:
            if(ls.asm.opcode!= None and "j" in ls.asm.opcode and ls.asm.asmParaAll.__len__()!=0 and "r"not in ls.asm.asmParaAll[0].name):
                p0 = ls.asm.asmParaAll[0].name
                jcc_Special = ls.asm.jcc_Special
                if(jccTage in p0):
                    ls.asm.asmParaAll.remove(ls.asm.asmParaAll[0])
                    ls.asm.addAsmPara(hex(Add),0)
                if(jcc_Special != None and jccTage in jcc_Special):
                    ls.asm.jcc_Special ="jmp  " +  hex(Add)
            ls = ls.BLink

    def AllTvmAsmToAsm(self):
        ls = self.tvmToAsmHead
        while ls != None:
            ls.setASMOpcode_1()
            ls.record_tage()
            ls.setASMOpcode_2()
            ls.tvmAsmToAsm()
            ls = ls.BLink
        ls = self.tvmToAsmHead
        # while ls != None:
        #     ls.asm.print()
        #     ls.print()
        #     print("")
        #     ls = ls.BLink

    def removeTvmToAsm(self,workAdd):
        ls = self.tvmToAsmHead
        while ls != None:
            if(workAdd in ls.workingAddList):
                #print("%x<<---------------------------------------------------------------------"%ls.workingAddList[0])
                fl = ls.FLink
                bl = ls.BLink
                if(fl == None and bl == None):
                    self.tvmToAsmHead = None
                    self.tvmToAsmEnd = None
                elif(fl == None):
                    self.tvmToAsmHead = bl
                elif(bl == None):
                    fl.BLink = None
                    self.tvmToAsmEnd = fl
                else:
                    fl.BLink = bl
                    bl.FLink = fl
                self.Count -=1
            ls = ls.BLink
        return

    def ASMTOHEX_ERROR(self,HEXBaseAdd):#这个有bug，因为keystone有问题，所以不能批量将ASM编译成HEX
        self.HEXBaseAdd = HEXBaseAdd
        allcode = ""
        ls = self.tvmToAsmHead
        while ls != None:
            allcode = allcode + ls.asm.getStr()+"\n"
            ls = ls.BLink
        #print(allcode)
        try:
            self.HEX,self.HEXCount = ASM2HEX.asm(allcode,addr=HEXBaseAdd)
            self.HEXCount = self.HEX.__len__()
        except:
            print("ASMTOHEX ERROR<--------------------------------------------------------------------")
        return self.HEXCount + HEXBaseAdd

    def ASMTOHEX(self,HEXBaseAdd):
        self.HEXBaseAdd = HEXBaseAdd
        ss = HEXBaseAdd
        ls = self.tvmToAsmHead
        while ls != None:#第一轮不处理 jcc near (预留0x20 字节空间给Jcc)
            if(ls.asm.jcc_Tage != None):
                self.reSetJccTage(ls.asm.jcc_Tage,ss)
            if(ls.asm.opcode != None and "j" in ls.asm.opcode):# FF25 属于 jmp_Special 这里不会遇到
                ls.asm.HEXAdd = ss
                ss = ss+0x20
                ls = ls.BLink
                continue
            ss = ls.asm.AsmToHex(ss)
            ls = ls.BLink
        ls = self.tvmToAsmHead
        while ls != None:#第二轮只处理 jcc near
            if(ls.asm.opcode != None and "j" in ls.asm.opcode):
                ls.asm.AsmToHex(0) #上一轮已经设置了地址了
            ls = ls.BLink
        self.HEXEndAdd = ss
        return ss

    def WriteHex_ERROR(self):
        #memcpy(self.HEXBaseAdd,self.HEX,self.HEXCount)

        rr = HEX2ASM.disasm_lite(bytes(self.HEX),self.HEXBaseAdd)
        for inst in rr:
            print("%s  "%inst[2],end="")
            print("%s  "%inst[3])

        # print("%x"%self.HEXBaseAdd)
        # for i in range(self.HEXCount):
        #     print("\\x%02x"%self.HEX[i],end="")
        #     # if(i % 0x10 == 0):
        #     #     print("")

    def WriteHex(self):
        ls = self.tvmToAsmHead
        while ls != None:#第一轮不处理 jcc near (预留0x20 字节空间给Jcc)
            ls.asm.AsmWrite()
            ls = ls.BLink
        
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

    def next_rip(self,add):
        nextadd = add + idautils.DecodeInstruction(add).size
        auto_make_code(nextadd)
        #del_items
        if(tvmFunTask.global_s_jmp in idc.GetDisasm(add)):
            if(idc.print_operand(add,0) in REG):
                return None
            ra = idc.get_operand_value(add,0)
            if(ra >= self.tvm0base):
                create_insn(ra)
                return ra
            else:
                return find_code(add,SEARCH_DOWN)
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

    def IsVStart(self,add):#判断是否为VRIP
        Tage = add
        Vadd = 0
        if(tvmFunTask.global_s_r11 in idc.print_operand(add,0) and (tvmFunTask.global_s_lea in idc.GetDisasm(add) or tvmFunTask.global_s_mov in idc.GetDisasm(add) )):
            for i in range(20):
                Tage = self.next_rip(Tage)
                create_insn(Tage)
                if(tvmFunTask.global_s_call in idc.GetDisasm(Tage)):
                    Vadd = idc.get_operand_value(add,1)
                    if(Vadd >= self.tvm0base and Vadd>0):
                        return Vadd
                    else:
                        continue
        return Vadd

    def GetVStart(self):#获取VRIP
        Tage = self.FunStart
        if("jmp" not in idc.GetDisasm(Tage)):
            return
        if(Tage == 0):
            return
        for i in range(0x100):
            if(tvmFunTask.global_s_call in idc.GetDisasm(Tage) or tvmFunTask.global_s_ret in idc.GetDisasm(Tage)):
                return
            Vadd = self.IsVStart(Tage)
            if(Vadd != 0 ):
                self.VStart = Vadd
                return 
            Tage = self.next_rip(Tage)
            if(Tage == None):
                return

class traceTask:
    def __init__(self,FunStart,tvm0base):
        self.AlltraceCode = traceCodeAll()
        self.traceTaskRegTable = traceTaskRegTable()
        self.tvmToAsmAll = tvmToAsmAll()   
        self.tvmFunTask = tvmFunTask(FunStart,tvm0base)
        self.tvmFunTask.GetVStart()
        self.VStart = self.tvmFunTask.VStart
        self.VEnd = 0
        return
    
    def track(self,n):
         V_RIP = self.VStart
         js = 0
         while 1:
            Tage = TVMTABEL.getTvmAsm(idc.byte_value(get_16bit(V_RIP)))
            if(Tage == None):
                if(idc.byte_value(get_16bit(V_RIP)) == 0x5d):
                    self.VEnd = tvmcode.Add
                    return True
                print("Error!!")
                return False
            V_RIP +=1
            opcodename = Tage.getname()
            tvmcode = traceCode(V_RIP-1,Tage)
            type = Tage.gettype()
            for i in range(type.__len__()):
                Find = False
                isReg = False
                if("reg" in type[i]):
                    ls = get_16bit(V_RIP)
                    ls = ls ^ Tage.xor
                    isReg = True
                    V_RIP += 2
                    Find = True
                elif("ll" in type[i] and Find == False):
                    ls = get_64bit(V_RIP)
                    V_RIP +=8
                    Find = True
                    
                elif("l" in type[i] and Find == False):
                    ls = get_32bit(V_RIP)
                    V_RIP +=4
                    Find = True
                    
                elif("w" in type[i] and Find == False):
                    ls = get_16bit(V_RIP)
                    V_RIP +=2
                    Find = True
                    
                elif("b" in type[i] and Find == False):
                    ls = idc.byte_value(get_16bit(V_RIP))
                    V_RIP +=1
                    Find = True

                if(isReg == True):
                    xxreg = getxxreg(ls)
                    if(xxreg == None):
                        xxreg = hex(ls)
                        sreg = "[ r10 + "+xxreg+" ]"
                    else:
                        sreg = xxreg
                    tvmcode.addPara(sreg,type[i])
                else:
                    snum  =hex(ls)
                    tvmcode.addPara(snum,type[i])
            if("jmp" in opcodename or "je" in opcodename or "int3" in opcodename or(tvmcode.paraAll[0].name in WORKINGREG  or "ip" in Tage.gettype()[0]) or "test" in opcodename or "cmp" in opcodename or  "ret" in opcodename or "rep" in opcodename):
                if("int3" in opcodename):
                    tvmcode.setWorking()
                elif( "rf" not in tvmcode.paraAll[0].name):
                    tvmcode.setWorking()
                    if(n>0):
                        if(js<n):
                            js +=1
                        else:
                            return
            self.AlltraceCode.addtraceCode(tvmcode)
            # if("mul" in tvmcode.tvmAsm.getopcodename()):
            #     tvmcode.print()
            if(Tage.type.__len__() != 0 and "ip"not in Tage.gettype()[0] and("o" in Tage.gettype()[0] or "mov" in Tage.getname())):
                self.traceTaskRegTable.addRegdefine(tvmcode.paraAll[0],tvmcode)
                # if(tvmcode.Add == 0x1400277be):
                #     tvmcode.print()
            if(Tage.type.__len__() != 0 and Tage.gettype().__len__()>=3 and "o" in Tage.gettype()[Tage.gettype().__len__()-1]):
                self.traceTaskRegTable.addRegdefine(tvmcode.paraAll[Tage.gettype().__len__()-1],tvmcode)

            if(Tage.type.__len__() != 0 and Tage.gettype().__len__() == 4 and "mul" in Tage.getname()):
                self.traceTaskRegTable.addRegdefine(tvmcode.paraAll[0],tvmcode)
                self.traceTaskRegTable.addRegdefine(tvmcode.paraAll[1],tvmcode)
                #print("imul")
            # if("int3"in opcodename  or "ret"in opcodename):
            #     self.VEnd = tvmcode.Add
            #     return True
    
    def traceOut(self):
        self.AlltraceCode.out()
        return

    def checkVREGproto(self,traceCode,defineRecord,useLabel):            #查找VREG引用路径，到原型(整数赋值或OREG赋值)为止
        findDefinePara = self.traceTaskRegTable.findLastDefine(traceCode,useLabel)
        for traceTaskReg in findDefinePara:
            #print(" %x "%traceTaskReg.traceCode.Add)
            self.checkVREGproto(traceTaskReg.traceCode,defineRecord,useLabel)
            if(traceTaskReg not in defineRecord.defineRecord):
                defineRecord.addRecord(traceTaskReg)
        
    def VRegRecord(self,useLabel):
        bftraceCodeAll = copy.deepcopy(self.AlltraceCode.traceCodeAll)  #深度拷贝，不影响原来
        for traceCode in bftraceCodeAll:
            defineRecord = defineRecordAll()
            lstraceCodeAll = list()
            # if(traceCode.Add == 0x1400277be):
            #     traceCode.print()
            if(traceCode.working == False):
                continue
            lstvmToAsm = tvmToAsm()
            if("mov" in traceCode.tvmAsm.getname()):
                o_tracecode_para_1 = traceCode.paraAll[1]

            self.checkVREGproto(traceCode,defineRecord,useLabel)
            for traceTaskReg in defineRecord.defineRecord:
                lstraceCodeAll.append(traceTaskReg.traceCode)
                #traceTaskReg.traceCode.print()
            #traceCode.print()
            lstraceCodeAll.append(traceCode)
            if(useLabel == True):
                if("mov" in traceCode.tvmAsm.getname() and traceCode.paraAll[0].name in WORKINGREG):
                    self.traceTaskRegTable.settraceTaskRegLabel(o_tracecode_para_1,traceCode,traceCode.paraAll[0])#设置标签
            lstvmToAsm.traceCodeAll = sorted(lstraceCodeAll, key=lambda x: x.Add, reverse=False)
            self.tvmToAsmAll.AddtvmToAsm(lstvmToAsm)
            
            #print("")

    
def tvmHandleTableInit():        
    TVMTABEL.append("v_sar_oregll_iregll_iregb_oregl",0x01,0xF8BE)
    TVMTABEL.append("v_or_oregll_iregll_iregll_oregl",0x1D,0x4AA7)
    TVMTABEL.append("v_mov_iregll_iregl",0x2B,0xBF3E)
    TVMTABEL.append("v_movzx_iregl_iregb",0x2F,0x7EE9)
    TVMTABEL.append("v_ror_oregb_iregb_iregb_oregl",0x3C,0xF8E1)
    TVMTABEL.append("v_mov_iregl_iregl",0x4A,0x564B)
    TVMTABEL.append("v_mov_iregw_iregw",0x4B,0xD916)
    TVMTABEL.append("v_add_oregb_iregb_iregb_oregl",0x4C,0xDD9D)
    TVMTABEL.append("v_add_oregll_iregll_iregll",0x4D,0x477D)
    TVMTABEL.append("v_add_oregl_iregl_iregl_oregl",0x4E,0xA9C7)
    TVMTABEL.append("v_add_oregw_iregw_iregw_oregl",0x4F,0x82BC)
    TVMTABEL.append("v_sub_oregl_iregl_iregl_oregl",0x5A,0xC198)
    TVMTABEL.append("v_sar_oregl_iregl_iregb_oregl",0x06,0x8374)
    TVMTABEL.append("v_and_oregl_iregl_iregl_oregl",0x6A,0x5CF0)
    TVMTABEL.append("v_and_oregll_iregll_iregll_oregl",0x6D,0xD9B1)
    TVMTABEL.append("v_and_oregl_iregl_iregl",0x6E,0xA1CE)
    TVMTABEL.append("v_xor_oregl_iregl_iregl_oregl",0x7A,0xD8ED)

    TVMTABEL.append("v_mov_ipreg_iregll",0x7D,0xD878)
    TVMTABEL.append("v_shr_oregll_iregll_iregb_oregl",0x09,0x9D87)
    TVMTABEL.append("v_int3",[0x9a,0x9b,0x98,0x99,0x9c,0x9d,0xe2,0xe3,0xe0,0xe1,0xe6,0xe7,0xe4,0xeb,0xec,0xed,0xf2,0xf3,0xf0,0xf1,0xf6,0xf7,0xf5,0xfa,0xfb,0xf9,0xfe,0xff,0xc2,0xc0,0xc1,0xc6,0xc7,0xc4,0xc5,0xc8,0xce,0xcf,0xcc,0xcd,0xdb,0xd8,0xde,0xdf,0xdc,0xdd,0x23,0x26,0x27,0x24,0x2a,0x28,0x2e,0x2c,0x2d,0x32,0x33,0x30,0x31,0x36,0x37,0x34,0x35,0x3a,0x3b,0x38,0x39,0x3e,0x3f,0x3d,0x2,0x3,0x0,0x7,0x4,0x5,0xa,0xb,0x8,0xe,0xf,0xd,0x12,0x13,0x10,0x17,0x14,0x15,0x1a,0x1b,0x18,0x1e,0x1f,0x1c,0x63,0x61,0x66,0x67,0x64,0x6b,0x69,0x6f,0x6c,0x71,0x76,0x77,0x74,0x7b,0x79,0x7e,0x7f,0x7c,0x53,0x50,0x55,0x5b,0x58,0x59,0x5e,0x5f,0x5c],0x0000)                                       #here
    TVMTABEL.append("v_jmp_iregxR11",0x9E,0x0AD7)                              #here
    TVMTABEL.append("v_jmp_iregxR10",0x9F,0x2E72)                              #here
    TVMTABEL.append("v_shl_oregll_iregll_iregb_oregl",0x11,0x5403)
    TVMTABEL.append("v_shl_oregl_iregl_iregb_oregl",0x16,0xEEF7)
    TVMTABEL.append("v_not_oregll_iregll",0x19,0x1400)
    TVMTABEL.append("v_setz_oregb_iregl",0x20,0x0D45)
    TVMTABEL.append("v_movsxd_iregll_iregl",0x21,0x8BC8)
    TVMTABEL.append("v_setR8d_iregl",0x22,0x77D7)
    TVMTABEL.append("v_movsx_iregl_iregb",0x25,0xD8E4)
    TVMTABEL.append("v_movzx_iregl_iregw",0x29,0xF10A)
    TVMTABEL.append("v_mov_ipreg_iregb",0x40,0xE304)
    TVMTABEL.append("v_mov_iregll_ipreg",0x41,0xE229)
    TVMTABEL.append("v_mov_ipreg_iregl",0x42,0x5431)
    TVMTABEL.append("v_mov_ipreg_iregw",0x43,0x02CB)

    TVMTABEL.append("v_mov_iregb_ipreg",0x44,0xBE8C)
    TVMTABEL.append("v_mov_iregll_iregll",0x45,0x58FB)
    TVMTABEL.append("v_mov_iregl_ipreg",0x46,0x10BC)
    TVMTABEL.append("v_mov_iregw_ipreg",0x47,0x6F62)
    TVMTABEL.append("v_mov_iregb_iregb",0x48,0xCFFE)
    TVMTABEL.append("v_add_oregll_iregll_iregll_oregl",0x49,0x41AA)
    TVMTABEL.append("v_not_oregll_iregll",0x51,0xDB42)
    TVMTABEL.append("v_add_oregl_iregl_iregl",0x52,0x77C6)
    TVMTABEL.append("v_not_oregb_iregb",0x54,0xDCF3)
    TVMTABEL.append("v_not_oregl_iregl",0x56,0xE297)
    TVMTABEL.append("v_not_oregw_iregw",0x57,0x666D)
    TVMTABEL.append("v_or_oregb_iregb_iregb_oregl",0x60,0xFBFD)
    TVMTABEL.append("v_or_oregl_iregl_iregl_oregl",0x62,0x7819)
    TVMTABEL.append("v_and_oregll_iregll_iregll_oregl",0x65,0x2954)
    TVMTABEL.append("v_and_oregb_iregb_iregb_oregl",0x68,0xD8A5)
    TVMTABEL.append("v_and_oregb_iregb_iregb_oregl",0x70,0x64D1)
    TVMTABEL.append("v_and_oregl_iregl_iregl_oregl",0x72,0x4A64)

    TVMTABEL.append("v_and_oregw_iregw_iregw_oregl",0x73,0xB562)
    TVMTABEL.append("v_xor_oregll_iregll_iregll_oregl",0x75,0x69C2)
    TVMTABEL.append("v_xor_oregb_iregb_iregb_oregl",0x78,0x19C1)
    TVMTABEL.append("v_ret_iregx",0x95,0x805C)                                  #here
    TVMTABEL.append("v_shr_oregb_iregb_iregb_oregl",0x0c,0x62D7)
    TVMTABEL.append("v_dec_oregl_iregl_oregl",0xc3,0x467C)
    TVMTABEL.append("v_inc_oregb_iregb_oregl",0xc9,0x4267)
    TVMTABEL.append("v_inc_oregll_iregll_oregl",0xca,0x6EE0)
    TVMTABEL.append("v_inc_oregl_iregl_oregl",0xcb,0x7FB4)
    TVMTABEL.append("v_test_iregw_iregw_oregl",0xd0,0x0499)
    TVMTABEL.append("v_test_iregb_iregb_oregl",0xd1,0x2A99)
    TVMTABEL.append("v_test_iregll_iregll_oregl",0xd2,0x8606)
    TVMTABEL.append("v_test_iregl_iregl_oregl",0xd3,0x7FDE)
    TVMTABEL.append("v_cmp_iregw_iregw_oregl",0xd4,0x87DF)
    TVMTABEL.append("v_cmp_iregb_iregb_oregl",0xd5,0x3728)
    TVMTABEL.append("v_cmp_iregll_iregll_oregl",0xd6,0x637D)
    TVMTABEL.append("v_cmp_iregl_iregl_oregl",0xd7,0xCBEF)

    TVMTABEL.append("v_sbb_oregb_iregb_iregb_oregl",0xd9,0x3F78)
    TVMTABEL.append("v_sbb_oregll_iregll_iregll_oregl",0xda,0x0E0D)
    TVMTABEL.append("v_jmp_iregxRax",0xe5,0xCD84)
    TVMTABEL.append("v_mov_iregll_ll",0xe8,0x3F26)
    TVMTABEL.append("v_mov_iregl_l",0xe9,0x448A)
    TVMTABEL.append("v_mov_iregll_ll",0xea,0x43EF)
    TVMTABEL.append("v_mov_iregw_w",0xee,0x44B1)
    TVMTABEL.append("v_mov_iregb_b",0xef,0x144C)
    TVMTABEL.append("v_mul_oregll_oregll_iregll_iregll",0xf4,0xEB97)
    TVMTABEL.append("v_jmp_ll",0xf8,0x0000)
    TVMTABEL.append("v_rep stosb_iregll_iregb_iregll",0xfc,0x8D54)
    TVMTABEL.append("v_je_iregb_ll_ll",0xfd,0xDE5E)
    return
tvmHandleTableInit()

def main0():
    allTraceTask = []
    Start = detvmSegmBase + 10
    for func in idautils.Functions():
        if(func > tvm0base):
            continue
        ls = traceTask(func,tvm0base)
        if(ls.tvmFunTask.VStart > 0x140000000):
            allTraceTask.append(ls)
            print("add: %x vadd: %x "%(ls.tvmFunTask.FunStart,ls.VStart),end="")
            ls.track(0)
            print("vend: %x"%(ls.VEnd))
            ls.VRegRecord(True)
            ls.tvmToAsmAll.optimizeAll()
            ls.tvmToAsmAll.AllTvmAsmToAsm(ls.VStart,ls.VEnd)
            Start = ls.tvmToAsmAll.ASMTOHEX(Start)
            Start += 0x10
    Ic_add_segment(detvmSegmBase,Start,".icey")
    mrsel = get_segm_by_name(".text")
    set_default_dataseg(mrsel.sel)
    for Task in allTraceTask:
        Task.tvmToAsmAll.WriteHex()
    auto_wait()
    for Task in allTraceTask:
        #print("destrart:%x  deend:%x"%(Task.tvmToAsmAll.HEXBaseAdd,Task.tvmToAsmAll.HEXEndAdd))
        patchDword = Task.tvmToAsmAll.HEXBaseAdd - (5 + Task.tvmFunTask.FunStart)
        patchAdd = Task.tvmFunTask.FunStart + 1
        patch_dword(patchAdd,patchDword)
        create_insn(Task.tvmToAsmAll.HEXBaseAdd)
        add_func(Task.tvmToAsmAll.HEXBaseAdd,Task.tvmToAsmAll.HEXEndAdd)
        set_name(Task.tvmToAsmAll.HEXBaseAdd,"ic_sub_"+hex(Task.tvmFunTask.FunStart))
    print("finsh<------------------------------------------------")
    return

def main1():
    testTrace = traceTask(0x140001250,tvm0base)  	#tvm0base是tvm0段的起始地址
    testTrace.track(0)								#开始跟踪 得到traceCode
    testTrace.VRegRecord(True)						#如果是False就是不使用标记（上文说过）
    testTrace.tvmToAsmAll.optimizeAll()				#变量传播优化,push、pop优化
    testTrace.tvmToAsmAll.AllTvmAsmToAsm() 			#转换成ASM
    tvmToAsm_P = testTrace.tvmToAsmAll.tvmToAsmHead         #结构为tvmToAsm
    while (tvmToAsm_P != None):
        tvmToAsm_P.printAsm()                       #输出Asm
        tvmToAsm_P.print()                          #输出traceCodeAll
        print("")                                   #隔开
        tvmToAsm_P = tvmToAsm_P.BLink               #下一个



if(__name__ == "__main__"):
    used = 1 # 0:全部  1:单个
    if(used == 0):
        main0()
    else:
        main1()