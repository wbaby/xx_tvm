#include <idc.idc>
extern global_s_push;
extern global_s_jmp;
extern global_s_pop;
extern global_s_mov;
extern global_s_lea;
extern global_s_add;

static memset(x, val, len)
{
    auto i;
    for (i = 0; i < len; i++)
    {
        PatchByte(x + i, val);
    }
}

static GetmovOrLea(add){//传入push 的地址 ，返回 lea reg ，或 mov reg 的地址（10条以内）
    auto s_reg = GetOpnd(add,0);
    auto Tage = add;
    auto i=0;auto cs;
    auto isMov = 0,isLea = 0;
    for(i=0;i<5;i++){
        Tage = FindCode(Tage,SEARCH_DOWN);
        cs = GetDisasm(Tage);
        isMov = (stristr(cs,global_s_mov)!=-1);
        isLea = (stristr(cs,global_s_lea)!=-1);
        if(isMov && stristr(GetOpnd(Tage,0),s_reg) != -1){
            return Tage;
        }else if(isLea && stristr(GetOpnd(Tage,0),s_reg) != -1){
            return Tage;
        }else{
            continue;
        } 
    }
    return -1;
}

static GetJmpAdd(add){ //传入入push 的地址,返回 jmp地址
    auto s_reg = GetOpnd(add,0);
    auto Tage = add;
    auto i=0;auto cs;
    auto isJmp = 0;
    for(i=0;i<10;i++){
        Tage = FindCode(Tage,SEARCH_DOWN);
        cs = GetDisasm(Tage);
        isJmp = (stristr(cs,global_s_jmp)!=-1);
        if(isJmp && stristr(GetOpnd(Tage,0),s_reg) != -1){
            return Tage;
        }else{
            continue;
        } 
    }
    return -1;
}

static GetTrueAdd(add){//传入 lea 、mov 指令的地址
    auto s_reg = GetOpnd(add,0);
    auto cs = GetDisasm(add);
    auto isMov = 0,isLea = 0;
    auto as = GetOperandValue(add,1);
    isMov = (stristr(cs,global_s_mov)!=-1);
    isLea = (stristr(cs,global_s_lea)!=-1);
    auto Tage = add;
    auto i = 0;
    if(isMov){
        for(i=0;i<5;i++){
            Tage = FindCode(Tage,SEARCH_DOWN);
            if(stristr(GetDisasm(Tage),global_s_add)!=-1 && stristr(GetOpnd(add,0),s_reg) != -1){
                return as + GetOperandValue(Tage,1);
            }
        }
    }else if(isLea){
         for(i=0;i<5;i++){
            Tage = FindCode(Tage,SEARCH_DOWN);
            if(stristr(GetDisasm(Tage),global_s_lea)!=-1 && stristr(GetOpnd(add,0),s_reg) != -1){
                return as + GetOperandValue(Tage,1);
            }
        }
    }
    return -1;
}


static main(){
    global_s_push = "push";
    global_s_jmp = "jmp";
    global_s_pop = "pop";
    global_s_mov = "mov";
    global_s_lea = "lea";
    global_s_add = "add";


    
    
    auto CurrentFunStar = GetFunctionAttr(ScreenEA(),FUNCATTR_START);
    auto CurrentFunEnd = GetFunctionAttr(ScreenEA(),FUNCATTR_END) + 1;//retn
    auto Tage = ScreenEA();

    auto movOrlea;
    auto TrueAdd;
    auto JmpAdd;
    auto JmpSize,popSize;
    auto offset = 0;
    // while(Tage < CurrentFunEnd){
    //     Tage = FindCode(Tage,SEARCH_DOWN);
    //     if(stristr(GetDisasm(Tage),global_s_push)!= -1){
    //         //符合push reg
    //        movOrlea = GetmovOrLea(Tage);
    //        if(movOrlea == -1){
    //         continue;
    //        }
    //        JmpAdd = GetJmpAdd(Tage);
    //        if(JmpAdd == -1){
    //         continue;
    //        }
    //        TrueAdd = GetTrueAdd(movOrlea);
    //        if(TrueAdd == -1){
    //         continue;
    //        }
    //        memset(Tage,0x90,FindCode(JmpAdd,SEARCH_DOWN)-Tage);
    //        memset(TrueAdd,0x90,FindCode(TrueAdd,SEARCH_DOWN) - TrueAdd);
    //        offset =TrueAdd - (Tage + 5);
    //        //Message("%x %x %x %x %x\n",Tage,movOrlea,JmpAdd,TrueAdd,offset); 
    //        PatchByte(Tage,0xe9);
    //        PatchDword(Tage+1,offset);
    //        Message("%x %x\n",movOrlea,TrueAdd); 
    //     }
    // }
    auto i = 0;
    //auto offset = 0;
    for(i = 0;i<100;i++){
        Tage = FindCode(Tage,SEARCH_DOWN);
        if(stristr(GetDisasm(Tage),global_s_push)!= -1){
            //符合push reg
           movOrlea = GetmovOrLea(Tage);
           if(movOrlea == -1){
            continue;
           }
           JmpAdd = GetJmpAdd(Tage);
           if(JmpAdd == -1){
            continue;
           }
           TrueAdd = GetTrueAdd(movOrlea);
           if(TrueAdd == -1){
            continue;
           }
           memset(Tage,0x90,FindCode(JmpAdd,SEARCH_DOWN)-Tage);
           memset(TrueAdd,0x90,FindCode(TrueAdd,SEARCH_DOWN) - TrueAdd);
           offset =TrueAdd - (Tage + 5);
           //Message("%x %x %x %x %x\n",Tage,movOrlea,JmpAdd,TrueAdd,offset); 
           PatchByte(Tage,0xe9);
           PatchDword(Tage+1,offset);
           break;
        }
    }
    Message("end\n");
    return 0;
    
} //memset(Tage,0x90,FindCode(ls,SEARCH_DOWN)-Tage);