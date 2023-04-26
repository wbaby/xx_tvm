#include <idc.idc>

static memset(x, val, len)
{
    auto i;
    for (i = 0; i < len; i++)
    {
        PatchByte(x + i, val);
    }
}

static main(){
    auto s_push = "push";
    auto s_jmp = "jmp";
    auto s_pop = "pop";

    auto CurrentFunStar = GetFunctionAttr(ScreenEA(),FUNCATTR_START);
    auto CurrentFunEnd = GetFunctionAttr(ScreenEA(),FUNCATTR_END) - 1;//retn
    auto Tage = CurrentFunStar;
    while(Tage != CurrentFunEnd){
        if(stristr(GetDisasm(Tage),s_push)!= -1){
            //符合push reg
            auto ls = Tage,i=0,s_reg = GetOpnd(Tage,0);
            for(i = 0;i<10;i++){
                //往下找十条有没有 jmp reg
                ls = FindCode(ls,SEARCH_DOWN);
                if(stristr(GetDisasm(ls),s_jmp)!=-1 && stristr(GetOpnd(ls,0),s_reg) != -1){
                    ls = FindCode(ls,SEARCH_DOWN);
                    if(stristr(GetDisasm(ls),s_pop)!=-1 && stristr(GetOpnd(ls,0),s_reg) != -1){
                        Message("here: %x\n",Tage);
                        memset(Tage,0x90,FindCode(ls,SEARCH_DOWN)-Tage);

                        break;
                    }
                }
            }
        }
        Tage = FindCode(Tage,SEARCH_DOWN);
    }
    Message("end\n");
    return 0;
    
}