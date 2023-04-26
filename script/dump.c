#include<idc.idc>

static main(){
    auto i,fp;
    fp = fopen("F:\\所有作业\\tx初赛2\\2023腾讯游戏安全技术竞赛-PC客户端安全-决赛题目\\决赛题附加题附件\\tack\\1400DC86A.bin","rb");
    auto kk = loadfile(fp,0,0x140001000,0x26000);
    if(kk ==1){
        Message("ok!\n");
    }
    else{
        Message("NO!\n");
    }
}

static main(){
    auto i,fp;
    fp = fopen("F:\\所有作业\\tx初赛2\\2023腾讯游戏安全技术竞赛-PC客户端安全-决赛题目\\决赛题附加题附件\\tack\\1400DC86A.bin","wb");
    auto kk = savefile(fp,0,0x1400DC86A,0x640);
    if(kk ==1){
        Message("ok!\n");
    }
    else{
        Message("NO!\n");
    }
}