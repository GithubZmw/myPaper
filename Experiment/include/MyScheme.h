#include "common.h"
#include <map>

BIG order;
csprng rng1;//随机数发生器

// 通讯消息格式定义
typedef struct {
    ECP C_i;
    ECP W_i;
}Msg1;

typedef struct {
    BIG c;
    BIG su;
    BIG ss;
    ECP2 T1;
    ECP2 T2;
    ECP2 T3;
    ECP A_1;
    ECP A_2;
}Msg2;


// 智能设备实体
typedef struct {
    BIG id_i;
    BIG s_i;
    ECP C_i;
    ECP W_i;
} SD;


// 域管理员的实体
typedef struct{
  BIG id_i;
  ECP2 si_P;
  bool isJoin;
  ECP W_i;
}itemDM;


typedef struct{
    BIG q;
    BIG x;
    ECP P_1;
    ECP2 P_2;
    ECP2 P_pub;
    ECP ACC;
    vector<itemDM> L;
}DM;

// 方案相关的操作
void Update(SD *sd,DM dm);
void Setup(DM *dm);
Msg1 Join_DM(DM *dm, BIG id_i, BIG x);
void Join_SD_step2(SD *sd, BIG id_i, Msg1 msg1,DM dm);
Msg2 Sign(SD sd, DM dm);
bool Verify(Msg2 msg2, DM dm);
itemDM Open(Msg2 msg2, DM dm);
void Revoke(itemDM item, DM *dm);


// 其他操作【包括初始化，测试所用的函数】
void hashtoZp384(BIG num, octet *ct, BIG q);
void hashToZp384(BIG res, BIG beHashed, BIG q);
void initRNG(core::csprng *rng);
void randBigInt(BIG *big);
FP12 e(ECP alpha1, ECP2 alpha2);
void showItem(itemDM item);
void showDM(DM dm);
void showSD(SD sd);
void showMsg2(Msg2 msg2);



// 区块链实体
vector<DM> BC;


