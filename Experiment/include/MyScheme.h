#include "common.h"
#include <map>

// 通讯消息格式定义
typedef struct {
    int j;
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
    int j;
    BIG s_i;
    ECP C_i;
    ECP W_i;

} SD;


// 域管理员的实体

typedef struct{
  int j;
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


void Join_SD_step1();
void Join_SD_step2(BIG id_i,Msg1 msg1);
Msg2 Sign(SD sd,DM dm);
void Update();



void Setup(DM *dm);
Msg1 Join_DM(DM *dm, BIG id_i, BIG x);
bool Verify(Msg2 msg2);
void Open();
void Revoke();


// 区块链实体
vector<DM> BC;


