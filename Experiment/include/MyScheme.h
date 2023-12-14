#include "common.h"
#include <map>

/**
	@brief Msg1 Structure - 加入过程中DM给SD生成的证书
*/
typedef struct {
    ECP2 C_i;/** DM给SD颁发的群成员证书 */
    ECP2 W_i;/** DM给SD颁发的未被撤销证明 */
}Msg1;


/**
	@brief Msg2 Structure - 这是跨域认证中SD生成的跨域认证签名sigma
*/
typedef struct {
    BIG c;
    BIG su;
    BIG ss;
    ECP T1;
    ECP T2;
    ECP T3;
    ECP2 A_1;
    ECP2 A_2;
}Msg2;

/**
	@brief SD Structure - 实体SD，它代表我们方案中的智能设备实体
*/
typedef struct {
    BIG id_i;/** 智能设备SD的真实身份 */
    BIG s_i;/** 智能设备SD的私钥 */
    ECP2 C_i;/** 域管理员DM为智能设备SD颁发的群成员证书 */
    ECP2 W_i;/** 域管理员DM给智能设备SD颁发的未被撤销证明 */
} SD;


/**
	@brief itemDM Structure - 实体DM中的列表项，它代表我们方案中的原管理员DM存储的列表L中的项
    @brief itemDM Structure - 里面存储了每个加入该域的智能设备SD的相关信息，用于身份追踪
*/
typedef struct{
  BIG id_i;/** 智能设备SD的真实身份 */
  ECP si_P;
  bool isJoin;/** 智能设备SD加入群组时，值为true；它被域管理员DM撤销时，值为false */
  ECP2 W_i;/** 智能设备SD加入后累加器的值，用于验证 */
}itemDM;

/**
	@brief DM Structure - 实体DM，它代表我们方案中的域管理员实体，存储由系统参数等信息
*/
typedef struct{
    BIG q;/** 系统参数，椭圆曲线的阶 */
    BIG x;/** 域管理员DM的私钥 */
    ECP P_1;/** 群G1的生成元 */
    ECP2 P_2;/** 群G2的生成元 */
    ECP P_pub;/** 群公钥 */
    ECP2 ACC;/** 当前累加器的值 */
    vector<itemDM> L;/** 域管理员DM存储的云成员信息 */
}DM;

/**
 * 哈希函数
 * @param c 哈希的结果
 * @param T1 待哈希的值
 * @param T2 待哈希的值
 * @param T3 待哈希的值
 * @param A1 待哈希的值
 * @param A2 待哈希的值
 * @param R1 待哈希的值
 * @param R2 待哈希的值
 * @param R3 待哈希的值
 * @param R4 待哈希的值
 * @param dm 待哈希的值
 */
void H(BIG *c,ECP T1,ECP T2,ECP T3,ECP2 A1,ECP2 A2,ECP R1,ECP R2,FP12 R3,ECP R4,DM dm);

/**
 * 更新设备的证据,未被撤销的智能设备可以使用这个函数更新自己的证据.被撤销的设备使用这个函数无法更新自己的证据
 * @param sd 智能设备
 * @param dm 域管理员
 */
void Update(SD *sd,DM dm);
/**
 * 域管理员的初始化阶段，生成系统参数供其他实体使用
 * @param dm 域管理员
 */
void Setup(DM *dm);
/**
 * 加入过程SD执行的第一阶段，SD生成自己的身份
 * @param sd 智能设备SD
 * @param id_i 这能设备的身份
 */
void Join_SD_step1(SD *sd,BIG *id_i);
/**
 * 当智能设备想要加入域时，需要先向域管理员注册，该函数为Join过程中DM需要进行的操作
 * @param dm 本域的域管理员
 * @param id_i 待加入智能设备的身份
 * @param x 域管理员DM的私钥
 */
Msg1 Join_DM(DM *dm, BIG id_i, BIG x);
/**
 * 智能设备SD加入过程的第二阶段，SD存储证书等信息
 * @param sd 智能设备
 * @param id_i 智能设备的身份
 * @param msg1 DM加入过程发送的信息
 * @param dm 域管理员
 */
void Join_SD_step2(SD *sd, BIG id_i, Msg1 msg1,DM dm);
/**
 * 智能设备的签名算法
 * @param sd 智能设备
 * @param dm 智能设备所属的域管理员
 * @return  返回签名消息
 */
Msg2 Sign(SD sd, DM dm);
/**
 * 域管理员DM验证消息
 * @param msg2 智能设备生成的签名
 * @return 签名验证通过则返回true，否则返回false
 */
bool Verify(Msg2 msg2, DM dm);
/**
 * 返回一个身份所在的itemDM【事实上只需要返回一个idi即可，但是由于id_i是一个数组，不能返回，这里简单的直接返回itemDM】
 * @param msg2 某智能设备的签名
 * @param dm  域管理员
 * @return 恶意设备的真实身份 id_i
 */
itemDM Open(Msg2 msg2, DM dm);
/**
 * 撤销非法用户
 * @param item 非法设备的信息
 * @param dm 域管理员
 */
void Revoke(itemDM item, DM *dm);



/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 * @param q 有限域的阶
 */
void hashtoZp384(BIG num, octet *ct, BIG q);
/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param res  哈希之后的结果
 * @param beHashed 被哈希的值
 */
void hashToZp384(BIG res, BIG beHashed, BIG q);
/**
 * 初始化随机种子，这样randBigInt()每次生成的随机数都不相同
 * @param rng 待初始化的随机数种子
 */
void initRNG(core::csprng *rng);
/**
 * 双线性映射
 * @param alpha1 G1上的元素
 * @param alpha2 G2上的元素
 * @return 返回双线性映射的结果GT上的元素
 */
FP12 e(ECP alpha1, ECP2 alpha2);
/**
 * 控制台查看itemDM
 * @param item 待查看的对象
 */
void showItem(itemDM item);
/**
 * 控制台查看DM
 * @param dm 待查看的对象
 */
void showDM(DM dm);
/**
 * 控制台查看SD
 * @param sd 待查看的对象
 */
void showSD(SD sd);
/**
 * 控制台查看Msg2
 * @param msg2 待查看的对象
 */
void showMsg2(Msg2 msg2);





