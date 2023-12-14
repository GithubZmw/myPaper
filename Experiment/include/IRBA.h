//
// Created by zwm on 2023/12/12.
//
#include <map>
#include "common.h"

/**
	@brief Params Structure - 系统参数
*/
typedef struct {
    BIG q;/** 椭圆曲线的阶 */
    ECP P;/** 群G1的生成元 */
    ECP2 Q;/** 群G2的生成元 */
    ECP P_pub;/** 群公钥 */
}Params;

/**
	@brief Msg1_Extract Structure - 提取阶段UE发送的消息
*/
typedef struct {
    BIG ID_UE;/** 设备UE的身份 */
    ECP R;/** 设备UE的公钥 */
    BIG t;/** 设备UE身份的到期时间 */
}Msg1_Extract;


/**
	@brief Msg2_Extract Structure - 提取阶段SD发送的消息
*/
typedef struct {
    ECP2 S_ID;/** DM给SD颁发的群成员证书 */
}Msg2_Extract;

/**
	@brief UE Structure - 代表论文中的实体UE
*/
typedef struct {
    BIG ID_UE;/** 设备UE的身份 */
    BIG t;/** 设备UE身份的到期时间 */
    BIG r;/** 设备UE私钥的一部分 */
    ECP R;/** 设备UE的公钥 */
    ECP2 S_ID;/** AS给设备UE颁发的证书 */
}UE;

/**
	@brief AS Structure - 论文中的AS实体
*/
typedef struct {
    /** 设备UE在Extract过程中，AS需要为其生成随机数N,从而用于后续的认证。实际应用中，这里应该使用
     * 一个列表L，L里面存储 <设备,N> 对。本实验为了简单，只模拟一个设备的情况。值得注意的是、这对测量时间开销无影响
     */
    BIG N;
    BIG s;/** DM给SD颁发的群成员证书 */
}AS;


/**
	@brief Sign Structure - 认证签名
*/
typedef struct {
    ECP2 theta;
    FP12 sigma;
    FP12 w;
    ECP2 epsolon;
    BIG z;
}Sign;


/**
 * 获取当前时间，精确到微秒
 * @return 当前时间戳
 */
long long getCurrentTime();
/**
 * 生成一个Fq有限域上的随机数
 * @param big 生成的随机数的值将会赋值给这个变量
 */
void randBigInt_IRBA(BIG *big);
/**
 * 哈希函数，将大数ct哈希到有限域Z_q上,并将结果存储在num
 * @param num 哈希结果
 * @param ct 被哈希的值
 * @param q 大素数q,哈希结果被限定在Z_q上
 */
void hashtoZp384_IRBA(BIG num, octet *ct, BIG q);
/**
 * 论文中的哈希函数 H1 : {0,1} X {0,1} X G1 -> G2
 * @param result 哈希结果，是一个G2上的点
 * @param ID_UE 设备UE的身份
 * @param t 时间戳
 * @param P 设备UE的公钥
 */
void H1(ECP2 *result, BIG ID_UE, BIG t, ECP P);
/**
 * 哈希函数，将一个Zq上的元素哈希到G1上
 * @param result 哈希结果
 * @param m Zq上的元素
 */
void H2(ECP *result, BIG m);
/**
 * 哈希函数，将一个Zq上的元素哈希到G2上
 * @param result 哈希结果
 * @param m Zq上的元素
 */
void H2(ECP2 *result, BIG m);
/**
 * 哈希函数，论文中的H3 : GT^4 -> Zq
 * @param result 哈希结果。Zq上的元素
 * @param x GT上的元素
 * @param y GT上的元素
 * @param w GT上的元素
 * @param sigma GT上的元素
 */
void H3(BIG *result, FP12 x, FP12 y, FP12 w, FP12 sigma);

/**
 * 双线性映射
 * @param alpha1 G1上的元素
 * @param alpha2 G2上的元素
 * @return 返回双线性映射的结果GT上的元素
 */
FP12 e_IRBA(ECP alpha1, ECP2 alpha2);
/**
 * 控制台查看UE
 * @param ue  待查看对象
 */
void showUE(UE ue);
/**
 * 控制台查看Sign
 * @param ue  待查看对象
 */
void showSign(Sign sign);
/**
 * 初始化系统参数
 * @param params 初始化的系统参数存储在这个变量中
 * @param s 初始化生成的系统私钥存储在这里
 */
void Setup(Params *params, AS *As);
/**
 * Extract的第一步，由UE执行，生成Msg1之后发给AS
 * @param params 系统参数
 * @param ue 设备UE
 * @return 返回需要在Extract阶段发给AS的信息
 */
Msg1_Extract Extract_UE(Params params, UE *ue) ;
/**
 * Extract的第二步，AS收到UE的Msg1之后，生成Msg2发送给UE
 * @param params 系统参数
 * @param msg1 AS收到的UE发来的信息
 * @param As 认证服务器，需要为UE生成私钥，并存储一些消息
 * @return 返回需要发给UE的信息
 */
Msg2_Extract Extract_AS(Params params, Msg1_Extract msg1, AS As);
/**
 * Extract的第三步，UE收到Msg2之后，存储自己的签名私钥
 * @param ue 设备UE，存储Extract阶段，AS为器生成的私钥
 * @param msg2 接收到的AS为其生成的信息
 */
void Extract_UE2(UE *ue, Msg2_Extract msg2);
/**
 * 文中的签名部分。注意：论文中未给出x和y的计算方法，根据签名验证可推出x和y的计算方法，本函数恢复了论文方案省略的部分
 * @param params 系统参数
 * @param m 待签名消息
 * @param ue 跨域认证的发起设备
 * @param As 认证服务器
 * @return 返回一个认证消息
 */
Sign Signing(Params params, BIG m, UE ue, AS *As);
/**
 * 跨域认证的验证部分。注意：论文中未给出x和y的计算方法，根据签名验证可推出x和y的计算方法，本函数恢复了论文方案省略的部分
 * @param params 系统参数
 * @param m UE认证消息中签名消息，该消息应该随认证消息sign一起发送到AS这里
 * @param sign UE的的认证消息
 * @param ue 认证的发起设备。在这里用来提供(ID_UE,t,R)，事实上，这些信息在Extract中应该由AS存储起来。这里只是为了测计算开销，
 *           因此为了简单，直接将UE作为参数。
 * @param As 认证服务器
 * @return 认证通过返回true，否则返回false
 */
bool Verify(Params params, BIG m, Sign sign, UE ue, AS As);




