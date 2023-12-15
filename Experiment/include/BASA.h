//
// Created by Miracle on 2023/12/9.
//

#include "common.h"


/**
	@brief Params Structure - 系统参数
*/
typedef struct {
    BIG hid;/** SM9算法的标识值，在哈希函数中会用到 */
    BIG q;/** 椭圆曲线的阶 */
    BIG N;/** 椭圆曲线的阶 */
    ECP P1;/** 群G1的生成元 */
    ECP2 P2;/** 群G2的生成元 */
    ECP2 P_pub_s;/** KGC的公钥 */
}Params;

/**
	@brief Signature Structure - 存储SM9签名
*/
typedef struct {
    BIG h;/** 签名的第一部分 */
    ECP S;/** 签名的第二部分 */
}Signature;


/**
	@brief XID Structure - 指论文的实体
*/
typedef struct {
    BIG ID;/** 真实身份 */
    long deadline;/** 身份的有效期 */
}XID;


/**
 * 生成一个Fq有限域上的随机数
 * @param big 随机数对象，生成的随机数的值将会赋值给这个变量
 */
void randBigInt_BASA(BIG *big);
/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 * @param q 有限域的阶
 */
void hashtoZp384_BASA(BIG num, octet *ct, BIG q);
/**
 * 哈希函数,用来将三个BIG类型求哈希
 * @param ID 用户ID
 * @param hid 哈希参数
 * @param q 椭圆曲线的阶
 */
void H(BIG *result, BIG ID, BIG hid, BIG q);
/**
 * 双线性映射
 * @param alpha1 G1上的元素
 * @param alpha2 G2上的元素
 * @return 返回双线性映射的结果GT上的元素
 */
FP12 e3(ECP alpha1, ECP2 alpha2);
/**
 * 初始胡系统参数
 * @param params
 */
void Setup(Params *params, BIG *privKey);

/**
 * SM9算法的密钥生成算法
 * @param ID 申请密钥生成的用户ID
 * @param params 系统参数
 * @param ks 系统主私钥
 * @return 返回ID的签名私钥
 */
ECP KGC_genKey(BIG ID, Params params, BIG ks);

/**
 * 国密SM9算法
 * @param params BASA的公共参数
 * @param sk 签名私钥
 * @param M 签名消息
 */
Signature SM9_sign(Params params, ECP sk_e, BIG M);

/**
* SM9验签算法
* @param signature SM9签名
* @param params 公共参数
* @return 签名合法返回true,否则返回false
*/
bool SM9_verify(Signature signature, Params params, BIG IDe, BIG M_p);
/**
 * 判断伪身份是否过期
 * @param pid 待判断的伪身份
 * @return 未过期返回true,否则返回false
 */
bool isValid(XID xid);
/**
 * 生成伪身份
 * @param params 系统参数
 * @param ks KGC的私钥
 * @return 返回伪身份
 */
XID genPID(Params params, BIG ks);





