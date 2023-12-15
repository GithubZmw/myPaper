//
// Created by Miracle on 2023/11/30.
//

#include <map>
#include <array>
#include "common.h"
#include "iostream"
#include "ecdh_NIST256.h"

using namespace NIST256;
using namespace BLS12383;
using namespace B384_58;

// 定义一些ECC加解密需要用到的变量
char s1[EGS_NIST256], w1[2 * EFS_NIST256 + 1];
octet SK_base = {0, sizeof(s1), s1};
octet PK_base = {0, sizeof(w1), w1};

char s_diA[EGS_NIST256], w_diA[2 * EFS_NIST256 + 1];
char s_pasA[EGS_NIST256], w_pasA[2 * EFS_NIST256 + 1];
char s_pasB[EGS_NIST256], w_pasB[2 * EFS_NIST256 + 1];

char ds[EGS_NIST256], cs[EGS_NIST256];
char info_ds[EGS_NIST256], info_cs[EGS_NIST256];
char Msg2_CertA_info_ds[EGS_NIST256], Msg2_CertA_info_cs[EGS_NIST256];
char Msg2_CertB_info_ds[EGS_NIST256], Msg2_CertB_info_cs[EGS_NIST256];
char msg1_cert_ds[EGS_NIST256], msg1_cert_cs[EGS_NIST256];
char msg1_sign_ds[EGS_NIST256], msg1_sign_cs[EGS_NIST256];

/**
	@brief di_A Structure - 论文中的实体di_A
*/
typedef struct {
    octet sk = {0, sizeof(s_diA), s_diA};/** 私钥 */
    octet pk = {0, sizeof(w_diA), w_diA};/** 公钥 */
}di_A;

/**
	@brief PAS_A Structure - 论文中的实体PAS_A
*/
typedef struct {
    octet sk  = {0, sizeof(s_pasA), s_pasA};/** 私钥 */
    octet pk  = {0, sizeof(w_pasA), w_pasA};/** 公钥 */
}PAS_A;
/**
	@brief PAS_B Structure - 论文中的实体PAS_B
*/
typedef struct {
    octet sk = {0, sizeof(s_pasB), s_pasB};/** 私钥 */
    octet pk = {0, sizeof(w_pasB), w_pasB};/** 公钥 */
}PAS_B;
/**
	@brief Msg Structure - 认证过程中的通讯消息
*/
typedef struct {
    BIG ID_A;/** di_A的身份 */
    bool flag;
    BIG vskB;/** 跨域认证私钥 */
    BLS12383::ECP2 vpkB;/** 跨域认证公钥 */
    BLS12383::ECP Lics;/** PAS_B为di_A颁发的证书 */
    BLS12383::ECP blk;/** 黑名单 */
}Msg;
/**
	@brief Params Structure - 系统参数,符号含义与论文中的一致
*/
typedef struct {
    BIG p_widetilde;/** 椭圆曲线的阶 */
    BIG p,q,p_prime,q_prime;/** 论文中的参数 */
    BLS12383::ECP g1,h1,g;
    BLS12383::ECP2 g2;
    BIG tau;
    BIG n;
}Params;
/**
	@brief Cert Structure - 证书，由于文中需要进行签名和验签，本实验采用ECC算法，签名格式如下
*/
typedef struct C{
    octet CS = {0, sizeof(cs), cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(ds), ds};/** 签名的第二部分 */
    // 重载 < 操作符 ， 为了满足黑名单的要求，这里重载运算符，用于存储在map中作为key
    bool operator<(const C& other) const {
        // 这里假设 octet 中的 val 是 char 数组
        return memcmp(this->CS.val, other.CS.val, min(this->CS.len, other.CS.len)) < 0;
    }
}Cert;
typedef struct {
    octet CS = {0, sizeof(msg1_cert_cs), msg1_cert_cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(msg1_cert_ds), msg1_cert_ds};/** 签名的第二部分 */
}Msg1_certA;
typedef struct {
    octet CS = {0, sizeof(msg1_sign_cs), msg1_sign_cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(msg1_sign_ds), msg1_sign_ds};/** 签名的第二部分 */
}Msg1_signA;
/**
	@brief Msg1 Structure - 认证过程中的通讯消息
*/
typedef struct {
    Msg1_certA certA;/** 用自己私钥生成的签名 */
    Msg1_signA signA;/** 用接受对方公钥加密的消息 */
}Msg1;
/**
	@brief Info_Cert Structure - 证书，由于文中需要进行签名和验签，本实验采用ECC算法，签名格式如下
*/
typedef struct {
    octet CS = {0, sizeof(info_cs), info_cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(info_ds), info_ds};/** 签名的第二部分 */
}Info_Cert;
/**
	@brief Info Structure - 论文中提到的di_A的身份信息
*/
typedef struct {
    octet information;/** 身份信息 */
    Info_Cert cert;/** 证书 */
}Info;
/**
	@brief Info_Cert Structure - 证书，由于文中需要进行签名和验签，本实验采用ECC算法，签名格式如下
*/
typedef struct {
    octet CS = {0, sizeof(Msg2_CertA_info_cs), Msg2_CertA_info_cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(Msg2_CertA_info_ds), Msg2_CertA_info_ds};/** 签名的第二部分 */
}Msg2_CertA;
/**
	@brief Info_Cert Structure - 证书，由于文中需要进行签名和验签，本实验采用ECC算法，签名格式如下
*/
typedef struct {
    octet CS = {0, sizeof(Msg2_CertB_info_cs), Msg2_CertB_info_cs};/** 签名的第一部分 */
    octet DS = {0, sizeof(Msg2_CertB_info_ds), Msg2_CertB_info_ds};/** 签名的第二部分 */
}Msg2_CertB;
/**
	@brief Msg2 Structure - 论文中通讯时发送的消息之一
*/
typedef struct {
    int crossLicensing;/** 跨域证书 */
    BIG ID_A;/** di_A的身份 */
    Msg2_CertA certA;/** di_A生成的证书 */
    Info infoA;/** di_A的身份信息 */
    octet pkA;/** PAS_A的公钥信息 */
    Msg2_CertB signB;/** 使用PAS_B的公钥加密得到的信息 */
}Msg2;
/**
	@brief Args Structure - 论文中的认证过程比较复杂，本实验将认证的复杂过程分开验证，在不影响效率的情况下复现实验
                          - 下面这些参数是伪身份生成时需要计算的，这里提前定义好，将来初始化之后使用，
*/
typedef struct {
    BLS12383::ECP A, A_d;
    BLS12383::ECP B1, B2, B3, B4, C, a, Lics;
    BLS12383::ECP u, v, w;
    BLS12383::ECP g11, g12, g13;
    BLS12383::ECP pk1, pk2, pk3;
    BLS12383::ECP2 vpkB;
    BIG d, sk1, sk2, sk3, vskB,h_uw;//pk1_revoke,w_revoke;
    BIG r, ID_A;//
    BIG gamma, epsilon, theta1, theta2, theta3, theta4, beta1, beta2, beta3, beta4;//
    BIG r_d, epsilon_d, sigma_d, gamma_d, d_d, theta1_d, theta2_d, theta3_d, theta4_d, beta1_d, beta2_d, beta3_d, beta4_d;//
    BIG ch;//
    BIG r_dd, epsilon_dd, sigma_dd, gamma_dd, d_dd, theta1_dd, theta2_dd, theta3_dd, theta4_dd, beta1_dd, beta2_dd, beta3_dd, beta4_dd;//
    BIG r_d_2, sigma_d_2, r_dd_2, ch_2, sigma_dd_2;
} Args;

/**
	@brief UVW Structure - 零知识证明的一部分
*/
typedef struct {
    BLS12383::ECP u_d;
    BLS12383::ECP v_d;
    BLS12383::ECP w_d;
}UVW;
/**
	@brief BXX Structure - 零知识证明的一部分
*/
typedef struct {
    BLS12383::ECP B11_d;
    BLS12383::ECP B12_d;
    BLS12383::ECP B31_d;
    BLS12383::ECP B32_d;
    BLS12383::ECP B4_d;
}BXX;



/**
	@brief mp Structure - 大整数模幂运算需要用到
*/
typedef struct {
    BIG big;/** 模幂运算的结果 */
} mp;


/**
 * 查看一个octet类型数据的详细信息，用于调试
 * @param oc 要查看的octet
 */
void showOCT(octet oc);
/**
 * 查看结构体Args中的相信信息，用于代码的调试
 * 【注意：该函数并未查看Args中的所有变量信息，在调试中可根据需要自行修改，打印想看的信息】
 * @param args Args的一个实例
 */
void showArgs(Args args);
/**
 * 查看CCAP方案的系统参数Params，用于调试
 * @param params 要查看的系统参数实例
 */
void showParams(Params params);
/**
 * 将一个int数字转化为十六进制字符串
 * @param n int类型的数字
 * @return 转化后的string
 */
string toHexString(int n);
/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 * @param q 有限域的阶
 */
void hashtoZp384_CCAP(BIG num, octet *ct, BIG q);
/**
 * 在BLS12381曲线上进行双线性映射操作，将ECP和ECP2上的元素映射到FP12上
 * @param alpha1 ECP上的群元素
 * @param alpha2 ECP2上的群元素
 * @return 返回双线性映射的结果，是一个FP12上的元素
 */
 FP12 e2(BLS12383::ECP alpha1, BLS12383::ECP2 alpha2);
/**
 * 大整数模拟运算，求 base^exponent mod modulus 的值
 * 使用分治法求解，时间复杂度为O( log2(n) )
 * 由于B384_58::BIG是数组类型的数据，无法作为函数的返回值，因此这里创建了一个结构体作为返回值
 * @param base 底数
 * @param exponent 指数
 * @param modulus 模数
 * @return 返回模幂运算的结果
 */
mp powmod(B384_58::BIG base, B384_58::BIG exponent, B384_58::BIG modulus);
/**
 * 生成ECC的公私钥对.下面给出公私钥对的创建格式;
 * @param sk ECC的公钥
 * @param pk ECC的私钥
 */
void getKeyPair(octet *sk, octet *pk);
/**
 * ECC的签名算法。
 * @param sk ECC签名使用的私钥
 * @param message  待签名的消息
 * @param CS 签名的第一部分
 * @param DS 签名的第二部分
 */
void sign_DSA(octet sk, octet message, octet *CS, octet *DS);
/**
 * ECC验签算法
 * @param pk 验签使用的公钥
 * @param message  签名的消息
 * @param CS 签名的第一部分
 * @param DS 签名的第二部分
 * @return 验签通过返回true，否则返回false
 */
bool verify_DSA(octet pk, octet message, octet CS, octet DS);
/**
 * 生成一个Fp有限域上的随机数
 * @param big 随机数对象，生成的随机数的值将会赋值给这个变量
 */
void randBig(BIG *big);
/**
 * 初始化CCAP方案的系统参数
 * @param params  存储系统参数的变量
 */
void Setup(Params *params);
/**
 * 初始化各个实体的公私钥对
 * @param diA 域A中的设备【Device】 diA
 * @param pasA 域A中的代理认证服务器【Proxy Authentication Server】PAS_A
 * @param pasB 域B中的代理认证服务器【Proxy Authentication Server】PAS_B
 */
void init_entity(di_A *diA, PAS_A *pasA, PAS_B *pasB);
/**
 * 初始化CCAP方案中的黑名单，这里往里面存储一个元素模拟以下黑名单
 */
void initBlackList();
/**
 * 测试ECC加密和解密总共的耗时
 * CCAP方案中发送消息时采用公钥加密算法加密消息，但是未说明使用什么公钥加密算法
 * 考虑到现在市面上使用ECC算法较多【HTTPS的SSL层使用的就是这个算法】，因此使用ECC加密模拟论文中的加密
 */
void ECC_encAndDec();
/**
 * 检查一个id是否存在于黑名单中，由于这个时间可能很短，这里不实现这个函数，也就是不计算查黑名单的时间开销
 * @param id 要查找的身份 id
 */
bool inBlack(BIG id);
/**
 * 初始化系统认证过程中需要用到的参数
 * @param args 初始化的参数存储在这个结构体中
 * @param msg 初始化参数的时候需要用到认证过程中产生的一些参数，例如ID_A这些参数存储在这个变量之中
 */
void initArgs(Args *args, Msg msg);
/**
 * 初始化多项式的参数
 * @param args 里面包含三个秘密 sk1,sk2,sk3
 */
void init_fi(Args args);
/**
 * Shamir秘密共享多项式函数
 * @param x 函数的自变量
 * @param t 多项式的阶
 */
void f(int i, BIG x, BIG *result);
/**
 * 计算m[i][j] , j = {1,2,...,n}
 */
void init_m();
/**
 * 通过此函数追踪设备的真实身份。
 * 文中需要使用乘法循环群才能完成身份追踪的最后两步，即
 *      ID' =  (w / s^sk1) mod n^2
 *      ID = ID' - 1 mod n
 * 但是并未找到支持配对的乘法循环群曲线，本实验使用的时BLS12383曲线，无法通过上述步骤最总真是身份
 * 但是这对于测量计算开销并无来影响
 * @param args 需要用到私钥 pk1,pk2,pk3，从而追踪到sk1,sk2,sk3
 */
void ID_tracking(Args args);
/**
 * 生成初始化秘密共享的函数，初始化mij
 * @param args 初始化需要用到的参数
 */
void PAS_A_gen_mij(Args args);
/**
 * 秘密共享时，验证Mij
 * 这里假设将秘密共享给2个人，即 m[i][j]中,j={1,2}
 * @param args
 */
void PAS_B_verify_Mij(Args args);
/**
 * 跨域认证请求
 */
void diA_crossDomain_requestByPID();
/**
 * PAS_A计算u,w,v
 * @param args
 * @return 返回 u w v
 */
UVW PAS_A_gen_UVW(Args args);
/**
 * PAS_B验证UVW的正确性
 * @param uvw 收到的uvw
 * @param args 系统参数
 */
void PAS_B_verify_UVW(UVW uvw, Args args);
/**
 * PAS_A生成认证的 A C
 * @param args 系统参数
 * @return A，C
 */
FP12 PAS_A_gen_AC(Args args);
/**
 * PAS_B验证A,C的正确性
 * @param C_d 收到的C
 * @param args 系统参数
 */
void PAS_B_verify_AC(FP12 C_d, Args args);
/**
 * PAS_A生成认证的 B11,B12,B31,B32,B4
 * @param args 系统参数
 * @return B11,B12,B31,B32,B4
 */
BXX PAS_A_gen_BXX(Args args);
/**
 * PAS_B验证B11,B12,B31,B32,B4的正确性
 * @param bxx B11,B12,B31,B32,B4
 * @param args 系统参数
 */
void PAS_B_verify_BXX(BXX bxx, Args args);
/**
 * PAS_A生成认证的 D
 * @param args 系统参数
 * @return D
 */
FP12 PAS_A_gen_D(Args args);
/**
 * PAS_B验证D的正确性
 * @param D_d 收到的PAS_A发来的D
 * @param args 系统参数
 * @param msg 系统参数
 */
void PAS_B_verify_D(FP12 D_d, Args args, Msg msg);
/**
 * 生成为身份过程的零知识证明需要验证很多东西，这里是使用多个函数进行验证
 * 本函数验证 u_d , v_d , w_d
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_UVW(Args args);
/**
 * 验证零知识证明之中的 A ，C 两个参数
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_AC(Args args);
/**
 * 验证零知识证明中的 B11_d,B12_d,B31_d,B32_d,B4_d
 * @param args  零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_BXX(Args args);
/**
 * 验证D是否正确
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 * @param msg 里面存储的有前面认证过程中PAS_A计算的黑名单blk
 */
void verify_D(Args args, Msg msg);
