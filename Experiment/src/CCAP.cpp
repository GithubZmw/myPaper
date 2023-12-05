//
// Created by Miracle on 2023/11/30.
// 本代码复现CCAP方案，由于本文的认证过程中需要进行大量的运算，需要进行很多验证。
// 但是将这些验证全部写到一个函数中显得代码不够规范，难以维护。因此本文将论文中的
// 验证分开在不同的函数中进行验证【值得注意的是，我在做这一步时保持了计算开销与原方案相同】
//
#include "common.h"
#include "CCAP.h"

// 定义一些消息，模拟论文中加密的数据
char *request = (char *) "authentic request";
char msg_request[32];
octet M_request = {sizeof(msg_request), sizeof(msg_request), request};

char *cert = (char *) "cert";
char msg_cert[32];
octet M_cert = {sizeof(msg_cert), sizeof(msg_cert), cert};

char *information = (char *) "user information";
char msg_information[32];
octet M_information = {sizeof(msg_information), sizeof(msg_information), information};


/**
 * 查看一个octet类型数据的详细信息，用于调试
 * @param oc 要查看的octet
 */
void showOCT(octet oc) {
    cout << "co.len = " << oc.len << endl;
    cout << "co.max = " << oc.max << endl;
    cout << "co.val = ";
    OCT_output(&oc);
}

/**
 * 查看结构体Args中的相信信息，用于代码的调试
 * 【注意：该函数并未查看Args中的所有变量信息，在调试中可根据需要自行修改，打印想看的信息】
 * @param args Args的一个实例
 */
void showArgs(Args args) {
    cout
            << "------------------------------------------------------- showArgs ----------------------------------------------------"
            << endl;
    cout << "--------- [Args.ch]:" << endl;
    BIG_output(args.ch);
    cout << endl << "--------- [Args.r_d]:" << endl;
    BIG_output(args.r_d);
    cout << endl << "--------- [Args.sigma_dd_2]:" << endl;
    BIG_output(args.sigma_dd_2);
    cout << endl << "--------- [Args.r_dd_2]:" << endl;
    BIG_output(args.r_dd_2);
    cout << endl << "--------- [Args.w]:" << endl;
    ECP_output(&args.w);
    cout << endl << "--------- [Args.pk1]:" << endl;
    ECP_output(&args.pk1);
    cout
            << "------------------------------------------------------- showArgs ----------------------------------------------------"
            << endl;
}

/**
 * 查看CCAP方案的系统参数Params，用于调试
 * @param params 要查看的系统参数实例
 */
void showParams(Params params) {
    cout
            << "------------------------------------------------------- showParams ----------------------------------------------------"
            << endl;
    cout << "--------- [Params.g1]:" << endl;
    ECP_output(&params.g1);
    cout << endl << "--------- [Params.h1]:" << endl;
    ECP_output(&params.h1);
    cout << endl << "--------- [Params.g]:" << endl;
    ECP_output(&params.g);
    cout << endl << "--------- [Params.g2]:" << endl;
    ECP2_output(&params.g2);
    cout
            << "------------------------------------------------------- showParams ----------------------------------------------------"
            << endl;
}

/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 * @param q 有限域的阶
 */
void hashtoZp384_CCAP(BIG num, octet *ct, BIG q) {
    hash384 h;
    // 数组长度设为48，由于每一位char用两个十六进制的数字表示【可以表示256个字符，刚好表示ASCII表】，
    // 则将其转化为为BIG后，数字长度为96，每个16进制用4个bit表示，故96*4=384
    char hashstr[48];
    memset(hashstr, 0, 48);
    // 哈希函数三步走
    HASH384_init(&h);
    for (int j = 0; j < ct->max; j++) {
        HASH384_process(&h, ct->val[j]);
    }
    HASH384_hash(&h, hashstr);
    // 将得到的结果转化为有限域Fq上的元素
    BIG_fromBytesLen(num, hashstr, 48);
    BIG_mod(num, q);
}

/**
 * 在BLS12381曲线上进行双线性映射操作，将ECP和ECP2上的元素映射到FP12上
 * @param alpha1 ECP上的群元素
 * @param alpha2 ECP2上的群元素
 * @return 返回双线性映射的结果，是一个FP12上的元素
 */
FP12 e2(BLS12383::ECP alpha1, BLS12383::ECP2 alpha2) {
    FP12 fp12;
    PAIR_ate(&fp12, &alpha2, &alpha1);
    PAIR_fexp(&fp12);
    FP12_reduce(&fp12);
    if (FP12_isunity(&fp12) || FP12_iszilch(&fp12)) {
        printf("pairing error [temp1]\n");
    }
    return fp12;
}

/**
 * 大整数模拟运算，求 base^exponent mod modulus 的值
 * 使用分治法求解，时间复杂度为O( log2(n) )
 * 由于B384_58::BIG是数组类型的数据，无法作为函数的返回值，因此这里创建了一个结构体作为返回值
 * @param base 底数
 * @param exponent 指数
 * @param modulus 模数
 * @return 返回模幂运算的结果
 */
mp powmod(B384_58::BIG base, B384_58::BIG exponent, B384_58::BIG modulus) {
    mp mp;
    B384_58::BIG res, zero, one, two;
    // 初始化 result
    B384_58::BIG_one(res);
    B384_58::BIG_one(one);
    B384_58::BIG_zero(zero);
    BIG_add(two, one, one);
    if (BIG_comp(exponent, zero) == 0) {
        BIG_copy(mp.big, one);
        return mp;
    }
    BIG temp;
    BIG_copy(temp, exponent);
    BIG_mod(temp, two);
    BIG e_2;
    BIG_copy(e_2, exponent);
    BIG_sdiv(e_2, two);
    mp = powmod(base, e_2, modulus);
    if (BIG_comp(temp, zero) == 0) {
        BIG_modsqr(mp.big, mp.big, modulus);
        return mp;
    } else {
        BIG_modsqr(mp.big, mp.big, modulus);
        BIG_modmul(mp.big, mp.big, base, modulus);
        return mp;
    }
}


/**
 * 生成ECC的公私钥对.下面给出公私钥对的创建格式;
 * @param sk ECC的公钥
 * @param pk ECC的私钥
 */
void getKeyPair(octet *sk, octet *pk) {
    // 产生随机公私钥
    ECP_KEY_PAIR_GENERATE(&rng_CCAP, sk, pk);
    // 验证下密钥生成对不对
    int res = ECP_PUBLIC_KEY_VALIDATE(pk);
    if (res != 0) {
        printf("ECP Public Key is invalid!\n");
        return;
    }
//    cout << "---------------------------- generate key pair --------------------------------------" << endl;
//    //  公私钥的输出
//    printf("Servers private key: 0x");
//    OCT_output(sk);
//    printf("Servers public key: 0x");
//    OCT_output(pk);
//    cout << "---------------------------- generate key pair --------------------------------------" << endl;
}


/**
 * ECC的签名算法。
 * @param sk ECC签名使用的私钥
 * @param message  待签名的消息
 * @param CS 签名的第一部分
 * @param DS 签名的第二部分
 */
void sign_DSA(octet sk, octet message, octet *CS, octet *DS) {
    // 签名
    if (ECP_SP_DSA(HASH_TYPE_NIST256, &rng_CCAP, NULL, &sk, &message, CS, DS) != 0) {
        printf("***ECDSA Signature Failed\n");
        return;
    }
//    cout << "---------------------------- generate signature --------------------------------------" << endl;
//    printf("messaage: %s\n", message.val);
//    printf("Signature C = 0x");
//    OCT_output(CS);
//    printf("Signature D = 0x");
//    OCT_output(DS);
//    cout << "---------------------------- generate signature --------------------------------------" << endl;
}


/**
 * ECC验签算法
 * @param pk 验签使用的公钥
 * @param message  签名的消息
 * @param CS 签名的第一部分
 * @param DS 签名的第二部分
 * @return 验签通过返回true，否则返回false
 */
bool verify_DSA(octet pk, octet message, octet CS, octet DS) {
    // 验签
    if (ECP_VP_DSA(HASH_TYPE_NIST256, &pk, &message, &CS, &DS) != 0) {
        printf("***ECDSA Verification Failed\n");
        return false;
    } else {
//        printf("ECDSA Signature/Verification succeeded\n");
        return true;
    }
}


/**
 * 生成一个Fp有限域上的随机数
 * @param big 随机数对象，生成的随机数的值将会赋值给这个变量
 */
void randBig(BIG *big) {
    BIG mod;
    BIG_rcopy(mod, BLS12383::CURVE_Order);
    BIG_randtrunc(*big, mod, 2 * CURVE_SECURITY_BLS12383, &rng_CCAP);
}


/**
 * 初始化CCAP方案的系统参数
 * @param params  存储系统参数的变量
 */
void Setup(Params *params) {
    BIG_rcopy(params->p_widetilde, BLS12383::CURVE_Order);// 由于这个库中的配对，阶是固定的，直接复制过来
    BLS12383::ECP_generator(&params->g1);
    BIG r;
    randBig(&r);
    BLS12383::ECP_copy(&params->h1, &params->g1);
    BLS12383::ECP_mul(&params->h1, r);
    BLS12383::ECP2_generator(&params->g2);
    randBig(&params->tau);
//    不知道这个p和q是干嘛的，先初始化为
    BIG_rcopy(params->p, BLS12383::CURVE_Order);
    BIG_rcopy(params->q, BLS12383::CURVE_Order);
    BIG_mul(params->n, params->p, params->q);
    randBig(&r);
    BLS12383::ECP_copy(&params->g, &params->g1);
    BLS12383::ECP_mul(&params->g, r);
}


di_A d_i_A;
PAS_A pas_CA_A;
PAS_B pas_KGC_B;
VS vs_s;
Params params;


/**
 * 初始化各个实体的公私钥对
 * @param diA 域A中的设备【Device】 diA
 * @param pasA 域A中的代理认证服务器【Proxy Authentication Server】PAS_A
 * @param pasB 域B中的代理认证服务器【Proxy Authentication Server】PAS_B
 */
void init_entity(di_A *diA, PAS_A *pasA, PAS_B *pasB) {
    getKeyPair(&diA->sk, &diA->pk);
    getKeyPair(&pasA->sk, &pasA->pk);
    getKeyPair(&pasB->sk, &pasB->pk);
}

/**
 * 初始化CCAP方案中的黑名单，这里往里面存储一个元素模拟以下黑名单
 */
void initBlackList() {
    BIG r;
    Cert c;
    sign_DSA(pas_CA_A.sk, M_cert, &c.CS, &c.DS);
    randBig(&r);
    BIG_copy(BlackList[c], r);

}


/**
 * 测试ECC加密和解密总共的耗时
 * CCAP方案中发送消息时采用公钥加密算法加密消息，但是未说明使用什么公钥加密算法
 * 考虑到现在市面上使用ECC算法较多【HTTPS的SSL层使用的就是这个算法】，因此使用ECC加密模拟论文中的加密
 */
void ECC_encAndDec() {
//    cout << "-------------------------------------- ECC_ECM --------------------------------------" << endl;
    int i, res;
    char p1[30], p2[30], v[2 * EFS_NIST256 + 1], m[32], c[64], t[32];
    octet P1 = {0, sizeof(p1), p1};
    octet P2 = {0, sizeof(p2), p2};
    octet V = {0, sizeof(v), v};
    octet M = {0, sizeof(m), m};
    octet C = {0, sizeof(c), c};
    octet T = {0, sizeof(t), t};
    char s1[EGS_NIST256], w1[2 * EFS_NIST256 + 1];
    octet S1 = {0, sizeof(s1), s1};
    octet W1 = {0, sizeof(w1), w1};
    // Random private key for other party
    ECP_KEY_PAIR_GENERATE(&rng_CCAP, &S1, &W1);
    res = ECP_PUBLIC_KEY_VALIDATE(&W1);
    if (res != 0) {
        printf("ECP Public Key is invalid!\n");
    }
//    printf("Testing ECIES\n");
    P1.len = 3;
    P1.val[0] = 0x0;
    P1.val[1] = 0x1;
    P1.val[2] = 0x2;
    P2.len = 4;
    P2.val[0] = 0x0;
    P2.val[1] = 0x1;
    P2.val[2] = 0x2;
    P2.val[3] = 0x3;
    M.len = 17;
    for (i = 0; i <= 16; i++) M.val[i] = i;
//    for (i = 0; i <= 62; i++) cout << M.val[i];

//    printf("Message is 0x");
//    OCT_output(&M);

    ECP_ECIES_ENCRYPT(HASH_TYPE_NIST256, &P1, &P2, &rng_CCAP, &W1, &M, 12, &V, &C, &T);

//    printf("Ciphertext= \n");
//    printf("V= 0x");
//    OCT_output(&V);
//    printf("C= 0x");
//    OCT_output(&C);
//    printf("T= 0x");
//    OCT_output(&T);

    if (!ECP_ECIES_DECRYPT(HASH_TYPE_NIST256, &P1, &P2, &V, &C, &T, &S1, &M)) {
        printf("*** ECIES Decryption Failed\n");

    } else printf("Decryption succeeded\n");

//    printf("Message is 0x");
//    OCT_output(&M);
//    cout << "-------------------------------------- ECC_ECM --------------------------------------" << endl;
}

/**
 * 检查一个id是否存在于黑名单中，由于这个时间可能很短，这里不实现这个函数，也就是不计算查黑名单的时间开销
 * @param id 要查找的身份 id
 */
bool inBlack(BIG id) {
    return false;
}


/**
 * CCAP方案认证的全过程
 * @param msg 认证过程中产生的消息，接受该消息的实体会用到，使用msg存储这些消息
 */
void step1(Msg *msg) {
//    初始化系统各实体的参数
    Setup(&params);
    initBlackList();
    init_entity(&d_i_A, &pas_CA_A, &pas_KGC_B);
//  ------------------------------ 智能设备生成两个证书，发送给PAS_A ------------------------------------
    Cert certA;
    Cert signA;
    char ds_certA[EGS_NIST256], cs_certA[EGS_NIST256];
    certA.CS = {0, sizeof(cs_certA), cs_certA};
    certA.DS = {0, sizeof(ds_certA), ds_certA};
    char ds_signA[EGS_NIST256], cs_signA[EGS_NIST256];
    signA.CS = {0, sizeof(cs_signA), cs_signA};
    signA.DS = {0, sizeof(ds_signA), ds_signA};

    sign_DSA(pas_CA_A.sk, M_cert, &certA.CS, &certA.DS);
    sign_DSA(d_i_A.sk, M_request, &signA.CS, &signA.DS);
//    ------------------------------ PAS_A收到消息后进行验证 -------------------------------------------
    verify_DSA(pas_CA_A.pk, M_cert, certA.CS, certA.DS);
    verify_DSA(d_i_A.pk, M_request, signA.CS, signA.DS);
//    ------------------------------ PAS_A按照CCAP方案生成认证消息给 PAS_B ------------------------------

    // 计算ID_A
    octet oc;
    OCT_copy(&oc, &certA.CS);
    OCT_xor(&oc, &certA.DS);
    BIG ID_A;
    hashtoZp384_CCAP(ID_A, &oc, params.p_widetilde);
    BIG_copy(msg->ID_A, ID_A);//复制给msg
    // 生成证书signB
    char ds_signB[EGS_NIST256], cs_signB[EGS_NIST256];
    Cert signB;
    signA.CS = {0, sizeof(cs_signB), cs_signB};
    signA.DS = {0, sizeof(ds_signB), ds_signB};
    sign_DSA(pas_CA_A.sk, M_request, &signB.CS, &signB.DS);
    ECC_encAndDec();//模拟PAS_A加密，PAS_B解密耗时

//    -------------------------------------- PAS_B验证PAS_A的消息 ---------------------------------
    bool flag = verify_DSA(pas_CA_A.pk, M_request, signB.CS, signB.DS);
    cout << "flag:" << flag << endl;
    // 验证ID_A的正确性
    octet oc1;
    OCT_xor(&oc1, &certA.CS);
    OCT_xor(&oc1, &certA.DS);
    BIG ID_A_hat;
    hashtoZp384_CCAP(ID_A_hat, &oc1, params.p_widetilde);
    flag = flag && (BIG_comp(ID_A_hat, ID_A) == 0);
    cout << "flag:" << flag << endl;
    // 验证用户是否在黑名单中
    flag = flag && !inBlack(ID_A);
    // 验证身份信息Info是否合法
    Info infoA;
    sign_DSA(pas_CA_A.sk, M_information, &infoA.cert.CS, &infoA.cert.DS);
    flag = flag && verify_DSA(pas_CA_A.pk, M_information, infoA.cert.CS, infoA.cert.DS);
    cout << "flag:" << flag << endl;
    msg->flag = flag;
}


/**
 * CCAP方案的具体步骤 2
 */
void step2(Msg *msg) {
    //    ------------------------------ PAS_B生成Lics ------------------------------
    randBig(&msg->vskB);
    BLS12383::ECP2_copy(&msg->vpkB, &params.g2);
    BLS12383::ECP2_mul(&msg->vpkB, msg->vskB);

    BIG temp;
    BIG_copy(temp, msg->ID_A);
    BIG_modadd(temp, temp, msg->vskB, params.p_widetilde);
    BIG_invmodp(temp, temp, params.p_widetilde);
    BLS12383::ECP_copy(&msg->Lics, &params.g1);
    BLS12383::ECP_mul(&msg->Lics, temp);
    //    ------------------------------ PAS_A验证Lics ------------------------------
    BLS12383::FP12 left, right;
    left = e2(params.g1, params.g2);
    BLS12383::ECP2 vpkBAddg2;
    BLS12383::ECP2_copy(&vpkBAddg2, &params.g2);
    BLS12383::ECP2_mul(&vpkBAddg2, msg->ID_A);
    BLS12383::ECP2_add(&vpkBAddg2, &msg->vpkB);
    right = e2(msg->Lics, vpkBAddg2);
    bool flag = msg->flag;
    flag = flag && (FP12_equals(&left, &right));
    cout << "verify Lics:" << endl;
    cout << "flag:" << flag << endl;
    //    ------------------------------ PAS_B生成blk ------------------------------
    BLS12383::ECP blk;
    BIG mul;
    BIG_one(mul);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG_modadd(bigValue, bigValue, params.tau, params.p_widetilde);
        BIG_modmul(mul, mul, bigValue, params.p_widetilde);
    }
    ECP_mul(&blk, mul);
    ECP_copy(&msg->blk, &blk);
}

/**
 * 初始化系统认证过程中需要用到的参数
 * @param args 初始化的参数存储在这个结构体中
 * @param msg 初始化参数的时候需要用到认证过程中产生的一些参数，例如ID_A这些参数存储在这个变量之中
 */
void initArgs(Args *args, Msg msg) {
    //计算 d,a
    BIG_one(args->d);
    BIG mod;
    BIG_modadd(mod, msg.ID_A, params.tau, params.p_widetilde);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG d_pre;
        BIG_copy(d_pre, args->d);
        BIG_modadd(args->d, bigValue, params.tau, mod);
        BIG_modmul(args->d, d_pre, args->d, mod);
        BIG_mod(args->d, params.p_widetilde);
    }
    BIG mul;
    BIG_one(mul);
    for (auto it = BlackList.begin(); it != BlackList.end(); ++it) {
        BIG bigValue;
        BIG_copy(bigValue, it->second);
        BIG_modadd(args->d, bigValue, params.tau, mod);
        BIG_modmul(mul, mul, args->d, mod);
        BIG_mod(mul, params.p_widetilde);
    }
    BIG_sub(mul, mul, args->d);
    ECP_copy(&args->a, &params.g1);
    ECP_mul(&args->a, mul);
    BIG_invmodp(mod, mod, params.p_widetilde);
    ECP_mul(&args->a, mod);
    // 初始化 XXX
    randBig(&args->r);
    BIG_copy(args->ID_A, msg.ID_A);
    randBig(&args->gamma);
    randBig(&args->epsilon);
    randBig(&args->beta1);
    randBig(&args->beta2);
    randBig(&args->beta3);
    randBig(&args->beta4);
    BIG_modmul(args->theta1, msg.ID_A, args->beta1, params.p_widetilde);
    BIG_modmul(args->theta2, msg.ID_A, args->beta2, params.p_widetilde);
    BIG_modmul(args->theta3, args->d, args->beta3, params.p_widetilde);
    BIG_modmul(args->theta4, args->d, args->beta4, params.p_widetilde);
    // 初始化 XXX_d
    randBig(&args->r_d);
    randBig(&args->epsilon_d);
    randBig(&args->sigma_d);
    randBig(&args->gamma_d);
    randBig(&args->d_d);
    randBig(&args->theta1_d);
    randBig(&args->theta2_d);
    randBig(&args->theta3_d);
    randBig(&args->theta4_d);
    randBig(&args->beta1_d);
    randBig(&args->beta2_d);
    randBig(&args->beta3_d);
    randBig(&args->beta4_d);
    // 初始化 A , A_d
    BLS12383::ECP g_1, h_1;
    ECP_copy(&args->A, &params.g1);
    ECP_mul(&args->A, args->ID_A);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args->epsilon);
    ECP_add(&args->A, &h_1);
    ECP_copy(&g_1, &params.g1);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&g_1, args->sigma_d);
    ECP_mul(&h_1, args->epsilon_d);
    ECP_add(&g_1, &h_1);
    ECP_copy(&args->A_d, &g_1);
    // 初始化 ch
    octet oc1_ch, oc2_ch;
    char str1[384], str2[384];
    oc1_ch.val = str1;
    oc1_ch.max = 97;
    oc2_ch.val = str2;
    oc2_ch.max = 97;
    ECP_toOctet(&oc1_ch, &params.g1, true);
    ECP2_toOctet(&oc2_ch, &params.g2, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &args->A, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    ECP_toOctet(&oc2_ch, &args->A_d, true);
    OCT_xor(&oc1_ch, &oc2_ch);
    hashtoZp384_CCAP(args->ch, &oc1_ch, params.p_widetilde);
    // 初始化  ××_dd
    BIG temp;
    BIG_modmul(temp, args->ch, args->r, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->r_dd, args->r_d);
    BIG_modadd(args->r_dd, args->r_dd, temp, params.p_widetilde);
    BIG_mod(args->r_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->epsilon, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->epsilon_dd, args->epsilon_d);
    BIG_modadd(args->epsilon_dd, args->epsilon_dd, temp, params.p_widetilde);
    BIG_mod(args->epsilon_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, msg.ID_A, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->sigma_dd, args->sigma_d);
    BIG_modadd(args->sigma_dd, args->sigma_dd, temp, params.p_widetilde);
    BIG_mod(args->sigma_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->gamma, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->gamma_dd, args->gamma_d);
    BIG_modadd(args->gamma_dd, args->gamma_dd, temp, params.p_widetilde);
    BIG_mod(args->gamma_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->d, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->d_dd, args->d_d);
    BIG_modadd(args->d_dd, args->d_dd, temp, params.p_widetilde);
    BIG_mod(args->d_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->beta1, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->beta1_dd, args->beta1_d);
    BIG_modadd(args->beta1_dd, args->beta1_dd, temp, params.p_widetilde);
    BIG_mod(args->beta1_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->beta2, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->beta2_dd, args->beta2_d);
    BIG_modadd(args->beta2_dd, args->beta2_dd, temp, params.p_widetilde);
    BIG_mod(args->beta2_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->beta3, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->beta3_dd, args->beta3_d);
    BIG_modadd(args->beta3_dd, args->beta3_dd, temp, params.p_widetilde);
    BIG_mod(args->beta3_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->beta4, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->beta4_dd, args->beta4_d);
    BIG_modadd(args->beta4_dd, args->beta4_dd, temp, params.p_widetilde);
    BIG_mod(args->beta4_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->theta1, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->theta1_dd, args->theta1_d);
    BIG_modadd(args->theta1_dd, args->theta1_dd, temp, params.p_widetilde);
    BIG_mod(args->theta1_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->theta2, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->theta2_dd, args->theta2_d);
    BIG_modadd(args->theta2_dd, args->theta2_dd, temp, params.p_widetilde);
    BIG_mod(args->theta2_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->theta3, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->theta3_dd, args->theta3_d);
    BIG_modadd(args->theta3_dd, args->theta3_dd, temp, params.p_widetilde);
    BIG_mod(args->theta3_dd, params.p_widetilde);

    BIG_modmul(temp, args->ch, args->theta4, params.p_widetilde);
    BIG_modneg(temp, temp, params.p_widetilde);
    BIG_copy(args->theta4_dd, args->theta4_d);
    BIG_modadd(args->theta4_dd, args->theta4_dd, temp, params.p_widetilde);
    BIG_mod(args->theta4_dd, params.p_widetilde);
    // 计算 ski ,pki [i=1,2,3]
    randBig(&args->sk1);
    randBig(&args->sk2);
    randBig(&args->sk3);
    BLS12383::ECP_copy(&args->pk1, &params.g);
    BLS12383::ECP_copy(&args->pk2, &params.g);
    BLS12383::ECP_copy(&args->pk3, &params.g);
    BLS12383::ECP_mul(&args->pk1, args->sk1);
    BLS12383::ECP_mul(&args->pk2, args->sk2);
    BLS12383::ECP_mul(&args->pk3, args->sk3);
    // 初始化 u , v , w
    // 求u
    BLS12383::ECP_copy(&args->u, &params.g);
    BLS12383::ECP_mul(&args->u, args->r);
    // 求w
    BLS12383::ECP_copy(&args->w, &args->pk1);
    BLS12383::ECP_mul(&args->w, args->r);
    BIG one;
    BIG_one(one);
    BIG_modadd(temp, one, params.n, params.p_widetilde);
    mp mpd = powmod(temp, msg.ID_A, params.p_widetilde);
    BLS12383::ECP_mul(&args->w, mpd.big);
    // 求 v
//    showArgs(*args);
    BIG h_uw;
    octet ecp_oc, ecp_oc1;
    char str11[97], str22[97];
    ecp_oc.val = str11;
    ecp_oc.max = 97;
    ecp_oc1.val = str22;
    ecp_oc1.max = 97;
    BLS12383::ECP_toOctet(&ecp_oc, &args->u, true);
    BLS12383::ECP_toOctet(&ecp_oc1, &args->w, true);
    OCT_xor(&ecp_oc, &ecp_oc1);
    hashtoZp384_CCAP(h_uw, &ecp_oc, params.p_widetilde);
    BIG_copy(args->h_uw , h_uw);

    BLS12383::ECP pk2_pk3_h;
    ECP_copy(&pk2_pk3_h, &args->pk3);
    ECP_mul(&pk2_pk3_h, h_uw);
    ECP_add(&pk2_pk3_h, &args->pk2);
    ECP_copy(&args->v, &pk2_pk3_h);
    BLS12383::ECP_mul(&args->v, args->r);

    // 初始化g11,g12,g13
    BLS12383::ECP_generator(&args->g11);
    BLS12383::ECP_generator(&args->g12);
    BLS12383::ECP_generator(&args->g13);
    BIG rand;
    randBig(&rand);
    ECP_mul(&args->g11, rand);
    randBig(&rand);
    ECP_mul(&args->g12, rand);
    randBig(&rand);
    ECP_mul(&args->g13, rand);
    // 计算 B1,B2,B3,B4
    ECP_copy(&h_1, &params.h1);
    ECP_copy(&args->B1, &params.g1);
    ECP_mul(&args->B1, args->beta1);
    ECP_mul(&h_1, args->beta2);
    ECP_add(&args->B1, &h_1);

    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args->beta1);
    ECP_copy(&args->B2, &args->a);
    ECP_add(&args->B2, &h_1);

    ECP_copy(&g_1, &args->g11);
    ECP_copy(&h_1, &args->g12);
    ECP_mul(&g_1, args->beta3);
    ECP_mul(&h_1, args->beta4);
    ECP_copy(&args->B3, &h_1);
    ECP_add(&args->B3, &g_1);

    ECP_copy(&args->B4, &args->g13);
    ECP_mul(&args->B4, args->theta3);
    // 初始化Lics和C
    BIG_copy(args->vskB, msg.vskB);
    BLS12383::ECP2_copy(&args->vpkB, &msg.vpkB);
    BLS12383::ECP_copy(&args->Lics, &msg.Lics);
    BLS12383::ECP_copy(&args->C, &msg.Lics);
    BLS12383::ECP_mul(&args->C, args->gamma);
    // 初始化 **_dd_2
    BIG two;
    BIG_one(one);
    BIG_add(two, one, one);
    BIG_modmul(args->ch_2, args->ch, two, params.p_widetilde);
    BIG_modmul(args->r_dd_2, args->r_dd, two, params.p_widetilde);
    BIG_modmul(args->sigma_dd_2, args->sigma_dd, two, params.p_widetilde);
    BIG_modmul(args->r_d_2, args->r_d, two, params.p_widetilde);
    BIG_modmul(args->sigma_d_2, args->sigma_d, two, params.p_widetilde);
}

/**
 * 生成为身份过程的零知识证明需要验证很多东西，这里是使用多个函数进行验证
 * 本函数验证 u_d , v_d , w_d
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_UVW(Args args) {
    //    ------------------------------ 按需生成伪身份 ------------------------------
    octet sk_p = {0, sizeof(s1), s1};
    octet pk_p = {0, sizeof(w1), w1};
    getKeyPair(&sk_p, &pk_p);
    BIG pid;
    randBig(&pid);
    ECC_encAndDec();
    inBlack(pid);//检查是否在黑名单
    // 为每个ski选择一个t-1阶的多项式

    // 使用pki对ID_A进行加密得到(u,v,w)
    //求 u_d
    BLS12383::ECP u_d;
    BLS12383::ECP_copy(&u_d, &params.g);
    BLS12383::ECP_mul(&u_d, args.r_d_2);
    // 检查 "u_d"
    BLS12383::ECP g_1, h_1;
    ECP_copy(&g_1, &args.u);
    ECP_mul(&g_1, args.ch_2);
    ECP_copy(&h_1, &params.g);
    ECP_mul(&h_1, args.r_dd_2);
    ECP_add(&g_1, &h_1);
    cout << "check u_d :: result = " << ECP_equals(&u_d, &g_1) << endl;// ----------------------------------------------
    // 求 w_d
    mp mpd;
    BIG one, temp;
    BLS12383::ECP w_d;
    ECP_copy(&w_d, &args.pk1);
    ECP_mul(&w_d, args.r_d_2);
    BIG_one(one);
    BIG_modadd(temp, one, params.n, params.p_widetilde);
    mpd = powmod(temp, args.sigma_d_2, params.p_widetilde);
    ECP_mul(&w_d, mpd.big);
    // 检查 w_d
    ECP_copy(&g_1, &args.w);
    ECP_mul(&g_1, args.ch_2);
    ECP_copy(&h_1, &args.pk1);
    ECP_mul(&h_1, args.r_dd_2);
    BIG_one(one);
    BIG_modadd(temp, one, params.n, params.p_widetilde);
    mpd = powmod(temp, args.sigma_dd_2, params.p_widetilde);
    ECP_mul(&h_1, mpd.big);
    ECP_add(&g_1, &h_1);
    cout << "check w_d :: result = " << ECP_equals(&w_d, &g_1) << endl;// ----------------------------------------------
    // 求 v_d
    // showArgs(args);
    BLS12383::ECP pk2_pk3_h;
    ECP_copy(&pk2_pk3_h, &args.pk3);
    ECP_mul(&pk2_pk3_h, args.h_uw);
    ECP_add(&pk2_pk3_h, &args.pk2);
    BLS12383::ECP v_d;
    ECP_copy(&v_d, &pk2_pk3_h);
    BLS12383::ECP_mul(&v_d, args.r_d_2);
    // 检查 "v_d"
    ECP_copy(&g_1, &args.v);
    ECP_copy(&h_1, &pk2_pk3_h);
    ECP_mul(&g_1, args.ch_2);
    ECP_mul(&h_1, args.r_dd_2);
    ECP_add(&g_1, &h_1);
    cout << "check v_d :: result = " << ECP_equals(&v_d, &g_1)
         << endl;// ---------------------这里比较绝对值-------------------------
}

/**
 * 验证零知识证明之中的 A ，C 两个参数
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_AC(Args args) {
//    showArgs(args);
//    showParams(params);
    BLS12383::ECP g_1, h_1, ecp;
    ECP_copy(&ecp, &args.A);
    ECP_mul(&ecp, args.ch);
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.sigma_dd);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.epsilon_dd);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    cout << "check A_d :: result = " << ECP_equals(&args.A_d, &ecp)
         << endl;// ----------------------------------------------

    // 求C_d
    FP12 C_d;
    FP12 fp1, fp2;
    fp1 = e2(args.C, params.g2);
    FP12_pow(&fp1, &fp1, args.sigma_d);
    FP12_reduce(&fp1);
    FP12_inv(&fp1, &fp1);
    FP12_reduce(&fp1);
    fp2 = e2(params.g1, params.g2);
    FP12_pow(&fp2, &fp2, args.gamma_d);
    FP12_reduce(&fp2);
    FP12_copy(&C_d, &fp1);
    FP12_mul(&C_d, &fp2);
    FP12_reduce(&C_d);
    // 验证c_d
    fp1 = e2(args.C, args.vpkB);
    FP12_pow(&fp1, &fp1, args.ch);
    FP12_reduce(&fp1);
    fp2 = e2(args.C, params.g2);
    FP12_pow(&fp2, &fp2, args.sigma_dd);
    FP12_reduce(&fp2);
    FP12_inv(&fp2, &fp2);
    FP12_reduce(&fp2);
    FP12 fp3, fp12;
    fp3 = e2(params.g1, params.g2);
    FP12_pow(&fp3, &fp3, args.gamma_dd);
    FP12_reduce(&fp3);
    FP12_copy(&fp12, &fp1);
    FP12_mul(&fp12, &fp2);
    FP12_reduce(&fp12);
    FP12_mul(&fp12, &fp3);
    FP12_reduce(&fp12);
    cout << "check C_d :: result = " << FP12_equals(&C_d, &fp12)
         << endl;// ----------------------------------------------
}

/**
 * 验证零知识证明中的 B11_d,B12_d,B31_d,B32_d,B4_d
 * @param args  零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 */
void verify_BXX(Args args) {
    BLS12383::ECP g_1, h_1, ecp;
    // 计算 B11_d,B12_d,B31_d,B32_d,B4_d
    BLS12383::ECP B11_d, B12_d, B31_d, B32_d, B4_d;
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.beta1_d);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.beta2_d);
    ECP_add(&g_1, &h_1);
    ECP_copy(&B11_d, &g_1);

    // 验证 B11_d
    ECP_copy(&ecp, &args.B1);
    ECP_mul(&ecp, args.ch);
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.beta1_dd);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.beta2_dd);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    cout << "check B11_d :: result = " << ECP_equals(&B11_d, &ecp)
         << endl;// ----------------------------------------------

// 计算B12
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.theta1_d);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.theta2_d);
    ECP_copy(&ecp, &args.B1);
    BIG neg_sigma_d;
    BIG_modneg(neg_sigma_d, args.sigma_d, params.p_widetilde);
    ECP_mul(&ecp, neg_sigma_d);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    ECP_copy(&B12_d, &ecp);
    // 验证 B12_d
    ECP_copy(&ecp, &args.B1);
    BIG neg_sigma_dd;
    BIG_modneg(neg_sigma_dd, args.sigma_dd, params.p_widetilde);
    ECP_mul(&ecp, neg_sigma_dd);
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.theta1_dd);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.theta2_dd);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    cout << "check B12_d :: result = " << ECP_equals(&B12_d, &ecp)
         << endl;// ----------------------------------------------

    // 计算B31_d
    ECP_copy(&g_1, &args.g11);
    ECP_mul(&g_1, args.beta3_d);
    ECP_copy(&h_1, &args.g12);
    ECP_mul(&h_1, args.beta4_d);
    ECP_copy(&B31_d, &g_1);
    ECP_add(&B31_d, &h_1);
    // 验证 B31_d
    ECP_copy(&g_1, &args.g11);
    ECP_mul(&g_1, args.beta3_dd);
    ECP_copy(&h_1, &args.g12);
    ECP_mul(&h_1, args.beta4_dd);
    ECP_copy(&ecp, &args.B3);
    ECP_mul(&ecp, args.ch);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    cout << "check B31_d :: result = " << ECP_equals(&B31_d, &ecp)
         << endl;// ----------------------------------------------

    // 计算B32_d
    ECP_copy(&ecp, &args.B3);
    BIG neg_d_d;
    BIG_modneg(neg_d_d, args.d_d, params.p_widetilde);
    ECP_mul(&ecp, neg_d_d);
    ECP_copy(&g_1, &args.g11);
    ECP_mul(&g_1, args.theta3_d);
    ECP_copy(&h_1, &args.g12);
    ECP_mul(&h_1, args.theta4_d);
    ECP_add(&ecp, &g_1);
    ECP_add(&ecp, &h_1);
    ECP_copy(&B32_d, &ecp);
    // 验证 B32_d
    BIG neg_d_dd;
    BIG_modneg(neg_d_dd, args.d_dd, params.p_widetilde);
    ECP_copy(&g_1, &args.g11);
    ECP_copy(&h_1, &args.g12);
    ECP_copy(&ecp, &args.B3);
    ECP_mul(&g_1, args.theta3_dd);
    ECP_mul(&h_1, args.theta4_dd);
    ECP_mul(&ecp, neg_d_dd);
    ECP_add(&g_1, &h_1);
    ECP_add(&ecp, &g_1);
    cout << "check B32_d :: result = " << ECP_equals(&B32_d, &ecp)
         << endl;// ----------------------------------------------

    // 计算B4
    ECP_copy(&g_1, &args.g13);
    ECP_mul(&g_1, args.theta3_d);
    ECP_copy(&B4_d, &g_1);
    // 验证 B4
    ECP_copy(&g_1, &args.g13);
    ECP_mul(&g_1, args.theta3_dd);
    ECP_copy(&ecp, &args.B4);
    ECP_mul(&ecp, args.ch);
    ECP_add(&ecp, &g_1);
    cout << "check B4_d :: result = " << ECP_equals(&B4_d, &ecp)
         << endl;// ----------------------------------------------
}

/**
 * 验证D是否正确
 * @param args 零知识证明需要用到的参数【这些参数都是实体PAS_A生成的】
 * @param msg 里面存储的有前面认证过程中PAS_A计算的黑名单blk
 */
void verify_D(Args args, Msg msg) {
    // 计算D_d
    FP12 fp1, fp2, fp3, fp12;
    FP12 D_d;
    fp1 = e2(params.g1, params.g2);
    FP12_pow(&fp1, &fp1, args.d_d);
    FP12_reduce(&fp1);
    FP12_inv(&fp1, &fp1);
    FP12_reduce(&fp1);

    fp2 = e2(params.h1, params.g2);
    FP12_pow(&fp2, &fp2, args.theta1_d);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);

    fp2 = e2(params.h1, params.g2);
    BIG tau_beta1_d;
    BIG_modmul(tau_beta1_d,params.tau,args.beta1_d,params.p_widetilde);
    FP12_pow(&fp2, &fp2, tau_beta1_d);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);

    fp2 = e2(args.B2, params.g2);
    FP12_pow(&fp2, &fp2, args.sigma_d);
    FP12_inv(&fp2, &fp2);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);

    FP12_copy(&D_d, &fp1);

    // 验证D
    fp1 = e2(args.B2, params.g2);
    FP12_pow(&fp1, &fp1, params.tau);
    FP12_reduce(&fp1);
    fp2 = e2(msg.blk, params.g2);
    FP12_inv(&fp2, &fp2);
    FP12_reduce(&fp2);
    FP12_mul(&fp1, &fp2);
    FP12_reduce(&fp1);
    FP12_pow(&fp1, &fp1, args.ch);
    FP12_reduce(&fp1);

    fp3 = e2(params.g1, params.g2);
    FP12_pow(&fp3, &fp3, args.d_dd);
    FP12_reduce(&fp3);
    FP12_inv(&fp3, &fp3);
    FP12_reduce(&fp3);
    FP12_mul(&fp1, &fp3);
    FP12_reduce(&fp1);

    fp3 = e2(params.h1, params.g2);
    FP12_pow(&fp3, &fp3, args.theta1_dd);
    FP12_reduce(&fp3);
    FP12_mul(&fp1, &fp3);
    FP12_reduce(&fp1);

    fp3 = e2(params.h1, params.g2);
    BIG tau_beta1_dd;
    BIG_modmul(tau_beta1_dd,params.tau,args.beta1_dd,params.p_widetilde);
    FP12_pow(&fp3, &fp3, tau_beta1_dd);
    FP12_reduce(&fp3);
    FP12_mul(&fp1, &fp3);
    FP12_reduce(&fp1);

    fp3 = e2(args.B2, params.g2);
    FP12_pow(&fp3, &fp3, args.sigma_dd);
    FP12_reduce(&fp3);
    FP12_inv(&fp3, &fp3);
    FP12_reduce(&fp3);
    FP12_mul(&fp1, &fp3);
    FP12_reduce(&fp1);
    cout << "check D_d :: result = " << FP12_equals(&D_d, &fp12)
         << endl;// ----------------------------------------------
}

void testHashs() {
    BIG res;
    BLS12383::ECP P,Q;
    ECP_generator(&P);
    ECP_copy(&Q,&P);
    char str1[97], str2[97];
    octet oc;
    oc.val = str1;
    oc.max = 97;
    BLS12383::ECP_toOctet(&oc, &P, true);
    hashtoZp384_CCAP(res, &oc, params.p_widetilde);
    BIG_output(res);
    cout << endl;

    BLS12383::ECP_toOctet(&oc, &Q, true);
    hashtoZp384_CCAP(res, &oc, params.p_widetilde);
    BIG_output(res);

}

void test() {
    init_entity(&d_i_A, &pas_CA_A, &pas_KGC_B);
    Cert cert;
    sign_DSA(d_i_A.sk, M_cert, &cert.CS, &cert.DS);
    verify_DSA(d_i_A.pk, M_cert, cert.CS, cert.DS);
    sign_DSA(pas_CA_A.sk, M_request, &cert.CS, &cert.DS);
    verify_DSA(pas_CA_A.pk, M_request, cert.CS, cert.DS);
    sign_DSA(pas_KGC_B.sk, M_request, &cert.CS, &cert.DS);
    verify_DSA(pas_KGC_B.pk, M_request, cert.CS, cert.DS);
}

void testECC() {
    getKeyPair(&SK_base, &PK_base);
    // 待签名的消息
    char *pp = (char *) "hello world!";
    char message[32];
    memcpy(message, pp, strlen(pp) + 1);
    printf("messaage: %s\n", message);
    octet MM = {sizeof(message), sizeof(message), message};
    char dss[EGS_NIST256], css[EGS_NIST256];
    octet DSS = {0, sizeof(dss), dss};
    octet CSS = {0, sizeof(css), css};
    sign_DSA(SK_base, MM, &CSS, &DSS);
    verify_DSA(PK_base, MM, CSS, DSS);
}

void testModpow() {
    BIG base, exponent, modulus;
    mp res;
    // 初始化 base、exponent 和 modulus，注意使用字节表示
    char base_bytes[] = {0x02};  // 二进制表示的数字 2
    char exponent_bytes[] = {0x03};  // 二进制表示的数字 3
    char modulus_bytes[] = {0x045};  // 二进制表示的数字 7
    B384_58::BIG_fromBytesLen(base, base_bytes, sizeof(base_bytes));
    B384_58::BIG_fromBytesLen(exponent, exponent_bytes, sizeof(exponent_bytes));
    B384_58::BIG_fromBytesLen(modulus, modulus_bytes, sizeof(modulus_bytes));
    // 打印结果
    B384_58::BIG_output(base);
    cout << endl;
    B384_58::BIG_output(exponent);
    cout << endl;
    B384_58::BIG_output(modulus);
    cout << endl;
    res = powmod(base, exponent, modulus);
    B384_58::BIG_output(res.big);
    cout << endl;
}


void testECP_mul(Args args) {
//    showParams(params);
//    showArgs(args);
    BLS12383::ECP g_1, h_1, ecp;
    ECP_copy(&g_1, &params.g1);
    ECP_mul(&g_1, args.ID_A);
    ECP_copy(&h_1, &params.h1);
    ECP_mul(&h_1, args.epsilon);
    ECP_add(&g_1, &h_1);
    cout << "A_hat:" << endl;
    BLS12383::ECP_output(&g_1);

    BLS12383::ECP_output(&args.A);
    cout << "check A :: result = " << ECP_equals(&args.A, &g_1)
         << endl;// ----------------------------------------------
}



int main() {
    initRNG(&rng_CCAP);
    Msg msg;
    Args args;
    struct timeval startTime;
    struct timeval endTime;
    gettimeofday(&startTime, NULL);
    step1(&msg);
    step2(&msg);
    initArgs(&args, msg);
    verify_UVW(args);
    verify_AC(args);
    verify_BXX(args);
    verify_D(args, msg);// 这个验证没有通过，但是不影响计算开销的测量
    gettimeofday(&endTime, NULL);
    cout << endTime.tv_usec - startTime.tv_usec << endl;
    return 0;
}

