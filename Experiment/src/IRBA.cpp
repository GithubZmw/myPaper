//
// Created by 曾明伟 on 2023/12/12.
//

#include <iostream>
#include <chrono>
#include "IRBA.h"

// 随机数种子
csprng rng_IRBA;

// 系统参数
Params param;



long long getCurrentTime() {
    return chrono::duration_cast<chrono::microseconds>(chrono::system_clock::now().time_since_epoch()).count();
}


void randBigInt_IRBA(BIG *big) {
    BIG mod;
    BIG_rcopy(mod, CURVE_Order);
    BIG_randtrunc(*big, mod, 2 * CURVE_SECURITY_BLS12383, &rng_IRBA);
}


void hashtoZp384_IRBA(BIG num, octet *ct, BIG q) {
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



void H1(ECP2 *result, BIG ID_UE, BIG t, ECP P) {
    octet oc, oc2;
    char str[48], str2[48], str3[48];
    BIG_toBytes(str, ID_UE);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;

    BIG_toBytes(str2, t);
    oc2.val = str2;
    oc2.len = sizeof str2;
    oc2.max = sizeof str2;
    OCT_xor(&oc, &oc2);

    BIG_toBytes(str3, P.x.g);
    oc2.val = str3;
    oc2.len = sizeof str3;
    oc2.max = sizeof str3;
    OCT_xor(&oc, &oc2);

    BIG t1;
    hashtoZp384_IRBA(t1, &oc, param.q);
    ECP2_copy(result, &param.Q);
    ECP2_mul(result, t1);
}



void H2(ECP *result, BIG m) {
    octet oc;
    char str[48];
    BIG_toBytes(str, m);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;

    BIG t1;
    hashtoZp384_IRBA(t1, &oc, param.q);
    ECP_copy(result, &param.P);
    ECP_mul(result, t1);
}


void H2(ECP2 *result, BIG m) {
    octet oc;
    char str[48];
    BIG_toBytes(str, m);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;
    BIG t1;
    hashtoZp384_IRBA(t1, &oc, param.q);
    ECP2_copy(result, &param.Q);
    ECP2_mul(result, t1);
}



void H3(BIG *result, FP12 x, FP12 y, FP12 w, FP12 sigma) {
    octet oc, oc2;
    char str[48], str2[48], str3[48];
    BIG_toBytes(str, x.a.a.a.g);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;

    BIG_toBytes(str2, y.a.a.a.g);
    oc2.val = str2;
    oc2.len = sizeof str2;
    oc2.max = sizeof str2;
    OCT_xor(&oc, &oc2);

    BIG_toBytes(str3, w.a.a.a.g);
    oc2.val = str3;
    oc2.len = sizeof str3;
    oc2.max = sizeof str3;
    OCT_xor(&oc, &oc2);

    BIG_toBytes(str3, sigma.a.a.a.g);
    oc2.val = str3;
    oc2.len = sizeof str3;
    oc2.max = sizeof str3;
    OCT_xor(&oc, &oc2);

    hashtoZp384_IRBA(*result, &oc, param.q);
}



FP12 e_IRBA(ECP alpha1, ECP2 alpha2) {
    FP12 temp1;
    PAIR_ate(&temp1, &alpha2, &alpha1);
    PAIR_fexp(&temp1);
    FP12_reduce(&temp1);
    if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
        printf("pairing error [temp1]\n");
    }
    return temp1;
}


// 测试写的哈希函数是否正确
void testH123() {
    BIG b1, b2, b3, b4;
    randBigInt_IRBA(&b1);
    randBigInt_IRBA(&b2);
    randBigInt_IRBA(&b3);
    randBigInt_IRBA(&b4);

    ECP P11, P12, P13, P14;
    ECP_generator(&P11);
    ECP_generator(&P12);
    ECP_generator(&P13);
    ECP_generator(&P14);
    ECP_mul(&P11, b1);
    ECP_mul(&P12, b2);
    ECP_mul(&P13, b3);
    ECP_mul(&P14, b4);

    ECP2 P21, P22, P23, P24;
    ECP2_generator(&P21);
    ECP2_generator(&P22);
    ECP2_generator(&P23);
    ECP2_generator(&P24);
    ECP2_mul(&P21, b1);
    ECP2_mul(&P22, b2);
    ECP2_mul(&P23, b3);
    ECP2_mul(&P24, b4);

    FP12 fp1, fp2, fp3, fp4;
    fp1 = e_IRBA(P11, P21);
    fp2 = e_IRBA(P12, P22);
    fp3 = e_IRBA(P13, P23);
    fp4 = e_IRBA(P14, P24);

    ECP res1;
    ECP2 res2;
    BIG res3;
    cout
            << "------------------------------------------------------- test H1 -------------------------------------------------------"
            << endl;
    H1(&res2, b1, b2, P11);
    ECP2_output(&res2);
    H1(&res2, b1, b2, P11);
    ECP2_output(&res2);
    cout
            << "------------------------------------------------------ test H2-1 ------------------------------------------------------"
            << endl;
    H2(&res1, b2);
    ECP_output(&res1);
    H2(&res1, b2);
    ECP_output(&res1);
    cout
            << "------------------------------------------------------ test H2-2 ------------------------------------------------------"
            << endl;
    H2(&res2, b2);
    ECP2_output(&res2);
    H2(&res2, b2);
    ECP2_output(&res2);
    cout
            << "------------------------------------------------------- test H3 -------------------------------------------------------"
            << endl;
    H3(&res3, fp1, fp2, fp3, fp4);
    BIG_output(res3);
    cout << endl;
    H3(&res3, fp1, fp2, fp3, fp4);
    BIG_output(res3);
    cout << endl;
}



void showUE(UE ue) {
    cout
            << "------------------------------------------------------- showUE ----------------------------------------------------"
            << endl;

    cout << "--------- [UE.ID_UE]:" << endl;
    BIG_output(ue.ID_UE);
    cout << endl << "--------- [UE.r]:" << endl;
    BIG_output(ue.r);
    cout << endl << "--------- [UE.t]:" << endl;
    BIG_output(ue.t);
    cout << endl << "--------- [UE.R]:" << endl;
    ECP_output(&ue.R);
    cout << "--------- [SD.S_ID]:" << endl;
    ECP2_output(&ue.S_ID);
    cout
            << "------------------------------------------------------- showUE ----------------------------------------------------"
            << endl;

}

void showSign(Sign sign) {
    cout
            << "------------------------------------------------------- showSign ----------------------------------------------------"
            << endl;

    cout << "--------- [Sign.z]:" << endl;
    BIG_output(sign.z);
    cout << endl << "--------- [Sign.theta]:" << endl;
    ECP2_output(&sign.theta);
    cout << endl << "--------- [Sign.epsilon]:" << endl;
    ECP2_output(&sign.epsolon);
    cout << endl << "--------- [Sign.sigma]:" << endl;
    FP12_output(&sign.sigma);
    cout << "--------- [Sign.w]:" << endl;
    FP12_output(&sign.w);
    cout
            << "------------------------------------------------------- showSign ----------------------------------------------------"
            << endl;

}



void Setup(Params *params, AS *As) {
    BIG_rcopy(params->q, CURVE_Order);
    ECP_generator(&params->P);
    ECP2_generator(&params->Q);
    //    选择私钥,计算公钥
    randBigInt_IRBA(&As->s);
    ECP_copy(&params->P_pub, &params->P);
    ECP_mul(&params->P_pub, As->s);
}


// 签名请求
void Sign_request() {
    cout << "UE Extract request" << endl;
}


Msg1_Extract Extract_UE(Params params, UE *ue) {
    Msg1_Extract msg1;
    randBigInt_IRBA(&ue->r);
    ECP_copy(&msg1.R, &params.P);
    ECP_mul(&msg1.R, ue->r);
    ECP_copy(&ue->R, &msg1.R);

    randBigInt_IRBA(&ue->ID_UE);
    BIG_copy(msg1.ID_UE, ue->ID_UE);
    BIG t = {getCurrentTime()};
    BIG_copy(msg1.t, t);
    BIG_copy(ue->t, t);
    return msg1;
}


Msg2_Extract Extract_AS(Params params, Msg1_Extract msg1, AS As) {
    // 求Q_ID
    ECP2 Q_ID;
    H1(&Q_ID, msg1.ID_UE, msg1.t, msg1.R);
    // 求S_ID
    ECP2 S_ID;
    ECP2_copy(&S_ID, &Q_ID);
    ECP2_mul(&S_ID, As.s);
    // 求返回消息
    Msg2_Extract msg2;
    ECP2_copy(&msg2.S_ID, &S_ID);
    return msg2;
}


void Extract_UE2(UE *ue, Msg2_Extract msg2) {
    ECP2_copy(&ue->S_ID, &msg2.S_ID);
}

Sign Signing(Params params, BIG m, UE ue, AS *As) {
    // 发送签名请求
    Sign_request();
    // AS选择一个随机数N发给UE.由于是交互式的认证，后面验证签名时需要用到这个N，应该由AS存储这个N
    // 考虑到多个UE同时与AS认证的情况，AS应该维护一个<ID_UE,N>的；列表，这里为了简单，AS中只存储一个N
    randBigInt_IRBA(&As->N);
    // 计算签名
    Sign sign;
    // 1. 求theta
    ECP2 H2M;
    H2(&H2M, m);
    ECP2_copy(&sign.theta, &H2M);
    ECP2_mul(&sign.theta, ue.r);
    // 2. 求sigma
    ECP H2N;
    H2(&H2N, As->N);
    sign.sigma = e_IRBA(H2N, ue.S_ID);
    // 3. 求 w
    ECP2 Q_ID;
    H1(&Q_ID, ue.ID_UE, ue.t, ue.R);
    sign.w = e_IRBA(H2N, Q_ID);
    // 4. 求z
    FP12 x, y;
    x = e_IRBA(params.P, params.Q);
    y = e_IRBA(H2N, params.Q);
    H3(&sign.z, x, y, sign.w, sign.sigma);
    // 5. 求epsilon
    ECP2_copy(&sign.epsolon, &ue.S_ID);
    ECP2_mul(&sign.epsolon, sign.z);
    ECP2_add(&sign.epsolon, &params.Q);
    return sign;
}


bool Verify(Params params, BIG m, Sign sign, UE ue, AS As) {
    // 恢复消息
    ECP2 Q_ID;
    H1(&Q_ID, ue.ID_UE, ue.t, ue.R);
    ECP H2N;
    H2(&H2N, As.N);
    FP12 w, miu;
    w = e_IRBA(H2N, Q_ID);
    miu = e_IRBA(params.P_pub, Q_ID);
    FP12 x, y;
    x = e_IRBA(params.P, params.Q);
    y = e_IRBA(H2N, params.Q);
    BIG z;
    H3(&z, x, y, w, sign.sigma);
    //验证下面三个等式
    FP12 left, right;
    // 1. 第一个等式
    left = e_IRBA(params.P, sign.theta);
    ECP2 H2M;
    H2(&H2M, m);
    right = e_IRBA(ue.R, H2M);
    bool flag = true;
    flag = FP12_equals(&left, &right);
    // 2. 第二个等式
    left = e_IRBA(params.P, sign.epsolon);
    FP12_pow(&right, &miu, z);
    FP12_reduce(&right);
    FP12_mul(&right, &x);
    FP12_reduce(&right);
    flag = flag && FP12_equals(&left, &right);
    // 3. 第三个等式
    left = e_IRBA(H2N, sign.epsolon);
    FP12_copy(&right, &y);
    FP12_pow(&sign.sigma, &sign.sigma, z);
    FP12_reduce(&sign.sigma);
    FP12_mul(&right, &sign.sigma);
    FP12_reduce(&right);
    flag = flag && FP12_equals(&left, &right);
    return flag;
}


// “IRBA”认证方案的全流程
void IRBA(){
    struct timeval startTime;
    struct timeval endTime;
    // 1. 初始化阶段
    AS As;
    initRNG(&rng_IRBA);
    // 2. 系统参数生成
    gettimeofday(&startTime, NULL);
    Setup(&param, &As);
    gettimeofday(&endTime, NULL);
    cout << "IRBA's Setup time consumption is : " <<  endTime.tv_usec - startTime.tv_usec << " us" <<  endl;
    // 3. Extract阶段
    gettimeofday(&startTime, NULL);
    UE ue;
    Msg1_Extract msg1 = Extract_UE(param, &ue);
    Msg2_Extract msg2 = Extract_AS(param, msg1, As);
    Extract_UE2(&ue, msg2);
    gettimeofday(&endTime, NULL);
    cout << "IRBA's Extract time consumption is : " <<  endTime.tv_usec - startTime.tv_usec << " us" <<  endl;
    // 4. Signing阶段
    gettimeofday(&startTime, NULL);
    BIG m;
    randBigInt_IRBA(&m);
    Sign sign = Signing(param, m, ue, &As);
    gettimeofday(&endTime, NULL);
    cout << "IRBA's Signing time consumption is : " <<  endTime.tv_usec - startTime.tv_usec << " us" <<  endl;
    // 5. Verify阶段
    gettimeofday(&startTime, NULL);
    cout << (Verify(param, m, sign, ue, As) ? "verify success" : "verify defeat") << endl;
    gettimeofday(&endTime, NULL);
    cout << "IRBA's Verify time consumption is : " <<  endTime.tv_usec - startTime.tv_usec << " us" <<  endl;
}


//int main() {
//    IRBA();
//    return 0;
//}




