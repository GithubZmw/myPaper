//
// Created by Miracle on 2023/12/9.
//

#include <iostream>
#include "BASA.h"


csprng rng_rng;

void randBigInt_BASA(BIG *big) {
    BIG mod;
    BIG_rcopy(mod, CURVE_Order);
    BIG_randtrunc(*big, mod, 2 * CURVE_SECURITY_BLS12383, &rng_rng);
}

void hashtoZp384_BASA(BIG num, octet *ct, BIG q) {
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

void H(BIG *result, BIG ID, BIG hid, BIG q) {
    octet oc, oc2;
    char str[48], str2[48], str3[48];
    BIG_toBytes(str, ID);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;

    BIG_toBytes(str2, hid);
    oc2.val = str2;
    oc2.len = sizeof str2;
    oc2.max = sizeof str2;
    OCT_xor(&oc, &oc2);

    BIG_toBytes(str3, q);
    oc2.val = str3;
    oc2.len = sizeof str3;
    oc2.max = sizeof str3;
    OCT_xor(&oc, &oc2);

    BIG t1;
    hashtoZp384_BASA(t1, &oc, q);

    BIG_copy(*result, t1);
}

FP12 e3(ECP alpha1, ECP2 alpha2) {
    FP12 temp1;
    PAIR_ate(&temp1, &alpha2, &alpha1);
    PAIR_fexp(&temp1);
    FP12_reduce(&temp1);
    if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
        printf("pairing error [temp1]\n");
    }
    return temp1;
}


void Setup(Params *params, BIG *privKey) {
    BIG hid;
    randBigInt_BASA(&hid);
    BIG_copy(params->hid, hid);
    BIG_rcopy(params->N, CURVE_Order);
    BIG_rcopy(params->q, CURVE_Order);
    ECP_generator(&params->P1);
    ECP2_generator(&params->P2);
    //    选择私钥,计算公钥
    BIG ks;
    randBigInt_BASA(&ks);
    ECP2_copy(&params->P_pub_s, &params->P2);
    ECP2_mul(&params->P_pub_s, ks);
    BIG_copy(*privKey, ks);
}

ECP KGC_genKey(BIG ID, Params params, BIG ks) {
    BIG t1;
    H(&t1, ID, params.hid, params.q);
    BIG_modadd(t1, t1, ks, params.N);
    BIG t2;
    BIG_copy(t2, t1);
    BIG_invmodp(t2, t2, params.N);
    BIG_modmul(t2, t2, ks, params.q);
    BIG_mod(t2, params.q);
    ECP D_id;
    ECP_copy(&D_id, &params.P1);
    ECP_mul(&D_id, t2);
    return D_id;
}

Signature SM9_sign(Params params, ECP sk_e, BIG M) {
    FP12 gt;
    gt = e3(params.P1, params.P_pub_s);
    BIG r;
    randBigInt_BASA(&r);
    FP12 w;
    FP12_pow(&w, &gt, r);
    FP12_reduce(&w);

    BIG h;
    H(&h, w.a.a.a.g, M, params.N);

    BIG l;
    BIG_copy(l, h);
    BIG_modneg(l, l, params.q);
    BIG_modadd(l, r, l, params.N);
    BIG_mod(l, params.N);
    ECP S;
    ECP_copy(&S, &sk_e);
    ECP_mul(&S, l);
    Signature sig;
    BIG_copy(sig.h, h);
    ECP_copy(&sig.S, &S);
    return sig;
}

bool SM9_verify(Signature signature, Params params, BIG IDe, BIG M_p) {

    bool flag = true;
    flag = flag && (BIG_comp(signature.h, params.N) <= 0);
    FP12 gt;
    gt = e3(params.P1, params.P_pub_s);
    FP12 t;
    FP12_pow(&t, &gt, signature.h);
    FP12_reduce(&t);

    BIG h1;
    H(&h1, IDe, params.hid, params.q);

    ECP2 P;
    ECP2_copy(&P, &params.P2);
    ECP2_mul(&P, h1);
    ECP2_add(&P, &params.P_pub_s);

    FP12 u;
    u = e3(signature.S, P);

    FP12 w_p;
    FP12_copy(&w_p, &u);
    FP12_mul(&w_p, &t);
    FP12_reduce(&w_p);

    BIG h2;
    H(&h2, w_p.a.a.a.g, M_p, params.q);
    return (BIG_comp(h2, signature.h) == 0);
}

bool isValid(XID xid) {
    bool res;
    struct timeval currTime;
    gettimeofday(&currTime, NULL);
    res = xid.deadline - currTime.tv_sec;
    return res > 0;
}

XID genPID(Params params, BIG ks) {
    BIG ID;
    randBigInt_BASA(&ID);
    struct timeval currTime;
    gettimeofday(&currTime, NULL);
    XID ID_ei_A;
    BIG_copy(ID_ei_A.ID, ID);
    ID_ei_A.deadline = currTime.tv_sec;
    return ID_ei_A;
}

void UpdateKeyRequest() {
//    cout << "Send update key request" << endl;
}

void UpdateKey() {
//    cout << "KGC_A update key" << endl;
}

void Send_sk_ei_A() {
//    cout << "send sk_ei_A to ei_A" << endl;
}

void crossDomainAuthRequest() {
//    cout << "cross Domain Authentication Request" << endl;
}

void BASA() {
    struct timeval startTime;
    struct timeval endTime;
    // ------------------------------------- 注册阶段 --------------------------------------------
    // 初始化参数
    initRNG(&rng_rng);
    Params params;
    BIG ks;

    long setupTime = 0, regTime = 0, signTime = 0, verifyTime = 0,signTime_eiA = 0, signTime_KGC = 0;
    int repeatCount = 100;
    for (int i = 0; i < repeatCount; ++i) {
        // 1. 初始化系统参数
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Setup(&params, &ks);
        gettimeofday(&endTime, NULL);
        setupTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // 2. 生成真实身份,并向KGC申请对应的签名私钥(注册阶段)
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        XID RID_ei_A = genPID(params, ks);
        gettimeofday(&endTime, NULL);
        regTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // 3. KGC为真实身份生成对应的签名私钥
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        ECP RID_sk = KGC_genKey(RID_ei_A.ID, params, ks);
        gettimeofday(&endTime, NULL);
        regTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        // 4. ei_A生成伪身份
        gettimeofday(&startTime, NULL);
        XID ID_ei_A = genPID(params, ks);
        gettimeofday(&endTime, NULL);
        regTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // 5. KGC为伪身份生成对应的签名私钥
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        ECP D_id = KGC_genKey(ID_ei_A.ID, params, ks);
        gettimeofday(&endTime, NULL);
        regTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // ------------------------------------- 跨域认证 --------------------------------------------
        // 1. ei_A验证自己当前伪身份的合法性
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        bool Valid = isValid(ID_ei_A);
        if (!Valid) {
            // 重新生成伪身份,为伪身份生成对应的签名私钥
            XID ID_ei_A = genPID(params, ks);
            ECP D_id = KGC_genKey(ID_ei_A.ID, params, ks);
        }
        // 2. 如果伪身份有效,那么使用真实身份的签名私钥对伪身份进行签名
        Signature signature = SM9_sign(params, RID_sk, ID_ei_A.ID);
        gettimeofday(&endTime, NULL);
        signTime_eiA += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // 3. KGC_A验证签名的正确性并为其ei_A生成签名私钥
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        bool flag = SM9_verify(signature, params, RID_ei_A.ID, ID_ei_A.ID);
//        cout << "flag: " << flag << endl;
        ECP sk_ei_A = KGC_genKey(ID_ei_A.ID, params, ks);
        gettimeofday(&endTime, NULL);
        signTime_KGC += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // 4. KGC_A向BAS_A发送密钥更新请求
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        UpdateKeyRequest();
        // 5. BAS_A更新域A中寡欲ei_A的密钥
        UpdateKey();
        // 6. KGC_A收到BAS_A的响应后,将sk_ei发给ei_A
        Send_sk_ei_A();
        // 7. ei_A生成消息M
        BIG N_ei_A;
        randBigInt_BASA(&N_ei_A);
        BIG M;
        BIG_add(M, ID_ei_A.ID, N_ei_A);
        // 8. 将消息M发给AAS_A,AAS_A生成消息M的签名
        signature = SM9_sign(params, sk_ei_A, M);
        // 9. AAS_A将签名给ei_A,然后ei_A给ej_B发送认证请求
        crossDomainAuthRequest();
        gettimeofday(&endTime, NULL);
        signTime_KGC += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        // 10. ej_B向AAS_B发送请求,验证签名的征正确性
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        flag = flag && SM9_verify(signature, params, ID_ei_A.ID, M);
        gettimeofday(&endTime, NULL);
        verifyTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "flag: " << flag << endl;

    }
    signTime = signTime_eiA + signTime_KGC;
    cout << "BASA's Setup time consumption is : " << setupTime / repeatCount << " us" << endl;
    cout << "BASA's Register time consumption is : " << regTime / repeatCount << " us" << endl;
    cout << "BASA's Sign_eiA time consumption is : " << signTime_eiA / repeatCount << " us" << endl;
    cout << "BASA's Sign_KGC time consumption is : " << signTime_KGC / repeatCount << " us" << endl;
    cout << "BASA's Sign time consumption is : " << signTime / repeatCount << " us" << endl;
    cout << "BASA's Verify time consumption is : " << verifyTime / repeatCount << " us" << endl;
}


//int main() {
//    BASA();
//    return 0;
//}