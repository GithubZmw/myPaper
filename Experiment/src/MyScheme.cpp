//
// Created by 曾明伟 on 2023/11/21.
//

#include "common.h"
#include "MyScheme.h"
#include "iostream"


BIG order;// 椭圆曲线的阶
csprng rng1;//随机数发生器
vector<DM> BC;// 区块链实体
DM DM1;//域管理员实例
SD SD1[3];//智能设备SD实例




// ------------------------------------------------ 工具函数的定义 -------------------------------------------------------


void hashtoZp384(BIG num, octet *ct, BIG q) {
    hash384 h;
    // 数组长度设为48，由于每一位char用两个十六进制的数字表示【可以表示256个字符，刚好表示ASCII表】，则将其转化为为BIG后，数字长度为96，每个16进制用4个bit表示，故96*4=384
    char hashstr[48];
    memset(hashstr, 0, 48);//逐字节初始化charstr
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


void hashToZp384(BIG res, BIG beHashed, BIG q) {
    char idChar[48];
    BIG_toBytes(idChar, beHashed);
    octet id_i_oc;
    id_i_oc.max = 48;
    id_i_oc.val = idChar;
    hashtoZp384(res, &id_i_oc, q);
}

void initRNG(core::csprng *rng) {
    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    unsigned long ran;
    time((time_t *) &ran);

    RAW.len = 100; // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (int i = 4; i < 100; i++)
        RAW.val[i] = i;

    CREATE_CSPRNG(rng, &RAW);
}

/**
 * 生成一个Fq有限域上的随机数
 * @param big 随机数对象，生成的随机数的值将会赋值给这个变量
 */
void randBigInt(BIG *big) {
    BIG mod;
    BIG_rcopy(mod, CURVE_Order);
    BIG_randtrunc(*big, mod, 2 * CURVE_SECURITY_BLS12383, &rng1);
}

FP12 e(ECP alpha1, ECP2 alpha2) {
    FP12 temp1;
    PAIR_ate(&temp1, &alpha2, &alpha1);
    PAIR_fexp(&temp1);
    FP12_reduce(&temp1);
    if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
        printf("pairing error [temp1]\n");
    }
    return temp1;
}

void H(BIG *c, ECP T1, ECP T2, ECP T3, ECP2 A1, ECP2 A2, ECP R1, ECP R2, FP12 R3, ECP R4, DM dm) {
    // 计算挑战c
    octet oc, oc2;
    char str[48], str2[48], str3[48];
    BIG_toBytes(str, T1.x.g);
    oc.val = str;
    oc.len = sizeof str;
    oc.max = sizeof str;
    BIG_toBytes(str2, T2.x.g);
    oc2.val = str2;
    oc2.len = sizeof str2;
    oc2.max = sizeof str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, T3.x.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, A1.x.a.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, A2.x.a.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, R1.x.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, R2.x.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(str2, R4.x.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    BIG_toBytes(oc2.val, R3.a.a.a.g);
    oc2.val = str2;
    OCT_xor(&oc, &oc2);
    hashtoZp384(*c, &oc2, dm.q);
}


void showItem(itemDM item) {
    cout << "--------- [item.id_i]:" << endl;
    BIG_output(item.id_i);
    cout << endl;
    cout << "--------- [item.si_P]:" << endl;
    ECP_output(&item.si_P);
    cout << "--------- [item.isJoin]:" << endl;
    cout << item.isJoin << endl;
    cout << "--------- [item.W_i]:" << endl;
    ECP2_output(&item.W_i);
}

//控制台查看DM
void showDM(DM dm) {
    cout
            << "------------------------------------------------------- showDM ----------------------------------------------------"
            << endl;
    cout << "--------- [DM.q]:" << endl;
    BIG_output(dm.q);
    cout << endl << "--------- [DM.x]:" << endl;
    BIG_output(dm.x);
    cout << endl << "--------- [DM.P_1]:" << endl;
    ECP_output(&dm.P_1);
    cout << "--------- [DM.P_2]:" << endl;
    ECP2_output(&dm.P_2);
    cout << "--------- [DM.P_pub]:" << endl;
    ECP_output(&dm.P_pub);
    cout << "--------- [DM.ACC]:" << endl;
    ECP2_output(&dm.ACC);
    // 遍历输出vector
    for (int i = 0; i < dm.L.size(); ++i) {
        cout << "----------------------- -------------- -----------------------" << endl
             << "----------------------- L[" << i << "] -----------------------" << endl
             << "----------------------- -------------- -----------------------" << endl;
        showItem(dm.L[i]);

    }
    cout
            << "------------------------------------------------------- showDM ----------------------------------------------------"
            << endl;
}

void showSD(SD sd) {
    cout
            << "------------------------------------------------------- showSD ----------------------------------------------------"
            << endl;

    cout << "--------- [SD.id_i]:" << endl;
    BIG_output(sd.id_i);
    cout << endl << "--------- [SD.s_i]:" << endl;
    BIG_output(sd.s_i);
    cout << endl << "--------- [SD.C_i]:" << endl;
    ECP2_output(&sd.C_i);
    cout << "--------- [SD.W_i]:" << endl;
    ECP2_output(&sd.W_i);
    cout
            << "------------------------------------------------------- showSD ----------------------------------------------------"
            << endl;

}

//控制台查看Msg2
void showMsg2(Msg2 msg2) {
    cout
            << "------------------------------------------------------- showMsg2 ----------------------------------------------------"
            << endl;

    cout << "--------- [Msgs.c]:" << endl;
    BIG_output(msg2.c);
    cout << endl;
    cout << endl << "--------- [Msg2.su]:" << endl;
    BIG_output(msg2.su);
    cout << endl;
    cout << endl << "--------- [Msg2.ss]:" << endl;
    BIG_output(msg2.ss);
    cout << endl;
    cout << "--------- [Msg2.T1]:" << endl;
    ECP_output(&msg2.T1);
    cout << "--------- [Msg2.T2]:" << endl;
    ECP_output(&msg2.T2);
    cout << "--------- [Msg2.T3]:" << endl;
    ECP_output(&msg2.T3);
    cout << "--------- [Msg2.A1]:" << endl;
    ECP2_output(&msg2.A_1);
    cout << "--------- [Msg2.A1]:" << endl;
    ECP2_output(&msg2.A_2);
    cout
            << "------------------------------------------------------- showMsg2 ----------------------------------------------------"
            << endl;
}


// ------------------------------------------------ 域管理员操作 -------------------------------------------------------

void Update(SD *sd, DM dm) {

    BIG res;
    BIG_one(res);
    itemDM back = dm.L.back();
    while (BIG_comp(back.id_i, sd->id_i) != 0) {
        BIG si;
        hashToZp384(si, back.id_i, dm.q);
        BIG_add(si, si, dm.x);
        if (!back.isJoin) {
            BIG_invmodp(si, si, dm.q);
        }
        BIG_modmul(res, res, si, order);
        dm.L.pop_back();
        back = dm.L.back();
    }
//    BIG_output(res);
//    cout << endl;
    ECP2_mul(&sd->W_i, res);
}

void Setup(DM *dm) {

    BIG_rcopy(dm->q, CURVE_Order);
    // 生成系统公私钥对
    BIG x;
    randBigInt(&x);
    BIG_copy(dm->x, x);
    ECP_generator(&dm->P_1);
    ECP_copy(&dm->P_pub, &dm->P_1);
    ECP_mul(&dm->P_pub, x);
    // 初始化累加器
    BIG r;
    randBigInt(&r);
    ECP2_generator(&dm->P_2);
    ECP2_copy(&dm->ACC, &dm->P_2);
    ECP2_mul(&dm->ACC, r);
    // 更新数据
}

void Join_SD_step1(SD *sd, BIG *id_i) {
    randBigInt(id_i);
    BIG_copy(sd->id_i, *id_i);
}

Msg1 Join_DM(DM *dm, BIG id_i, BIG x) {
    itemDM item;
    item.W_i = dm->ACC;
    // 计算群成员证书,更新累加器的值
    BIG s_i, temp;
    ECP2 C_i;
    hashToZp384(s_i, id_i, dm->q);
    BIG_modadd(temp, s_i, x, dm->q);
    ECP2_mul(&dm->ACC, temp);//更新累加器
    BIG_invmodp(temp, temp, dm->q);
    ECP2_copy(&C_i, &dm->P_2);//计算群成员证书
    ECP2_mul(&C_i, temp);
    // 存储必要的信息用于打开
    BIG_copy(item.id_i, id_i);
    item.si_P = dm->P_1;
    ECP_mul(&item.si_P, s_i);
    item.isJoin = true;
    dm->L.push_back(item);
//    将消息返回给SD
    Msg1 msg1;
    msg1.C_i = C_i;
    msg1.W_i = item.W_i;
    return msg1;
}

void Join_SD_step2(SD *sd, BIG id_i, Msg1 msg1, DM dm) {
    sd->C_i = msg1.C_i;
    sd->W_i = msg1.W_i;
    hashToZp384(sd->s_i, id_i, dm.q);
}


FP12 fp1, fp2;

void preComputation(SD sd, DM dm) {
    ECP2 Ci_p_Wi;
    ECP2_copy(&Ci_p_Wi, &sd.C_i);
    ECP2_add(&Ci_p_Wi, &sd.W_i);
    fp1 = e(dm.P_pub, Ci_p_Wi);
    fp2 = e(dm.P_1, Ci_p_Wi);
}


Msg2 Sign(SD sd, DM dm, bool usePreComp) {

    BIG u;
    randBigInt(&u);
    ECP T1, T2, T3;//计算这三个点
    ECP_copy(&T1, &dm.P_1);
    ECP_mul(&T1, u);
    ECP_copy(&T2, &T1);
    ECP_mul(&T2, u);
    ECP uP_pub;
    ECP_copy(&uP_pub, &dm.P_pub);
    ECP_mul(&uP_pub, u);
    ECP_copy(&T3, &dm.P_1);
    ECP_mul(&T3, sd.s_i);
    ECP_add(&T3, &uP_pub);

    ECP2 A1, A2;//计算这两个点
    ECP2_copy(&A1, &sd.W_i);
    ECP2_mul(&A1, u);
    ECP2_copy(&A2, &sd.C_i);
    ECP2_mul(&A2, u);

    BIG ru, rs;
    randBigInt(&ru);
    randBigInt(&rs);
    ECP R1, R2, R4;//  求R1,R2,R4
    ECP_copy(&R1, &dm.P_1);
    ECP_mul(&R1, ru);
    ECP_copy(&R2, &T1);
    ECP_mul(&R2, ru);
    ECP ru_P_pub;
    ECP_copy(&ru_P_pub, &dm.P_pub);
    ECP_mul(&ru_P_pub, ru);
    ECP_copy(&R4, &dm.P_1);
    ECP_mul(&R4, rs);
    ECP_add(&R4, &ru_P_pub);

    // 求R3
    FP12 t1, t2;
    FP12 R3, m2;
    if (usePreComp) {
        BIG uru,u2rs;
        BIG_modmul(uru,u,ru,dm.q);
        BIG_modmul(u2rs,u,u,dm.q);
        BIG_modmul(u2rs,u2rs,rs,dm.q);
        FP12_pow(&R3, &fp1, uru);
        FP12_reduce(&R3);
        FP12_pow(&m2, &fp2, u2rs);
        FP12_reduce(&m2);
        FP12_mul(&R3, &m2);
        FP12_reduce(&R3);
    } else {
        ECP2 A1pA2;
        ECP2_copy(&A1pA2, &A1);
        ECP2_add(&A1pA2, &A2);
        t1 = e(dm.P_pub, A1pA2);
        FP12_pow(&R3, &t1, ru);
        FP12_reduce(&R3);

        t2 = e(T1, A1pA2);
        FP12_pow(&m2, &t2, rs);
        FP12_reduce(&m2);
        FP12_mul(&R3, &m2);
        FP12_reduce(&R3);
    }

    // 计算挑战c
    BIG c;
    H(&c, T1, T2, T3, A1, A2, R1, R2, R3, R4, dm);

    // 计算 ss 和 su
    BIG su, ss;
    BIG_modmul(su, c, u, dm.q);
    BIG_modadd(su, ru, su, dm.q);
    BIG_mod(su, dm.q);
    BIG_modmul(ss, c, sd.s_i, dm.q);
    BIG_modadd(ss, rs, ss, dm.q);
    BIG_mod(ss, dm.q);
    // 返回值
    Msg2 msg2;
    msg2.T1 = T1;
    msg2.T2 = T2;
    msg2.T3 = T3;
    msg2.A_1 = A1;
    msg2.A_2 = A2;
    BIG_copy(msg2.c, c);
    BIG_copy(msg2.ss, ss);
    BIG_copy(msg2.su, su);
    return msg2;
}

bool Verify(Msg2 msg2, DM dm) {

    ECP T1, T2, T3;
    T1 = msg2.T1;
    T2 = msg2.T2;
    T3 = msg2.T3;

    //  求R1_hat,R2_hat
    ECP R1_hat, R2_hat;
    ECP_copy(&R1_hat, &dm.P_1);
    ECP_mul(&R1_hat, msg2.su);
    ECP_mul(&T1, msg2.c);
    ECP_sub(&R1_hat, &T1);

    ECP_copy(&R2_hat, &msg2.T1);
    ECP_mul(&R2_hat, msg2.su);
    ECP_mul(&T2, msg2.c);
    ECP_sub(&R2_hat, &T2);
    //  求R3_hat
    T1 = msg2.T1;
    T2 = msg2.T2;// 求R1和R2的时候对T1和T2进行了修改，因此重新初始化
    ECP2 A1, A2;
    A1 = msg2.A_1;
    A2 = msg2.A_2;//

    FP12 t1, t2, t3;
    FP12 R3_hat, m2, m3;
    ECP2 A1pA2;
    ECP2_copy(&A1pA2, &A1);
    ECP2_add(&A1pA2, &A2);

    t1 = e(dm.P_pub, A1pA2);
    FP12_pow(&R3_hat, &t1, msg2.su);
    FP12_reduce(&R3_hat);

    t2 = e(T1, A1pA2);
    FP12_pow(&m2, &t2, msg2.ss);
    FP12_reduce(&m2);

    ECP2 ACCpP2;
    ECP2_copy(&ACCpP2, &dm.ACC);
    ECP2_add(&ACCpP2, &dm.P_2);
    t3 = e(T2, ACCpP2);
    FP12_pow(&m3, &t3, msg2.c);
    FP12_reduce(&m3);
    FP12_inv(&m3, &m3);
    FP12_reduce(&m3);
    FP12_mul(&R3_hat, &m2);
    FP12_reduce(&R3_hat);
    FP12_mul(&R3_hat, &m3);
    FP12_reduce(&R3_hat);

    //  求R4
    ECP R4_hat, P_pub;
    ECP_copy(&R4_hat, &dm.P_1);
    ECP_mul(&R4_hat, msg2.ss);
    ECP_copy(&P_pub, &dm.P_pub);
    ECP_mul(&P_pub, msg2.su);
    ECP_mul(&T3, msg2.c);
    ECP_add(&R4_hat, &P_pub);
    ECP_sub(&R4_hat, &T3);

    // 求哈希得到c_hat
    BIG c_hat;
    H(&c_hat, T1, T2, T3, A1, A2, R1_hat, R2_hat, R3_hat, R4_hat, dm);

    return BIG_comp(c_hat, msg2.c) == 0 ? true : false;
}

itemDM Open(Msg2 msg2, DM dm) {
    itemDM item;
    if (Verify(msg2, dm)) {
        ECP_mul(&msg2.T1, dm.x);
        ECP_sub(&msg2.T3, &msg2.T1);
        for (int i = 0; i < dm.L.size(); ++i) {
            if (ECP_equals(&msg2.T3, &dm.L[i].si_P)) {
                return dm.L[i];
            }
        }
    }

    return item;
}

void Revoke(itemDM item, DM *dm) {
//    根据item做以下操作
    BIG s_i;
    hashToZp384(s_i, item.id_i, dm->q);
    BIG_add(s_i, s_i, dm->x);
    BIG_invmodp(s_i, s_i, dm->q);
    ECP2_mul(&dm->ACC, s_i);
    itemDM newItem;
    BIG_copy(newItem.id_i, item.id_i);
    newItem.si_P = item.si_P;
    newItem.isJoin = false;
    newItem.W_i = dm->ACC;
    dm->L.push_back(newItem);
}

void te() {

}

// 我们方案的全流程
void MyScheme() {


    // 1. 准备工作
    initRNG(&rng1);
    BIG_rcopy(order, CURVE_Order);

    struct timeval startTime;
    struct timeval endTime;
    long setupTime = 0, joinTime = 0, signTime = 0, verTime = 0, openTime = 0, revokeTime = 0, updateTime = 0, reSignTime = 0, preSignTime = 0;
    int repeatCount = 100;
    for (int i = 0; i < repeatCount; ++i) {
        // 2. 初始化阶段
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Setup(&DM1);
        gettimeofday(&endTime, NULL);
        setupTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "MyScheme's Setup time consumption is : \t" <<  endTime.tv_usec - startTime.tv_usec << " us" <<endl;

        // 3. SD加入群组[模拟三个人加入]
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        for (int i = 0; i < 3; ++i) {
            BIG id_i;
            Join_SD_step1(&SD1[i], &id_i);
            Msg1 msg1 = Join_DM(&DM1, id_i, DM1.x);
            Join_SD_step2(&SD1[i], id_i, msg1, DM1);
        }
        gettimeofday(&endTime, NULL);
        joinTime += ((endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec)) / 3;
//        cout << "MyScheme's Join time consumption is : \t" <<  (endTime.tv_usec - startTime.tv_usec)/3 <<" us" << endl;

        // 4. 智能设备 SD[2] 进行签名
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Msg2 msg2 = Sign(SD1[2], DM1, false);
        gettimeofday(&endTime, NULL);
        signTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "MyScheme's Sign time consumption is : \t" <<  endTime.tv_usec - startTime.tv_usec << " us" <<endl;

        // 5. 域管理员验证
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Verify(msg2, DM1);
        gettimeofday(&endTime, NULL);
        verTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << (Verify(msg2, DM1) ? "verify success" : "verify defeat") << endl;
//        cout << "MyScheme's Verify time consumption is : " <<  endTime.tv_usec - startTime.tv_usec <<" us" << endl;

        // 6. 假设SD[2]是恶意设备，首先通过其签名msg2揭露他的真实身份。
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        itemDM item = Open(msg2, DM1);
        gettimeofday(&endTime, NULL);
        openTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "MyScheme's Open time consumption is : \t" <<  endTime.tv_usec - startTime.tv_usec <<" us" << endl;

        // 7. 根据真实身份撤销这个智能设备
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Revoke(item, &DM1);
        gettimeofday(&endTime, NULL);
        revokeTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "MyScheme's Revoke time consumption is : " <<  endTime.tv_usec - startTime.tv_usec <<" us" << endl;

        // 8. 撤销后假设智能设备SD[0]想要进行认证,先更新证据，在进行跨域认证
        timerclear(&startTime);
        timerclear(&endTime);
        gettimeofday(&startTime, NULL);
        Update(&SD1[0], DM1);
        gettimeofday(&endTime, NULL);
        updateTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << "MyScheme's Update time consumption is : " <<  endTime.tv_usec - startTime.tv_usec <<" us" << endl;
        // 跨域认证时间
        gettimeofday(&startTime, NULL);
        Msg2 msg22 = Sign(SD1[0], DM1, false);
        Verify(msg22, DM1);
        gettimeofday(&endTime, NULL);
        reSignTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
//        cout << (Verify(msg22, DM1) ? "verify success" : "verify defeat") << endl;
//        cout << "Resign and Verify time consumption is : " <<  endTime.tv_usec - startTime.tv_usec << " us" <<  endl;

////         9. 撤销SD[2]后假设智能设备SD[2]想要进行认证,此时认证无法通过
//        timerclear(&startTime);
//        timerclear(&endTime);
//        Update(&SD1[2],DM1);
//        Msg2 msg222 = Sign(SD1[2], DM1,usePreComp);
//        cout << "SD[2] has been revoked,so it is not going to make cross authentication" << endl;
//        cout << (Verify(msg222, DM1) ? "verify success" : "verify defeat") << endl;

        // 10. 有预计算的认证速度
        timerclear(&startTime);
        timerclear(&endTime);
        Update(&SD1[1], DM1);
        preComputation(SD1[1], DM1);

        gettimeofday(&startTime, NULL);
        Msg2 msg111 = Sign(SD1[1], DM1, true);
        gettimeofday(&endTime, NULL);
        preSignTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

//        cout << (Verify(msg111, DM1) ? "verify success" : "verify defeat") << endl;

    }

    cout << "MyScheme's Setup time consumption is : \t" << setupTime / repeatCount << " us" << endl;
    cout << "MyScheme's Join time consumption is : \t" << joinTime / repeatCount << " us" << endl;
    cout << "MyScheme's Sign time consumption is : \t" << signTime / repeatCount << " us" << endl;
    cout << "MyScheme's Verify time consumption is : " << verTime / repeatCount << " us" << endl;
    cout << "MyScheme's Open time consumption is : \t" << openTime / repeatCount << " us" << endl;
    cout << "MyScheme's Revoke time consumption is : " << revokeTime / repeatCount << " us" << endl;
    cout << "MyScheme's Update time consumption is : " << updateTime / repeatCount << " us" << endl;
    cout << "Resign and Verify time consumption is : " << reSignTime / repeatCount << " us" << endl;
    cout << "preCompSign time consumption is : \t" << preSignTime / repeatCount << " us" << endl;

}


//int main() {
//    MyScheme();
//    return 0;
//}

