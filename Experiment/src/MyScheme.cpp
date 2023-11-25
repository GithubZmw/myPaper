//
// Created by 曾明伟 on 2023/11/21.
//

#include "common.h"
#include "MyScheme.h"
#include "iostream"


using namespace std;
DM DM1;
SD SD1;
// ------------------------------------------------ 工具函数的定义 -------------------------------------------------------

/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 */
void hashtoZp384(BIG num, octet *ct) {
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
    BIG_mod(num, DM1.q);
}


/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param res  哈希之后的结果
 * @param beHashed 被哈希的值
 */
void hashToZp384(BIG res, BIG beHashed) {
    char idChar[48];
    BIG_toBytes(idChar, beHashed);
    octet id_i_oc;
    id_i_oc.max = 48;
    id_i_oc.val = idChar;
    hashtoZp384(res, &id_i_oc);
}


csprng rng1;//随机数发生器

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


// 双线性映射
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

// G_T上的乘法
FP12 GT_Mul(FP12 temp1, FP12 temp2) {
    FP12_mul(&temp1, &temp2);
    FP12_reduce(&temp1);
    if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
        printf("pairing error [mul]\n");
    }
    return temp1;
}

// ECP上的点乘运算，运算不改变传入的参数
ECP myECP_mul(ECP ecp, BIG b) {
    ECP_mul(&ecp, b);
    return ecp;
}


// ECP2上的点乘运算,运算不改变传入的参数
ECP2 myECP2_mul(ECP2 ecp2, BIG b) {
    ECP2_mul(&ecp2, b);
    return ecp2;
}

// ECP上的点乘运算，运算不改变传入的参数
ECP myECP_add(ECP e1, ECP e2) {
    ECP_add(&e1, &e2);
    return e1;
}

//// ECP2上的点乘运算，运算不改变传入的参数
//ECP2 myECP2_add(ECP2 e1, ECP2 e2) {
//    ECP2_add(&e1, &e2);
//    return e1;
//}

void showItem(itemDM item) {
    cout << "--------- [item.j]:" << endl;
    cout << item.j << endl;
    cout << "--------- [item.id_i]:" << endl;
    BIG_output(item.id_i);
    cout << endl;
    cout << "--------- [item.si_P]:" << endl;
    ECP2_output(&item.si_P);
    cout << "--------- [item.isJoin]:" << endl;
    cout << item.isJoin << endl;
    cout << "--------- [item.W_i]:" << endl;
    ECP_output(&item.W_i);
}


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
    ECP2_output(&dm.P_pub);
    cout << "--------- [DM.ACC]:" << endl;
    ECP_output(&dm.ACC);
    // 遍历输出vector
    for (int i = 0; i < DM1.L.size(); ++i) {
        cout << "----------------------- -------------- -----------------------" << endl
             << "----------------------- L[" << i << "] -----------------------" << endl
             << "----------------------- -------------- -----------------------" << endl;
        showItem(DM1.L[i]);

    }
    cout
            << "------------------------------------------------------- showDM ----------------------------------------------------"
            << endl;
}

void showSD(SD sd) {
    cout
            << "------------------------------------------------------- showSD ----------------------------------------------------"
            << endl;

    cout << "--------- [SD.j]:" << endl;
    cout << sd.j << endl;
    cout << endl << "--------- [SD.s_i]:" << endl;
    BIG_output(sd.s_i);
    cout << endl << "--------- [SD.C_i]:" << endl;
    ECP_output(&sd.C_i);
    cout << "--------- [SD.W_i]:" << endl;
    ECP_output(&sd.W_i);
    cout
            << "------------------------------------------------------- showSD ----------------------------------------------------"
            << endl;

}


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
    ECP2_output(&msg2.T1);
    cout << "--------- [Msg2.T2]:" << endl;
    ECP2_output(&msg2.T2);
    cout << "--------- [Msg2.T3]:" << endl;
    ECP2_output(&msg2.T3);
    cout << "--------- [Msg2.A1]:" << endl;
    ECP_output(&msg2.A_1);
    cout << "--------- [Msg2.A1]:" << endl;
    ECP_output(&msg2.A_2);
    cout
            << "------------------------------------------------------- showMsg2 ----------------------------------------------------"
            << endl;

}

// ------------------------------------------------ 域管理员操作 -------------------------------------------------------

void Update() {
    for (int i = SD1.j; i < DM1.L.size(); i++) {
        char *idChar;
        BIG temp;
        BIG_add(temp, SD1.s_i, DM1.x);
        if (DM1.L[i].isJoin) {
            BIG_invmod2m(temp);
        }
        ECP_mul(&SD1.W_i, temp);
    }
}


ECP p1;
ECP2 p2, temp2[10];

void init(ECP *p1, ECP2 *p2) {
    ECP_copy(p1, &DM1.P_1);
    ECP2_copy(p2, &DM1.P_2);
}

/**
 * 域管理员的初始化阶段，生成系统参数供其他实体使用
 */
void Setup(DM *dm) {
    BIG_rcopy(dm->q, CURVE_Order);
    // 生成系统公私钥对
    BIG x;
    randBigInt(&x);
    BIG_copy(dm->x, x);
    ECP2_generator(&dm->P_2);
    ECP2_copy(&dm->P_pub, &dm->P_2);
    ECP2_mul(&dm->P_pub, x);
    // 初始化累加器
    BIG r;
    randBigInt(&r);
    ECP_generator(&dm->P_1);
    ECP_copy(&dm->ACC, &dm->P_1);
    ECP_mul(&dm->ACC, r);
    // 更新数据

}


// 加入过程SD执行的第一阶段，生成随机数
void Join_SD_step1(BIG *id_i) {
    randBigInt(id_i);
}

/**
 * 当智能设备想要加入域时，需要先向域管理员注册，该函数为Join过程中DM需要进行的操作
 * @param dm 本域的域管理员
 * @param id_i 待加入智能设备的身份
 * @param x 域管理员DM的私钥
 */
Msg1 Join_DM(DM *dm, BIG id_i, BIG x) {
    // 计算群成员证书,更新累加器的值
    BIG s_i, temp;
    ECP C_i;
    hashToZp384(s_i, id_i);
    BIG_add(temp, s_i, x);
    ECP_mul(&dm->ACC, temp);//更新累加器
    BIG_invmodp(temp, temp, dm->q);
    ECP_copy(&C_i, &dm->P_1);//计算群成员证书
    ECP_mul(&C_i, temp);
    // 存储必要的信息用于打开
    itemDM item;
    item.j++;//这里应该使用随机生成的数，这样就无法通过j来威胁安全性了
    BIG_copy(item.id_i, id_i);
    item.si_P = dm->P_2;
//    ECP2_copy(&item.si_P, &DM1.P_2);
    ECP2_mul(&item.si_P, s_i);
    item.isJoin = true;
    item.W_i = dm->ACC;
    dm->L.push_back(item);

//    将消息返回给SD
    Msg1 msg1;
    msg1.j = item.j;
    msg1.C_i = C_i;
    msg1.W_i = dm->ACC;
    return msg1;
}

// 接入过程中SD执行的第二阶段，存储证书等信息
void Join_SD_step2(BIG id_i, Msg1 msg1) {
    SD1.j = msg1.j;
    SD1.C_i = msg1.C_i;
    SD1.W_i = msg1.W_i;
    BIG hash;
    hashToZp384(hash, id_i);
    BIG_copy(SD1.s_i, hash);
}

/**
 * 智能设备的签名算法
 * @param sd 智能设备
 * @param dm 智能设备所属的域管理员
 * @return  返回签名消息
 */
Msg2 Sign(SD sd, DM dm) {
    BIG u;
    randBigInt(&u);

    ECP2 T1, T2, T3;//计算这三个点
    ECP2_copy(&T1, &dm.P_2);
    ECP2_mul(&T1, u);
    ECP2_copy(&T2, &T1);
    ECP2_mul(&T2, u);
    ECP2 uP_pub;
    ECP2_copy(&uP_pub, &dm.P_pub);
    ECP2_mul(&uP_pub, u);
    ECP2_copy(&T3, &dm.P_2);
    ECP2_mul(&T3, sd.s_i);
    ECP2_add(&T3, &uP_pub);

    ECP A1, A2;//计算这两个点
    ECP_copy(&A1, &sd.W_i);
    ECP_mul(&sd.W_i, u);
    ECP_copy(&A2, &sd.C_i);
    ECP_mul(&sd.C_i, u);

    //  求R1,R2,R4
    BIG ru, rs;
    randBigInt(&ru);
    randBigInt(&rs);
    ECP2 R1, R2, R4;
    ECP2_copy(&R1, &dm.P_2);
    ECP2_mul(&R1, ru);
    ECP2_copy(&R2, &R1);
    ECP2_mul(&R2, ru);
    ECP2 ru_P_pub;
    ECP2_copy(&R4, &dm.P_2);
    ECP2_mul(&R4, rs);
    ECP2_copy(&ru_P_pub, &dm.P_pub);
    ECP2_mul(&ru_P_pub, ru);
    ECP2_add(&R4, &ru_P_pub);
    // 求R3
    FP12 t1, t2;
    FP12 R3, m2;
    ECP A1pA2;
    A1pA2 = myECP_add(A1, A2);
    t1 = e(A1pA2, dm.P_pub);
    FP12_pow(&R3, &t1, ru);
    t2 = e(A1pA2, T1);
    FP12_pow(&m2, &t2, rs);
    FP12_mul(&R3, &m2);
    // 计算挑战c
    BIG c;
    char str1[48], str2[48];
    octet oc1, oc2;
    oc1.val = str1;
    oc1.max = 1024;
    oc2.val = str2;

    ECP2_toOctet(&oc1, &T1, true);
    ECP2_toOctet(&oc2, &T2, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &T3, true);
    OCT_xor(&oc1, &oc2);
    ECP_toOctet(&oc2, &A1, true);
    OCT_xor(&oc1, &oc2);
    ECP_toOctet(&oc2, &A2, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R1, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R2, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R4, true);
    OCT_xor(&oc1, &oc2);
    // 有可能有问题
    FP12_toOctet(&oc2, &R3);
    OCT_joctet(&oc1, &oc2);
    hashtoZp384(c, &oc1);
    // 计算 ss 和 su
    BIG su, ss, temp;
//    BIG_modmul(su, c, u,dm.q);
    BIG_mul(temp, c, u);
    BIG_add(su, ru, temp);
//    BIG_modmul(ss, c, sd.s_i,dm.q);
    BIG_mul(temp, c, sd.s_i);
    BIG_add(ss, rs, temp);
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


    showMsg2(msg2);
    return msg2;
}

/**
 * 域管理员DM验证消息
 * @param msg2 智能设备生成的签名
 * @return 签名验证通过则返回true，否则返回false
 */
bool Verify(Msg2 msg2, DM dm) {
    cout
            << "------------------------------------------------------- Verify -------------------------------------------------------------"
            << endl;
    showMsg2(msg2);//--------------------------------------------------

    ECP2 T1, T2, T3;
    T1 = msg2.T1;
    T2 = msg2.T2;
    T3 = msg2.T3;
    ECP A1, A2;
    //  求R1,R2
    ECP2 R1, R2;
    ECP2_copy(&R1, &DM1.P_2);
    ECP2_mul(&R1, msg2.su);
    ECP2_copy(&R2, &R1);
    ECP2_mul(&T1, msg2.c);
    ECP2_sub(&R1, &T1);
    ECP2_mul(&T2, msg2.c);
    ECP2_sub(&R2, &T2);
    //  求R3
    FP12 t1, t2, t3;
    FP12 R3, m2, m3;
    ECP A1pA2;
    A1pA2 = myECP_add(A1, A2);
    t1 = e(A1pA2, DM1.P_pub);
    FP12_pow(&R3, &t1, msg2.su);
    t2 = e(A1pA2, T1);
    FP12_pow(&m2, &t2, msg2.ss);
    t3 = e(DM1.ACC, T2);
    BIG_invmodp(msg2.c, msg2.c, dm.q);
    showMsg2(msg2);//--------------------------------------------------
    FP12_pow(&m3, &t3, msg2.c);
    GT_Mul(R3, m2);
    GT_Mul(R3, m3);
    //  求R4
    ECP2 R4, P_pub;
    ECP2_copy(&R4, &DM1.P_2);
    ECP2_mul(&R4, msg2.ss);
    ECP2_copy(&P_pub, &DM1.P_pub);
    ECP2_mul(&P_pub, msg2.su);
    BIG_invmodp(msg2.c, msg2.c, dm.q);
    ECP2_mul(&T3, msg2.c);
    ECP2_add(&R4, &P_pub);
    ECP2_sub(&R4, &T3);
    // 求哈希得到c
    //初始化T1,T2,T3  [因为上面的操作将T1,T2,T3的值改变了]
    showMsg2(msg2);//--------------------------------------------------
    T1 = msg2.T1;
    T2 = msg2.T2;
    T3 = msg2.T3;
    char str1[48], str2[48];
    octet oc1, oc2;
    oc1.val = str1;
    oc1.max = 2048;
    oc2.val = str2;
    ECP2_toOctet(&oc1, &T1, true);
    ECP2_toOctet(&oc2, &T2, true);
    OCT_joctet(&oc1, &oc2);
    ECP2_toOctet(&oc2, &T3, true);
    OCT_joctet(&oc1, &oc2);
    ECP_toOctet(&oc2, &A1, true);
    OCT_joctet(&oc1, &oc2);
    ECP_toOctet(&oc2, &A1, true);
    OCT_joctet(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R1, true);
    OCT_joctet(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R2, true);
    OCT_joctet(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R4, true);
    OCT_joctet(&oc1, &oc2);
    //    有可能有问题
    FP12_toOctet(&oc2, &R3);
    OCT_joctet(&oc1, &oc2);
    BIG c_hat;
    hashtoZp384(c_hat, &oc1);
    cout << "c_hat:" << endl;
    BIG_output(c_hat);
    cout << endl;
    return BIG_comp(c_hat, msg2.c) == 0 ? true : false;
}


void Open() {
//    Verify();
    ECP2 T1, T3;
    ECP2_mul(&T1, DM1.x);
    ECP2_sub(&T3, &T1);
//    根据T3查找map，从而得到签名者的真实身份


}

void Revoke() {
//    根据item做以下操作
    itemDM item;
    char *idChar;
    BIG_toBytes(idChar, item.id_i);
    octet id_i_oc;
    id_i_oc.max = 48;
    id_i_oc.val = idChar;
    BIG s_i;
    hashtoZp384(s_i, &id_i_oc);
    BIG temp;
    BIG_add(temp, s_i, DM1.x);
    BIG_invmod2m(temp);
    ECP_mul(&DM1.ACC, temp);
}



// ------------------------------------------------ 域内设备的操作 -------------------------------------------------------






/**
 * 测试得出我改写后的函数没有问题
 * 1、使用我写的函数，不会改变传入参数的值，并返回正确的结果
 */
void testMyFunction() {
    ECP test11;
    ECP_generator(&test11);
    ECP_output(&test11);
    ECP test12;
    ECP_generator(&test12);
    ECP_output(&test12);


    ECP2 test21;
    ECP2_generator(&test21);
    ECP2_output(&test21);
    ECP2 test22;
    ECP2_generator(&test22);
    ECP2_output(&test22);


    cout << "---------------------------------------------- ECP ----------------------------------------------" << endl;
    BIG b;
    randBigInt(&b);
    ECP_output(&test11);
    ECP_mul(&test11, b);
    ECP_output(&test11);

    cout << "---------------------------------------------- myECP ----------------------------------------------"
         << endl;

    ECP_output(&test11);
    myECP_mul(test11, b);
    ECP_output(&test11);


    cout << "---------------------------------------------- ECP2 ----------------------------------------------"
         << endl;

    randBigInt(&b);
    ECP2_output(&test21);
    ECP2_mul(&test21, b);
    ECP2_output(&test21);

    cout << "---------------------------------------------- myECP2 ----------------------------------------------"
         << endl;

    ECP2_output(&test21);
    myECP2_mul(test21, b);
    ECP2_output(&test21);


    cout << "---------------------------------------------- GT_ml ----------------------------------------------"
         << endl;
    FP12 fp1, fp2;
    fp1 = e(test11, test21);
    fp2 = e(test12, test22);
    FP12_output(&fp1);
    cout << endl;
    FP12_mul(&fp1, &fp2);
    FP12_output(&fp1);
    cout << endl;

    cout << "---------------------------------------------- myGT_ml ----------------------------------------------"
         << endl;
    fp1 = e(test11, test21);
    fp2 = e(test12, test22);
    FP12_output(&fp1);
    cout << endl;
    fp2 = GT_Mul(fp1, fp2);
    FP12_output(&fp1);
    cout << endl;
    FP12_output(&fp2);
    cout << endl;
}


// 测试octet的连接操作和转字符转操作
void testOctet() {
    char ch[] = "happy birthday";
    char res[100];
    octet oc;
    oc.max = 100;
    oc.val = ch;
    oc.len = (sizeof oc.val - 1) * 2;//去点字符串结尾的字符
    OCT_output(&oc);
    OCT_toStr(&oc, res);
    cout << res << endl;


    char ch2[] = "to you";
    octet oc2;
    oc2.max = 100;
    oc2.val = ch2;
    oc2.len = (sizeof oc2.len - 1) * 2;
    OCT_output(&oc2);

    OCT_toStr(&oc2, res);
    cout << res << endl;

    OCT_joctet(&oc, &oc2);
    OCT_output(&oc);


    cout << oc.len << endl;
    OCT_toStr(&oc, res);
    cout << res << endl;
}

//测试BIG_comp是否比较的是两个BIG的值
void testBIGComp() {
//    BIG a;
//    BIG_fromBytesLen(a,"123",3);
//    BIG b;
//    BIG_fromBytesLen(b,"123",3);
//    if(BIG_comp(a,b) == 0){
//        cout << "success" <<endl;
//    } else{
//        cout << "defeat" <<endl;
//    }
}


void testVerify() {
    ECP2 T1, T2, T3;
    ECP2 R1, R2, R4;
    ECP A1, A2, R3;

    BIG r;
    ECP2_generator(&T1);
    randBigInt(&r);
    ECP2_mul(&T2, r);
    randBigInt(&r);
    ECP2_mul(&T3, r);
    randBigInt(&r);
    ECP2_mul(&R1, r);
    randBigInt(&r);
    ECP2_mul(&R2, r);
    randBigInt(&r);
    ECP2_mul(&R4, r);

    randBigInt(&r);
    ECP_mul(&A1, r);
    randBigInt(&r);
    ECP_mul(&A2, r);
    randBigInt(&r);
    ECP_mul(&R3, r);

    char str1[48], str2[48];
    octet oc1, oc2;
    oc1.val = str1;
    oc1.max = 1024;
    ECP2_toOctet(&oc1, &T1, true);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    oc2.val = str2;
    ECP2_toOctet(&oc2, &T2, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP2_toOctet(&oc2, &T3, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP_toOctet(&oc2, &A1, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP_toOctet(&oc2, &A1, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP2_toOctet(&oc2, &R1, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP2_toOctet(&oc2, &R2, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

    ECP2_toOctet(&oc2, &R4, true);
    OCT_joctet(&oc1, &oc2);
    OCT_output(&oc1);
    cout << oc1.len << "," << oc1.max << endl;

//    FP12_toOctet(&oc1,&R3);
    BIG c_hat;
    hashtoZp384(c_hat, &oc1);
    BIG_output(c_hat);

//    if(BIG_comp(c_hat,c) == 0){
//        cout << "验证成功" <<endl;
//    }
}


void testFP12() {
    BIG b;
    randBigInt(&b);
    char str[] = "2379434";
    octet oc;
    oc.val = str;
//  生成FP12
    FP12 fp12;
    FP12_fromOctet(&fp12, &oc);
    cout << endl
         << "----------------------------------------------------------- genFP12 ------------------------------- "
         << endl << endl;
    FP12_output(&fp12);
    cout << endl;

//  将FP12转化为octet
    FP12_toOctet(&oc, &fp12);
    cout << endl
         << "----------------------------------------------------------- FP12_toOctet result is : ------------------------------- "
         << endl << endl;
    OCT_output(&oc);

    cout << endl << "----------------------------------------------------------- back ------------------------------- "
         << endl << endl;

    FP12_fromOctet(&fp12, &oc);
    FP12_output(&fp12);
}


void test_hashToZp() {
    BIG beHashed, test;
    randBigInt(&beHashed);
    BIG_rcopy(test, CURVE_Order);
    BIG_output(beHashed);
    cout << endl;
    BIG_output(test);
    cout << endl;

    cout << "------------------------------------------------------------hash-----------------------------------------"
         << endl;
    BIG res;
    hashToZp384(res, beHashed);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, beHashed);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, test);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, test);
    BIG_output(res);
    cout << endl;

}


// 测试ECP使用等于号直接赋值，而不使用它的copy方法赋值
void testECP() {
    ECP g;
    ECP_generator(&g);
    ECP_output(&g);
    ECP test;
    test = g;
    ECP_output(&test);

    cout << "-----------------------------------------------" << endl;
    BIG b;
    randBigInt(&b);
    ECP_mul(&g, b);// 改变g的值，看看test会不会跟着改变
    ECP_output(&g);
    ECP_output(&test);

    cout << "-----------------------------------------------" << endl;

    randBigInt(&b);
    ECP_mul(&g, b);// 改变g的值，看看test会不会跟着改变
    ECP_output(&g);
    ECP_output(&test);
}


/**
 * 测试求逆元的函数
 * 这里BIG_invmod2m用来求 a=1/a mod 2^BIGBITS_XXX. 速度很快  (有些元素没有逆元，该方法会返回false)
 * BIGBITS_XXX表示的是BIG所占的位数
 *      【使用B256_56::BIG创建变量，则BIGBITS_XXX等于256，函数球的的逆元是一个256bit的数】
 *      【使用B384_58::BIG创建变量，则BIGBITS_XXX等于384，函数球的的逆元是一个384bit的数】
 */
void test_invmod2m() {

    cout << "------------------------- test B384_58 -------------------------" << endl;

    BIG a;
    BIG_fromBytesLen(a, "6", 1);
    BIG_output(a);
    cout << endl;
    BIG_invmod2m(a);
    BIG_output(a);
    cout << endl;
    BIG_invmod2m(a);
    BIG_output(a);
    cout << endl;


    randBigInt(&a);
    BIG_output(a);
    cout << endl;
    BIG_invmod2m(a);
    BIG_output(a);
    cout << endl;
    BIG_invmod2m(a);
    BIG_output(a);
    cout << endl;


    cout << "------------------------- test B384_58 -------------------------" << endl;

    BIG b;
    BIG_fromBytesLen(b, "3", 1);
    BIG_output(b);
    cout << endl;
    BIG_invmod2m(b);
    BIG_output(b);
    cout << endl;
    BIG_invmod2m(b);
    BIG_output(b);
    cout << endl;


    randBigInt(&b);
    BIG_output(b);
    cout << endl;
    BIG_invmod2m(b);
    BIG_output(b);
    cout << endl;
    BIG_invmod2m(b);
    BIG_output(b);
    cout << endl;

    cout << "----------------------------- test B256_56 ---------------------" << endl;
    B256_56::BIG c;
    B256_56::BIG_fromBytesLen(c, "99", 1);
    B256_56::BIG_output(c);
    cout << endl;
    B256_56::BIG_invmod2m(c);
    B256_56::BIG_output(c);
    cout << endl;
    B256_56::BIG_invmod2m(c);
    B256_56::BIG_output(c);
    cout << endl;


    B256_56::BIG_fromBytesLen(c, "123456789", 7);
    B256_56::BIG_output(c);
    cout << endl;
    B256_56::BIG_invmod2m(c);
    B256_56::BIG_output(c);
    cout << endl;
    B256_56::BIG_invmod2m(c);
    B256_56::BIG_output(c);
    cout << endl;
}


void test_inv() {
    cout << "------------------------- test B384_58 -------------------------" << endl;

    BIG a, b, n;
    BIG_fromBytesLen(a, "2", 1);
    BIG_fromBytesLen(b, "5", 1);
    BIG_fromBytesLen(n, "7", 1);

    BIG_output(b);
    cout << endl;
    BIG_invmodp(b, a, n);
    BIG_output(b);
    cout << endl;
    BIG_invmodp(b, a, n);
    BIG_output(b);
    cout << endl;
}

/**
 * 注意：
 * 需要su和ss的计算后面需要mod q  【还要注意同余性质的应用】
 * 将ECP上的点转换后异或操作，从而达到异或多个点的目的
 */
void testSchnoor() {
    BIG order;
    BIG_rcopy(order, CURVE_Order);
    ECP P;
    ECP_generator(&P);
    BIG sk;
    randBigInt(&sk);
    ECP PK;
    ECP_copy(&PK, &P);
    ECP_mul(&PK, sk);
    BIG r;
    randBigInt(&r);
    ECP R;
    ECP_copy(&R, &P);
    ECP_mul(&R, r);
    cout << "-------------R:" << endl;
    ECP_output(&R);


    char str[48];
    octet oc;
    oc.val = str;
    oc.max = 384;

    char str2[48];
    octet oc2;
    oc2.val = str2;
    oc.max = 384;
    ECP_toOctet(&oc, &R, true);
    ECP_toOctet(&oc2, &PK, true);
    OCT_xor(&oc, &oc2);
    cout << "------------------------------------------------------------" << endl;
    OCT_output(&oc);

    FP12 fp12;
    ECP2 ecp2;
    ECP2_generator(&ecp2);
    ECP2_mul(&ecp2,r);
    fp12 = e(R,ecp2);
    FP12_toOctet(&oc2, &fp12);
    OCT_shl(&oc2, 120*4);
    OCT_output(&oc2);


    OCT_xor(&oc, &oc2);



    BIG c;
    hashtoZp384(c, &oc);


    BIG z;
    BIG_modmul(z, c, sk, order);
    BIG_modadd(z, r, z, order);
    BIG_mod(z, order);

    ECP zP;
    ECP_copy(&zP, &P);
    ECP_mul(&zP, z);
    cout << "-------------zP:" << endl;
    ECP_output(&zP);


    ECP cPK;
    ECP_copy(&cPK, &PK);
    ECP_mul(&cPK, c);

    ECP R_hat;
    ECP_copy(&R_hat, &zP);
    ECP_sub(&R_hat, &cPK);
    cout << "-------------R_hat:" << endl;
    ECP_output(&R_hat);
}

void testMyScheme() {
    //     准备工作
    initRNG(&rng1);
//    showDM(DM1);
//    初始化阶段
    Setup(&DM1);
//    showDM(DM1);
//  SD加入群组[模拟三个人加入]
//    for (int i = 0; i < 3; ++i) {
    BIG id_i;
    randBigInt(&id_i);
    Msg1 msg1 = Join_DM(&DM1, id_i, DM1.x);
    Join_SD_step2(id_i, msg1);
//    showDM(DM1);
//    showSD(SD1);
//    }
    Msg2 msg2 = Sign(SD1, DM1);
    bool pass = Verify(msg2, DM1);
    if (pass) {
        cout << "success" << endl;
    } else {
        cout << "defeat" << endl;
    }

}

int main() {
    initRNG(&rng1);
    testSchnoor();
//    testMyScheme();
    return 0;

}


