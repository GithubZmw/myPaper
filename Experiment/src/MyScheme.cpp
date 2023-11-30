//
// Created by 曾明伟 on 2023/11/21.
//

#include "common.h"
#include "MyScheme.h"
#include "iostream"


using namespace std;

// ------------------------------------------------ 工具函数的定义 -------------------------------------------------------

/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param num 将哈希结果映射到Z_p上得到的元素
 * @param ct 要哈希的数
 * @param q 有限域的阶
 */
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


/**
 * 哈希函数，将大数ct哈希到有限域Z_p上,并将结果存储在num
 * @param res  哈希之后的结果
 * @param beHashed 被哈希的值
 */
void hashToZp384(BIG res, BIG beHashed, BIG q) {
    char idChar[48];
    BIG_toBytes(idChar, beHashed);
    octet id_i_oc;
    id_i_oc.max = 48;
    id_i_oc.val = idChar;
    hashtoZp384(res, &id_i_oc, q);
}

// 初始化随机种子，这样randBigInt()每次生成的随机数都不相同
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


/**
 * 双线性映射
 * @param alpha1 G1上的元素
 * @param alpha2 G2上的元素
 * @return 返回双线性映射的结果GT上的元素
 */
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

// 控制台查看ItemDm
void showItem(itemDM item) {
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
    ECP2_output(&dm.P_pub);
    cout << "--------- [DM.ACC]:" << endl;
    ECP_output(&dm.ACC);
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

// 控制台查看SD
void showSD(SD sd) {
    cout
            << "------------------------------------------------------- showSD ----------------------------------------------------"
            << endl;

    cout << "--------- [SD.id_i]:" << endl;
    BIG_output(sd.id_i);
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

/**
 * 更新设备的证据,未被撤销的智能设备可以使用这个函数更新自己的证据.被撤销的设备使用这个函数无法更新自己的证据
 * @param sd 智能设备
 * @param dm 域管理员
 */
void Update(SD *sd, DM dm) {
    itemDM back = dm.L.back();
    while (BIG_comp(back.id_i,sd->id_i) != 0){
        BIG si;
        hashToZp384(si,back.id_i,dm.q);
        BIG_add(si, si, dm.x);
        if (!back.isJoin) {
            BIG_invmodp(si,si,dm.q);
        }
        ECP_mul(&sd->W_i, si);
        dm.L.pop_back();
        back = dm.L.back();
    }
}


//域管理员的初始化阶段，生成系统参数供其他实体使用
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
void Join_SD_step1(SD *sd,BIG *id_i) {
    randBigInt(id_i);
    BIG_copy(sd->id_i,*id_i);
}

/**
 * 当智能设备想要加入域时，需要先向域管理员注册，该函数为Join过程中DM需要进行的操作
 * @param dm 本域的域管理员
 * @param id_i 待加入智能设备的身份
 * @param x 域管理员DM的私钥
 */
Msg1 Join_DM(DM *dm, BIG id_i, BIG x) {

    itemDM item;
    item.W_i = dm->ACC;
    // 计算群成员证书,更新累加器的值
    BIG s_i, temp;
    ECP C_i;
    hashToZp384(s_i, id_i, dm->q);
    BIG_modadd(temp, s_i, x, dm->q);
    ECP_mul(&dm->ACC, temp);//更新累加器
    BIG_invmodp(temp, temp, dm->q);
    ECP_copy(&C_i, &dm->P_1);//计算群成员证书
    ECP_mul(&C_i, temp);
    // 存储必要的信息用于打开
    BIG_copy(item.id_i, id_i);
    item.si_P = dm->P_2;
    ECP2_mul(&item.si_P, s_i);
    item.isJoin = true;
    dm->L.push_back(item);
//    将消息返回给SD
    Msg1 msg1;
    msg1.C_i = C_i;
    msg1.W_i = item.W_i;
    return msg1;
}

// 接入过程中SD执行的第二阶段，存储证书等信息
void Join_SD_step2(SD *sd, BIG id_i, Msg1 msg1, DM dm) {

    sd->C_i = msg1.C_i;
    sd->W_i = msg1.W_i;
    hashToZp384(sd->s_i, id_i, dm.q);// ------------------------ 阶的问题
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
    ECP_mul(&A1, u);
    ECP_copy(&A2, &sd.C_i);
    ECP_mul(&A2, u);

    BIG ru, rs;
    randBigInt(&ru);
    randBigInt(&rs);
    ECP2 R1, R2, R4;//  求R1,R2,R4
    ECP2_copy(&R1, &dm.P_2);
    ECP2_mul(&R1, ru);
    ECP2_copy(&R2, &T1);
    ECP2_mul(&R2, ru);
    ECP2 ru_P_pub;
    ECP2_copy(&ru_P_pub, &dm.P_pub);
    ECP2_mul(&ru_P_pub, ru);
    ECP2_copy(&R4, &dm.P_2);
    ECP2_mul(&R4, rs);
    ECP2_add(&R4, &ru_P_pub);

    // 求R3
    FP12 t1, t2;
    FP12 R3, m2;
    ECP A1pA2;
    ECP_copy(&A1pA2, &A1);
    ECP_add(&A1pA2, &A2);
    t1 = e(A1pA2, dm.P_pub);
    FP12_pow(&R3, &t1, ru);
    FP12_reduce(&R3);

    t2 = e(A1pA2, T1);
    FP12_pow(&m2, &t2, rs);
    FP12_reduce(&m2);
    FP12_mul(&R3, &m2);
    FP12_reduce(&R3);

    // 计算挑战c
    BIG c;
    char str1[384], str2[384];
    octet oc1, oc2;
    oc1.val = str1;
    oc1.max = 97;
    oc2.val = str2;
    oc2.max = 97;
    // 将哈希函数中的变量全部转化为字符进行异或
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
    BIG_toBytes(oc2.val,R3.a.a.a.g);
    OCT_xor(&oc1, &oc2);

    hashtoZp384(c, &oc1, dm.q);

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

/**
 * 域管理员DM验证消息
 * @param msg2 智能设备生成的签名
 * @return 签名验证通过则返回true，否则返回false
 */
bool Verify(Msg2 msg2, DM dm) {

    ECP2 T1, T2, T3;
    T1 = msg2.T1;
    T2 = msg2.T2;
    T3 = msg2.T3;

    //  求R1_hat,R2_hat
    ECP2 R1_hat, R2_hat;
    ECP2_copy(&R1_hat, &dm.P_2);
    ECP2_mul(&R1_hat, msg2.su);
    ECP2_mul(&T1, msg2.c);
    ECP2_sub(&R1_hat, &T1);

    ECP2_copy(&R2_hat, &msg2.T1);
    ECP2_mul(&R2_hat, msg2.su);
    ECP2_mul(&T2, msg2.c);
    ECP2_sub(&R2_hat, &T2);
    //  求R3_hat
    T1 = msg2.T1;
    T2 = msg2.T2;// 求R1和R2的时候对T1和T2进行了修改，因此重新初始化
    ECP A1, A2;
    A1 = msg2.A_1;
    A2 = msg2.A_2;//

    FP12 t1, t2, t3;
    FP12 R3_hat, m2, m3;
    ECP A1pA2;
    ECP_copy(&A1pA2, &A1);
    ECP_add(&A1pA2, &A2);

    t1 = e(A1pA2, dm.P_pub);
    FP12_pow(&R3_hat, &t1, msg2.su);
    FP12_reduce(&R3_hat);

    t2 = e(A1pA2, T1);
    FP12_pow(&m2, &t2, msg2.ss);
    FP12_reduce(&m2);

    ECP ACCpP1;
    ECP_copy(&ACCpP1, &dm.ACC);
    ECP_add(&ACCpP1, &dm.P_1);
    t3 = e(ACCpP1, T2);
    FP12_pow(&m3, &t3, msg2.c);
    FP12_reduce(&m3);
    FP12_inv(&m3, &m3);
    FP12_reduce(&m3);
    FP12_mul(&R3_hat, &m2);
    FP12_reduce(&R3_hat);
    FP12_mul(&R3_hat, &m3);
    FP12_reduce(&R3_hat);

    //  求R4
    ECP2 R4_hat, P_pub;
    ECP2_copy(&R4_hat, &dm.P_2);
    ECP2_mul(&R4_hat, msg2.ss);
    ECP2_copy(&P_pub, &dm.P_pub);
    ECP2_mul(&P_pub, msg2.su);
    ECP2_mul(&T3, msg2.c);
    ECP2_add(&R4_hat, &P_pub);
    ECP2_sub(&R4_hat, &T3);

    // 求哈希得到c_hat
    char str1[384], str2[384];
    octet oc1, oc2;
    oc1.val = str1;
    oc1.max = 97;
    oc2.val = str2;
    oc2.max = 97;

    // 将哈希函数中的变量全部转化为字符进行异或
    ECP2_toOctet(&oc1, &msg2.T1, true);
    ECP2_toOctet(&oc2, &msg2.T2, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &msg2.T3, true);
    OCT_xor(&oc1, &oc2);
    ECP_toOctet(&oc2, &msg2.A_1, true);
    OCT_xor(&oc1, &oc2);
    ECP_toOctet(&oc2, &msg2.A_2, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R1_hat, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R2_hat, true);
    OCT_xor(&oc1, &oc2);
    ECP2_toOctet(&oc2, &R4_hat, true);
    OCT_xor(&oc1, &oc2);
    BIG_toBytes(oc2.val,R3_hat.a.a.a.g);
    OCT_xor(&oc1, &oc2);

    BIG c_hat;
    hashtoZp384(c_hat, &oc1, dm.q);

    return BIG_comp(c_hat, msg2.c) == 0 ? true : false;
}


/**
 * 返回一个身份所在的itemDM【事实上只需要返回一个idi即可，但是由于id_i是一个数组，不能返回，这里简单的直接返回itemDM】
 * @param msg2 某智能设备的签名
 * @param dm  域管理员
 * @return 恶意设备的真实身份 id_i
 */
itemDM Open(Msg2 msg2, DM dm) {
    itemDM item;
    if (Verify(msg2, dm)) {
        ECP2_mul(&msg2.T1, dm.x);
        ECP2_sub(&msg2.T3, &msg2.T1);
        for (int i = 0; i < dm.L.size(); ++i) {
            if (ECP2_equals(&msg2.T3, &dm.L[i].si_P)) {
                return dm.L[i];
            }
        }
    }

    return item;
}

/**
 * 撤销非法用户
 * @param item 非法设备的信息
 * @param dm 域管理员
 */
void Revoke(itemDM item, DM *dm) {
//    根据item做以下操作
    BIG s_i;
    hashToZp384(s_i, item.id_i, dm->q);
    BIG_add(s_i, s_i, dm->x);
    BIG_invmodp(s_i, s_i, dm->q);
    ECP_mul(&dm->ACC, s_i);
    itemDM newItem;
    BIG_copy(newItem.id_i, item.id_i);
    newItem.si_P = item.si_P;
    newItem.isJoin = false;
    newItem.W_i = dm->ACC;
    dm->L.push_back(newItem);
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
    hashToZp384(res, beHashed, order);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, beHashed, order);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, test, order);
    BIG_output(res);
    cout << endl;
    hashToZp384(res, test, order);
    BIG_output(res);
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

    char str[384];
    octet oc;
    oc.val = str;
    oc.max = 384;

    char str2[384];
    octet oc2;
    oc2.val = str2;
    oc.max = 384;
    ECP_toOctet(&oc, &R, true);
    //    cout << "R_oc:" <<  endl;
    //    OCT_output(&oc);
    //    cout << oc.len << endl;
    ECP_toOctet(&oc2, &PK, true);
    //    cout<< "PK_oc:"  << endl;
    //    OCT_output(&oc2);
    //    cout << oc2.len << endl;
    //    cout << endl;
    OCT_xor(&oc, &oc2);
    cout << "-------------------------- xor ----------------------------------" << endl;
    OCT_output(&oc);
    cout << oc.len << endl;

    FP12 fp12;
    ECP2 ecp2;
    ECP2_generator(&ecp2);
    ECP2_mul(&ecp2, r);
    fp12 = e(R, ecp2);
    char sss[384];
    BIG_toBytes(sss, fp12.a.a.a.g);
    oc2.val = sss;
    //    cout << "-------------------------- fp12 ----------------------------------" << endl;
    //    OCT_output(&oc2);
    //    cout << oc2.len << endl;
    OCT_xor(&oc, &oc2);

    BIG c;
    hashtoZp384(c, &oc, order);

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


// 双线性映射的性质没有问题，亲爱的张老师帮我完成了R3的恢复问题
void testPair() {
    BIG order;
    BIG_rcopy(order, CURVE_Order);

    ECP P1;
    ECP_generator(&P1);
    ECP2 P2;
    ECP2_generator(&P2);

    BIG sk;
    randBigInt(&sk);
    ECP2 PK;
    ECP2_copy(&PK, &P2);
    ECP2_mul(&PK, sk);

    BIG r;
    randBigInt(&r);
    ECP W_i;
    ECP_copy(&W_i, &P1);
    ECP_mul(&W_i, r);

    BIG si;
    randBigInt(&si);
    BIG si_Add_x;
    BIG_modadd(si_Add_x, si, sk, order);
    ECP ACC;
    ECP_copy(&ACC, &W_i);
    ECP_mul(&ACC, si_Add_x);

    ECP C_i;
    BIG si_Add_x_inv;
    BIG_invmodp(si_Add_x_inv, si_Add_x, order);
    ECP_copy(&C_i, &P1);
    ECP_mul(&C_i, si_Add_x_inv);

    BIG u;
    randBigInt(&u);
    ECP A1, A2;
    ECP_copy(&A1, &W_i);
    ECP_mul(&A1, u);
    ECP_copy(&A2, &C_i);
    ECP_mul(&A2, u);

    ECP2 T1, T2;
    ECP2_copy(&T1, &P2);
    ECP2_mul(&T1, u);
    ECP2_copy(&T2, &T1);
    ECP2_mul(&T2, u);

    // 求R3
    BIG ru, rs;
    randBigInt(&ru);
    randBigInt(&rs);
    FP12 t11, t22;
    FP12 R3, m22;
    ECP A1pA2;
    ECP_copy(&A1pA2, &A1);
    ECP_add(&A1pA2, &A2);
    t11 = e(A1pA2, PK);
    FP12_pow(&R3, &t11, ru);
    FP12_reduce(&R3);
    t22 = e(A1pA2, T1);
    FP12_pow(&m22, &t22, rs);
    FP12_reduce(&m22);
    FP12_mul(&R3, &m22);
    FP12_reduce(&R3);

    BIG c;
    randBigInt(&c);
    // 计算 ss 和 su
    BIG su, ss;
    BIG_modmul(su, c, u, order);
    BIG_modadd(su, ru, su, order);
    BIG_mod(su, order);
    BIG_modmul(ss, c, si, order);
    BIG_modadd(ss, rs, ss, order);
    BIG_mod(ss, order);


    cout << endl << endl;
    cout << "-----------A1:" << endl;
    ECP_output(&A1);
    cout << "-----------A2:" << endl;
    ECP_output(&A2);
    cout << "-----------W_i:" << endl;
    ECP_output(&W_i);
    cout << "-----------C_i:" << endl;
    ECP_output(&C_i);
    cout << "-----------ACC:" << endl;
    ECP_output(&ACC);
    cout << "-----------ACC =? siAddx * W_i:" << endl;
    ECP test;
    ECP_copy(&test, &W_i);
    ECP_mul(&test, si_Add_x);
    ECP_output(&test);
    cout << "-----------T1:" << endl;
    ECP2_output(&T1);
    cout << "-----------T2:" << endl;
    ECP2_output(&T2);
    cout << "-----------PK:" << endl;
    ECP2_output(&PK);
    cout << "-----------ru:" << endl;
    BIG_output(ru);
    cout << endl << "-----------rs:" << endl;
    BIG_output(rs);
    cout << endl << "-----------c:" << endl;
    BIG_output(c);
    cout << endl << "-----------R3:" << endl;
    FP12_output(&R3);//-------------------------------------------------
    cout << endl << endl;

    //    ------------------------------------------------------------- 验证---------------------------------------
    FP12 t1, t2, t3;
    FP12 R3_hat, m2, m3;
    t1 = e(A1pA2, PK);
    FP12_pow(&R3_hat, &t1, su);
    FP12_reduce(&R3_hat);
    t2 = e(A1pA2, T1);
    FP12_pow(&m2, &t2, ss);
    FP12_reduce(&m2);

    ECP ACCpP1;
    ECP_copy(&ACCpP1, &ACC);
    ECP_add(&ACCpP1, &P1);
    t3 = e(ACCpP1, T2);
    FP12_pow(&m3, &t3, c);
    FP12_reduce(&m3);
    FP12_inv(&m3, &m3);
    FP12_reduce(&m3);

    FP12_mul(&R3_hat, &m2);
    FP12_reduce(&R3_hat);
    FP12_mul(&R3_hat, &m3);
    FP12_reduce(&R3_hat);

    cout << endl << endl;
    cout << "-----------A1:" << endl;
    ECP_output(&A1);
    cout << "-----------A2:" << endl;
    ECP_output(&A2);
    cout << "-----------W_i:" << endl;
    ECP_output(&W_i);
    cout << "-----------C_i:" << endl;
    ECP_output(&C_i);
    cout << "-----------ACC:" << endl;
    ECP_output(&ACC);
    cout << "-----------T1:" << endl;
    ECP2_output(&T1);
    cout << "-----------T2:" << endl;
    ECP2_output(&T2);
    cout << "-----------PK:" << endl;
    ECP2_output(&PK);
    cout << "-----------ru:" << endl;
    BIG_output(ru);
    cout << endl << "-----------rs:" << endl;
    BIG_output(rs);
    cout << endl << "-----------c:" << endl;
    BIG_output(c);
    cout << endl << "-----------R3:" << endl;
    FP12_output(&R3);//-------------------------------------------------
    cout << endl << "-----------R3_hat:" << endl;
    FP12_output(&R3_hat);//-------------------------------------------------
    cout << endl << endl;
}


DM DM1;
SD SD1[3];

void testMyScheme() {
    // 1. 准备工作
    initRNG(&rng1);
    BIG_rcopy(order, CURVE_Order);
    // 2. 初始化阶段
    Setup(&DM1);
    // 3. SD加入群组[模拟三个人加入]
    for (int i = 0; i < 3; ++i) {
        BIG id_i;
        Join_SD_step1(&SD1[i],&id_i);
        Msg1 msg1 = Join_DM(&DM1, id_i, DM1.x);
        Join_SD_step2(&SD1[i], id_i, msg1,DM1);
    }
    // 4. 智能设备 SD[2] 进行签名
    Msg2 msg2 = Sign(SD1[2], DM1);
    // 5. 域管理员验证
    cout << (Verify(msg2, DM1) ? "verify success" : "verify defeat") << endl;
    // 6. 假设SD[2]是恶意设备，首先通过其签名msg2揭露他的真实身份。
    itemDM item = Open(msg2,DM1);
    // 7. 根据真实身份撤销这个智能设备
    Revoke(item,&DM1);
    // 8. 撤销后假设智能设备SD[1]想要进行认证
    Update(&SD1[1],DM1);
    Msg2 msg22 = Sign(SD1[1], DM1);
    cout << (Verify(msg22, DM1) ? "verify success" : "verify defeat") << endl;
}

int main() {
    struct timeval startTime;
    struct timeval endTime;
    gettimeofday(&startTime, NULL);
    initRNG(&rng1);
    testMyScheme();
    gettimeofday(&endTime, NULL);
    cout << endTime.tv_usec - startTime.tv_usec << endl;
    return 0;
}


