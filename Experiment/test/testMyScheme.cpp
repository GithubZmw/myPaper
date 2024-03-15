//
// Created by Miracle on 2023/12/13.
//

#include "MyScheme.h"
#include "iostream"

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

// 测试哈希函数是否正确
void test_hashToZp() {
    cout << "----------------------------------------------------- test_hashToZp -----------------------------------------------------"
         << endl;
    BIG order;
    BIG_rcopy(order,CURVE_Order);
    BIG beHashed, test;
    randBigInt(&beHashed);
    BIG_rcopy(test, CURVE_Order);
    BIG_output(beHashed);
    cout << endl;
    BIG_output(test);
    cout << endl;

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
    cout << "----------------------------------------------------- test_hashToZp ---------------------------------------------------"
         << endl;
}

/**
 * 注意：
 * 需要su和ss的计算后面需要mod q  【还要注意同余性质的应用】
 * 将ECP上的点转换后异或操作，从而达到异或多个点的目的
 */
void testSchnoor() {
    cout << "------------------------------------------------------ testSchnoor -----------------------------------------------------"
         << endl;
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
    cout << "----------------------------------------------------- testSchnoor ------------------------------------------------------"
         << endl;
}

//int main(){
//    test_hashToZp();
//    testSchnoor();
//    testPair();
//    return 0;
//}