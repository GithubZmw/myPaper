//
// Created by Miracle on 2023/11/20.
//

#include "test.h"
#include "common.h"
#include "iostream"
#include "map"


using namespace std;



template<typename T>
void PrintValue(T *arr, int len) {
    for (int i = 0; i < len; i++) {
        cout << arr[i] << ",";
    }
    cout << endl;
}


void test_rcopy() {
    BIG a;
    BIG_rcopy(a, CURVE_Order);
    cout << a;
}


void hashToZp384(char *h, char *res) {
    hash384 sh384;
    int i;
    HASH384_init(&sh384);
    for (i = 0; h[i] != 0; i++) HASH384_process(&sh384, h[i]);
    HASH384_hash(&sh384, res);
    for (i = 0; i < 48; i++) printf("%02x", (unsigned char) res[i]);
    printf("\n");
}


void testHash() {
    BIG num;
    char test256[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    char digest[100];
    int i;
    hash256 sh256;
    HASH256_init(&sh256);
    for (i = 0; test256[i] != 0; i++) HASH256_process(&sh256, test256[i]);
    HASH256_hash(&sh256, digest);
    for (i = 0; i < 32; i++) printf("%02x", (unsigned char) digest[i]);
    printf("\n");

    BIG_fromBytesLen(num, digest, 56);
    BIG_output(num);
    cout << endl;

    hash384 sh384;
    char test512[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    HASH384_init(&sh384);
    for (i = 0; test512[i] != 0; i++) HASH384_process(&sh384, test512[i]);
    HASH384_hash(&sh384, digest);
    for (i = 0; i < 48; i++) printf("%02x", (unsigned char) digest[i]);
    printf("\n");

    BIG_fromBytesLen(num, digest, 100);
    BIG_output(num);
    cout << endl;

    cout << "--------------------------------- test ---------------------------------" << endl;
    char *res;
    hashToZp384(test512, res);
    hashToZp384(test512, res);
    hashToZp384(test512, res);
    hashToZp384(test512, res);
}


void testBIG_fromBytesLen() {
    BIG x;
    char modx[] = "10000";
    BIG_fromBytesLen(x, modx, 5);


    BIG num;
    char hashstr[] = "123";
    PrintValue(hashstr, sizeof hashstr);
    //将hashstr中的每个字节的ASCII值转化为16进制后存储为num，例如：2的ASCII为50，转化为十六进制为32
    BIG_fromBytesLen(num, hashstr, 3);
//    BIG_fromBytes(num, hashstr);

    BIG_output(num);
    cout << endl;
    BIG mod;
    char modstr[] = "100";
    BIG_fromBytesLen(mod, modstr, 3);
    BIG_mod(num, mod);
    BIG_output(num);
    cout << endl;
    BIG_add(x, num, num);
    BIG_output(x);
    cout << endl;
}


void testToOctet() {
    ECP2 ecp2;
    ECP2_generator(&ecp2);
    ECP2_output(&ecp2);
    cout << endl;

    char str[24];
    octet oc;
    oc.val = str;
    ECP2_toOctet(&oc, &ecp2, true);
    BIG x;
    BIG_fromBytesLen(x, oc.val, oc.max);
    BIG_output(x);
    cout << endl;
    cout << endl;

    ECP2_fromOctet(&ecp2, &oc);
    ECP2_output(&ecp2);
}



void testMap() {
    map<int, int> Ta;
    Ta[0] = 5;

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

    BIG c_hat;
    hashtoZp384(c_hat, &oc1, ord);
    BIG_output(c_hat);

}




/**
 * 测试ECP使用等于号直接赋值，而不使用它的copy方法赋值
 * 使用等号赋值在我的方案里面没有影响
 */
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

// 测试求求逆的函数，这里的魔术必须是素数，使用的是扩展的欧几里得算法求逆
void test_inv() {
    cout << "------------------------- test B384_58 -------------------------" << endl;
    BIG a, b, n;
    randBigInt(&a);
    randBigInt(&b);
    randBigInt(&n);

    BIG_output(b);
    cout << endl;
    BIG_invmodp(b, a, n);
    BIG_output(b);
    cout << endl;
    BIG_invmodp(b, a, n);
    BIG_output(b);
    cout << endl;
}





//int main() {
//    testHash();
//}