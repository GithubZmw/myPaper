//
// Created by Miracle on 2023/11/20.
//

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


void test_hashtoZp384() {
    octet oc;
    char test[] = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    cout << test << endl;
    for (int i = 0; i < 3; ++i) {
        BIG res;
        BIG_fromBytesLen(res, "12345", 5);
        cout
                << "------------------------------------------------------------------ 1 ------------------------------------------------------------------"
                << endl;
        oc.len = 112;
        oc.max = 128;
        oc.val = test;
        BIG_output(res);
        cout << endl;
        hashtoZp384(res, &oc);
        BIG_output(res);
        cout << endl;
    }
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





//int main() {
////    test_hashtoZp384();
//    testHash();
//}