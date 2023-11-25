// BLS12-383曲线参考：https://blog.csdn.net/u011680118/article/details/119910411

#include <iostream>
#include "common.h"

#define CT_OFFSET 100

static char message[] = "This is a test message";

BIG msk;
BIG order;// BLS12383曲线的阶
csprng rng;//随机数发生器
ECP UJ;

//int main() {
//
//    // 声明并初始化随机数发生器
//    initRNG(&rng);
////    testForNIST256();
//    testForBLS12381WithPairing();
//    // 测试结束
//
//    return 1;
//}

/**
 * 测试NIST256曲线的
 */
void testForNIST256() {

    cout << "------------------- testForNIST256-start ---------------------" << endl;
    ECP alpha;
    ECP_generator(&alpha);
    long totalTime = 0;
    int repeatedCount = 1000;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        gettimeofday(&startTime, NULL);
        ECP_mul(&alpha, s);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&alpha)) {
            i--;
            printf("ECC SM error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("ECC SM time:%ld us\n", totalTime / repeatedCount);
    // 测试椭圆曲线的加法操作
    ECP beta;
    ECP_generator(&beta);
    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        ECP_mul(&alpha, s);
        randBigInt(&s);
        ECP_mul(&beta, s);
        gettimeofday(&startTime, NULL);
        ECP_add(&alpha, &beta);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&alpha)) {
            i--;
            printf("ECC ADD error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("ECC ADD time:%ld/1000 us\n", totalTime);
    cout << "------------------- testForNIST256-end\t ---------------------" << endl;

}

/**
 * 测试双线性配对的时间
 */
void testForBLS12381WithPairing() {
//    -------------------------------------------------------- G_1群的测试 -------------------------------------------------------
    cout << "------------------- testForBLS12381WithPairing-start\t ---------------------" << endl;
    BIG_rcopy(order, CURVE_Order);

    ECP alpha;
    ECP_generator(&alpha);
    long totalTime = 0;
    int repeatedCount = 1000;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        gettimeofday(&startTime, NULL);
        ECP_mul(&alpha, s);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&alpha)) {
            i--;
            printf("G1 SM error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G1 SM time:%ld us\n", totalTime / repeatedCount);

    ECP beta;
    ECP_generator(&beta);
    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        ECP_mul(&alpha, s);
        randBigInt(&s);
        ECP_mul(&beta, s);
        gettimeofday(&startTime, NULL);
        ECP_add(&alpha, &beta);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&alpha)) {
            i--;
            printf("G1 ADD error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G1 ADD time:%ld/1000 us\n", totalTime / repeatedCount);
    cout << endl;
//    -------------------------------------------------------- G_2群的测试 -------------------------------------------------------


    ECP2 alpha2;
    ECP2_generator(&alpha2);
    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        gettimeofday(&startTime, NULL);
        ECP2_mul(&alpha2, s);
        gettimeofday(&endTime, NULL);
        if (ECP2_isinf(&alpha2)) {
            i--;
            printf("G2 SM error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G2 SM time:%ld us\n", totalTime / repeatedCount);

    ECP2 beta2;
    ECP2_generator(&beta2);
    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        struct timeval startTime;
        struct timeval endTime;
        ECP2_mul(&alpha2, s);
        randBigInt(&s);
        ECP2_mul(&beta2, s);
        gettimeofday(&startTime, NULL);
        ECP2_add(&alpha2, &beta2);
        gettimeofday(&endTime, NULL);
        if (ECP2_isinf(&alpha2)) {
            i--;
            printf("G2 ADD error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G2 ADD time:%ld/1000 us\n", totalTime / repeatedCount);
    cout << endl;

//    -------------------------------------------------------- 测试双线性配对 -------------------------------------------------------

    FP12 temp1;
    FP12 temp2;

    long pairTotalTime = 0;
    long fp12MULTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        BIG s;
        randBigInt(&s);
        ECP_mul(&alpha, s);
        randBigInt(&s);
        ECP2_mul(&alpha2, s);

        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        PAIR_ate(&temp1, &alpha2, &alpha);
        PAIR_fexp(&temp1);
        FP12_reduce(&temp1);
        gettimeofday(&endTime, NULL);
        if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
            printf("pairing error [temp1]\n");
        }
        pairTotalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

        // ---------------------------------------------- 测试G_T上乘法的耗时 ----------------------------------------
        randBigInt(&s);
        ECP_mul(&alpha, s);
        randBigInt(&s);
        ECP2_mul(&alpha2, s);
        PAIR_ate(&temp2, &alpha2, &alpha);
        PAIR_fexp(&temp2);
        FP12_reduce(&temp2);
        if (FP12_isunity(&temp2) || FP12_iszilch(&temp2)) {
            printf("pairing error [temp2]\n");
        }


        gettimeofday(&startTime, NULL);
        FP12_mul(&temp1, &temp2);
        FP12_reduce(&temp1);
        gettimeofday(&endTime, NULL);
        if (FP12_isunity(&temp1) || FP12_iszilch(&temp1)) {
            printf("pairing error [mul]\n");
        }
        fp12MULTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
    }
    printf("PAIR time:%ld\n", pairTotalTime / repeatedCount);
    printf("GT MUL time:%ld\n", fp12MULTime / repeatedCount);
    cout << endl;

    // ---------------------------------------------- 测试映射到椭圆曲线点上的哈希的耗时 ----------------------------------------
    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        FP fp;
        FP_rand(&fp, &rng);
        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        ECP_map2point(&alpha, &fp);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&alpha)) {
            i--;
            printf("G1 map2point error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G1 map2point time:%ld\n", totalTime / repeatedCount);


    totalTime = 0;
    for (int i = 0; i < repeatedCount; i++) {
        FP2 fp;
        FP2_rand(&fp, &rng);
        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        ECP2_map2point(&alpha2, &fp);
        gettimeofday(&endTime, NULL);
        if (ECP2_isinf(&alpha2)) {
            i--;
            printf("G2 map2point error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    printf("G2 map2point time:%ld\n", totalTime / repeatedCount);


    int creLength = BASEBITS_B384_58 * 3;
    totalTime = 0;
    octet idOct;
    idOct.val = (char *) malloc(creLength);
    idOct.max = creLength;
    idOct.len = creLength;
    for (int i = 0; i < repeatedCount; i++) {

        for (int j = 0; j < creLength; j++) {
            idOct.val[j] = RAND_byte(&rng);
        }
        char temp[48];
        ECP point;
        FP fp;
        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        hashtoStr384(temp, &idOct);
        FP_fromBytes(&fp, temp);
        ECP_map2point(&point, &fp);
        gettimeofday(&endTime, NULL);
        if (ECP_isinf(&point)) {
            i--;
            printf("G1 hash error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }
    }
    free(idOct.val);
    printf("G1 hash id to point time:%ld\n", totalTime / repeatedCount);

    totalTime = 0;
    idOct.val = (char *) malloc(creLength);
    idOct.max = creLength;
    idOct.len = creLength;
    for (int i = 0; i < repeatedCount; i++) {

        for (int j = 0; j < creLength; j++) {
            idOct.val[j] = RAND_byte(&rng);
        }
        char temp[48 * 2];
        ECP2 point;
        FP2 fp;
        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        hashtoDStr384(temp, &idOct);
        FP2_fromBytes(&fp, temp);
        ECP2_map2point(&point, &fp);
        gettimeofday(&endTime, NULL);
        if (ECP2_isinf(&point)) {
            i--;
            printf("G2 hash error\n");
        } else {
            totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);
        }

    }
    free(idOct.val);
    printf("G2 hash id to point time:%ld\n", totalTime / repeatedCount);


    totalTime = 0;
    idOct.val = (char *) malloc(creLength);
    idOct.max = creLength;
    idOct.len = creLength;
    for (int i = 0; i < repeatedCount; i++) {

        for (int j = 0; j < creLength; j++) {
            idOct.val[j] = RAND_byte(&rng);
        }
        char temp[48];

        struct timeval startTime;
        struct timeval endTime;

        gettimeofday(&startTime, NULL);
        hashtoStr384(temp, &idOct);
        gettimeofday(&endTime, NULL);

        totalTime += (endTime.tv_sec - startTime.tv_sec) * 1000000 + (endTime.tv_usec - startTime.tv_usec);

    }
    free(idOct.val);
    printf("hash time:%ld\n", totalTime / repeatedCount);


    cout << "------------------- testForBLS12381WithPairing-end\t ---------------------" << endl;

}



void hashtoStr384(char *str, octet *ct) {
    hash384 h;
    memset(str, 0, 48);
    HASH384_init(&h);
    for (int j = 0; j < ct->max; j++) {
        HASH384_process(&h, ct->val[j]);
    }
    HASH384_hash(&h, str);
}

void hashtoDStr384(char *str, octet *ct) {
    hash384 h;
    memset(str, 0, 48 * 2);
    HASH384_init(&h);
    for (int j = 0; j < ct->max; j++) {
        HASH384_process(&h, ct->val[j]);
    }
    HASH384_hash(&h, str);
    //HASH384_init(&h);
    for (int j = 0; j < 48; j++) {
        HASH384_process(&h, str[j]);
    }
    HASH384_hash(&h, str + 48);
}

void hashtoZp256(BIG num, octet *ct) {
    hash256 h;
    char hashstr[32];
    memset(hashstr, 0, 32);
    HASH256_init(&h);
    //printf("start caculate hash...\n");

    for (int j = 0; j < ct->max; j++) {
        HASH256_process(&h, ct->val[j]);
        //printf("%x", temp[j]);
    }
    //printf("\n");

    HASH256_hash(&h, hashstr);

    BIG_fromBytesLen(num, hashstr, 32);
    BIG_mod(num, order);

    // printHexString("\nhash: ", hashstr, 32);
    // printf("\nhashbig=0x");
    // BIG_output(num);
    // printf("\n");
}


//void initRNG(core::csprng *rng) {
//    char raw[100];
//    octet RAW = {0, sizeof(raw), raw};
//    unsigned long ran;
//    time((time_t *) &ran);
//
//    RAW.len = 100; // fake random seed source
//    RAW.val[0] = ran;
//    RAW.val[1] = ran >> 8;
//    RAW.val[2] = ran >> 16;
//    RAW.val[3] = ran >> 24;
//    for (int i = 4; i < 100; i++)
//        RAW.val[i] = i;
//
//    CREATE_CSPRNG(rng, &RAW);
//}

