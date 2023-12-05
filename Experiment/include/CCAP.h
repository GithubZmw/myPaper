//
// Created by Miracle on 2023/11/30.
//

#include <map>
#include <array>
#include "common.h"
#include "iostream"
#include "ecdh_NIST256.h"

using namespace NIST256;
using namespace BLS12383;
using namespace B384_58;

//#include <ff_RSA2048.h>

csprng rng_CCAP;

char s1[EGS_NIST256], w1[2 * EFS_NIST256 + 1];
octet SK_base = {0, sizeof(s1), s1};
octet PK_base = {0, sizeof(w1), w1};

char s_diA[EGS_NIST256], w_diA[2 * EFS_NIST256 + 1];
char s_pasA[EGS_NIST256], w_pasA[2 * EFS_NIST256 + 1];
char s_pasB[EGS_NIST256], w_pasB[2 * EFS_NIST256 + 1];



char ds[EGS_NIST256], cs[EGS_NIST256];

typedef struct {
    octet sk = {0, sizeof(s_diA), s_diA};
    octet pk = {0, sizeof(w_diA), w_diA};
}di_A;

typedef struct {
    octet sk  = {0, sizeof(s_pasA), s_pasA};
    octet pk  = {0, sizeof(w_pasA), w_pasA};
}PAS_A;

typedef struct {
    octet sk = {0, sizeof(s_pasB), s_pasB};
    octet pk = {0, sizeof(w_pasB), w_pasB};
}PAS_B;

typedef struct {

}VS;


typedef struct {
    BIG ID_A;
    bool flag;
    BIG vskB;
    BLS12383::ECP2 vpkB;
    BLS12383::ECP Lics;
    BLS12383::ECP blk;
}Msg;



typedef struct {
    BIG p_widetilde;
    BIG p,q,p_prime,q_prime;
    BLS12383::ECP g1,h1,g;
    BLS12383::ECP2 g2;
    BIG tau;
    BIG n;
}Params;




typedef struct C{
    octet CS = {0, sizeof(cs), cs};
    octet DS = {0, sizeof(ds), ds};
    // 重载 < 操作符
    bool operator<(const C& other) const {
        // 这里假设 octet 中的 val 是 char 数组
        return memcmp(this->CS.val, other.CS.val, min(this->CS.len, other.CS.len)) < 0;
    }
}Cert;


map<Cert,BIG> BlackList;


typedef struct {
    Cert certA;
    Cert signA;
}Msg1;





typedef struct {
    octet information;
    Cert cert;
}Info;

typedef struct {
    int crossLicensing;
    BIG ID_A;
    Cert certA;
    Info infoA;
    octet pkA;
    Cert signB;
}Msg2;


typedef struct {
    BLS12383::ECP A, A_d;
    BLS12383::ECP B1, B2, B3, B4, C, a, Lics;
    BLS12383::ECP u, v, w;
    BLS12383::ECP g11, g12, g13;
    BLS12383::ECP pk1, pk2, pk3;
    BLS12383::ECP2 vpkB;
    BIG d, sk1, sk2, sk3, vskB,h_uw;
    BIG r, ID_A;//
    BIG gamma, epsilon, theta1, theta2, theta3, theta4, beta1, beta2, beta3, beta4;//
    BIG r_d, epsilon_d, sigma_d, gamma_d, d_d, theta1_d, theta2_d, theta3_d, theta4_d, beta1_d, beta2_d, beta3_d, beta4_d;//
    BIG ch;//
    BIG r_dd, epsilon_dd, sigma_dd, gamma_dd, d_dd, theta1_dd, theta2_dd, theta3_dd, theta4_dd, beta1_dd, beta2_dd, beta3_dd, beta4_dd;//
    BIG r_d_2, sigma_d_2, r_dd_2, ch_2, sigma_dd_2;
} Args;

typedef struct {

}Msg3;

typedef struct {
    BIG big;
} mp;

void Setup();