/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* test driver and function exerciser for ECDH/ECIES/ECDSA API Functions */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ecdh_Ed25519.h"
#include "rsa_RSA2048.h"
#include "randapi.h"

#if CHUNK==32 || CHUNK==64
#include "ecdh_NIST256.h"
#include "ecdh_Ed448.h"
#endif

using namespace core;

int ecdh_Ed25519(csprng *RNG)
{
    using namespace Ed25519;

    int i, res;
    unsigned long ran;
    char *pp = (char *)"M0ng00se";
    // These octets are automatically protected against buffer overflow attacks
    // Note salt must be big enough to include an appended word
    // Note ECIES ciphertext C must be big enough to include at least 1 appended block
    // Recall EFS_Ed25519 is field size in bytes. So EFS_Ed25519=32 for 256-bit curve
    char s0[2 * EGS_Ed25519], s1[EGS_Ed25519], w0[2 * EFS_Ed25519 + 1], w1[2 * EFS_Ed25519 + 1], z0[EFS_Ed25519], z1[EFS_Ed25519], key[AESKEY_Ed25519], salt[40], pw[40];
    octet S0 = {0, sizeof(s0), s0};
    octet S1 = {0, sizeof(s1), s1};
    octet W0 = {0, sizeof(w0), w0};
    octet W1 = {0, sizeof(w1), w1};
    octet Z0 = {0, sizeof(z0), z0};
    octet Z1 = {0, sizeof(z1), z1};
    octet KEY = {0, sizeof(key), key};
    octet SALT = {0, sizeof(salt), salt};
    octet PW = {0, sizeof(pw), pw};

    SALT.len = 8;
    for (i = 0; i < 8; i++) SALT.val[i] = i + 1; // set Salt

    printf("Alice's Passphrase= %s\n", pp);

    OCT_empty(&PW);
    OCT_jstring(&PW, pp);  // set Password from string

    // private key S0 of size EGS_Ed25519 bytes derived from Password and Salt

    PBKDF2(MC_SHA2,HASH_TYPE_Ed25519, &S0, EGS_Ed25519, &PW, &SALT, 1000);

    printf("Alices private key= 0x");
    OCT_output(&S0);

    // Generate Key pair S/W

    ECP_KEY_PAIR_GENERATE(NULL, &S0, &W0);
    printf("Alices public key= 0x");
    OCT_output(&W0);

    res = ECP_PUBLIC_KEY_VALIDATE(&W0);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }

    // Random private key for other party
    ECP_KEY_PAIR_GENERATE(RNG, &S1, &W1);
    res = ECP_PUBLIC_KEY_VALIDATE(&W1);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }
    printf("Servers private key= 0x");
    OCT_output(&S1);
    printf("Servers public key= 0x");
    OCT_output(&W1);

    // Calculate common key using DH - IEEE 1363 method

    ECP_SVDP_DH(&S0, &W1, &Z0, 0);
    ECP_SVDP_DH(&S1, &W0, &Z1, 0);

    if (!OCT_comp(&Z0, &Z1))
    {
        printf("*** ECPSVDP-DH Failed\n");
        return 0;
    }

    KDF2(MC_SHA2, HASH_TYPE_Ed25519, &KEY, AESKEY_Ed25519, &Z0, NULL);

    printf("Alice's DH Key=  0x");
    OCT_output(&KEY);
    printf("Servers DH Key=  0x");
    OCT_output(&KEY);

#if CURVETYPE_Ed25519 != MONTGOMERY

    char ds[EGS_Ed25519], p1[30], p2[30], v[2 * EFS_Ed25519 + 1], m[32], c[64], t[32], cs[EGS_Ed25519];
    octet DS = {0, sizeof(ds), ds};
    octet CS = {0, sizeof(cs), cs};
    octet P1 = {0, sizeof(p1), p1};
    octet P2 = {0, sizeof(p2), p2};
    octet V = {0, sizeof(v), v};
    octet M = {0, sizeof(m), m};
    octet C = {0, sizeof(c), c};
    octet T = {0, sizeof(t), t};

    printf("Testing ECIES\n");

    P1.len = 3;
    P1.val[0] = 0x0;
    P1.val[1] = 0x1;
    P1.val[2] = 0x2;
    P2.len = 4;
    P2.val[0] = 0x0;
    P2.val[1] = 0x1;
    P2.val[2] = 0x2;
    P2.val[3] = 0x3;

    M.len = 17;
    for (i = 0; i <= 16; i++) M.val[i] = i;

    ECP_ECIES_ENCRYPT(HASH_TYPE_Ed25519, &P1, &P2, RNG, &W1, &M, 12, &V, &C, &T);

    printf("Ciphertext= \n");
    printf("V= 0x");
    OCT_output(&V);
    printf("C= 0x");
    OCT_output(&C);
    printf("T= 0x");
    OCT_output(&T);

    if (!ECP_ECIES_DECRYPT(HASH_TYPE_Ed25519, &P1, &P2, &V, &C, &T, &S1, &M))
    {
        printf("*** ECIES Decryption Failed\n");
        return 0;
    }
    else printf("Decryption succeeded\n");

    printf("Message is 0x");
    OCT_output(&M);


    printf("Testing ECDSA\n");

    if (ECP_SP_DSA(HASH_TYPE_Ed25519, RNG, NULL, &S0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Signature Failed\n");
        return 0;
    }

    printf("Signature C = 0x");
    OCT_output(&CS);
    printf("Signature D = 0x");
    OCT_output(&DS);

    if (ECP_VP_DSA(HASH_TYPE_Ed25519, &W0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Verification Failed\n");
        return 0;
    }
    else
    {
        printf("ECDSA Signature/Verification succeeded\n");
    }

#endif

    return 1;
}

#if CHUNK==32 || CHUNK==64
int ecdh_NIST256(csprng *RNG)
{
    using namespace NIST256;

    int i, res;
    unsigned long ran;
    char *pp = (char *)"M0ng00se";
    // These octets are automatically protected against buffer overflow attacks
    // Note salt must be big enough to include an appended word
    // Note ECIES ciphertext C must be big enough to include at least 1 appended block
    // Recall EFS_NIST256 is field size in bytes. So EFS_NIST256=32 for 256-bit curve
    char s0[2 * EGS_NIST256], s1[EGS_NIST256], w0[2 * EFS_NIST256 + 1], w1[2 * EFS_NIST256 + 1], z0[EFS_NIST256], z1[EFS_NIST256], key[AESKEY_NIST256], salt[40], pw[40];
    octet S0 = {0, sizeof(s0), s0};
    octet S1 = {0, sizeof(s1), s1};
    octet W0 = {0, sizeof(w0), w0};
    octet W1 = {0, sizeof(w1), w1};
    octet Z0 = {0, sizeof(z0), z0};
    octet Z1 = {0, sizeof(z1), z1};
    octet KEY = {0, sizeof(key), key};
    octet SALT = {0, sizeof(salt), salt};
    octet PW = {0, sizeof(pw), pw};

    SALT.len = 8;
    for (i = 0; i < 8; i++) SALT.val[i] = i + 1; // set Salt

    printf("Alice's Passphrase= %s\n", pp);

    OCT_empty(&PW);
    OCT_jstring(&PW, pp);  // set Password from string

    // private key S0 of size EGS_NIST256 bytes derived from Password and Salt

    PBKDF2(MC_SHA2, HASH_TYPE_NIST256, &S0, EGS_NIST256, &PW, &SALT, 1000);

    printf("Alices private key= 0x");
    OCT_output(&S0);

    // Generate Key pair S/W

    ECP_KEY_PAIR_GENERATE(NULL, &S0, &W0);
    printf("Alices public key= 0x");
    OCT_output(&W0);

    res = ECP_PUBLIC_KEY_VALIDATE(&W0);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }

    // Random private key for other party
    ECP_KEY_PAIR_GENERATE(RNG, &S1, &W1);
    res = ECP_PUBLIC_KEY_VALIDATE(&W1);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }
    printf("Servers private key= 0x");
    OCT_output(&S1);
    printf("Servers public key= 0x");
    OCT_output(&W1);

    // Calculate common key using DH - IEEE 1363 method

    ECP_SVDP_DH(&S0, &W1, &Z0, 0);
    ECP_SVDP_DH(&S1, &W0, &Z1, 0);

    if (!OCT_comp(&Z0, &Z1))
    {
        printf("*** ECPSVDP-DH Failed\n");
        return 0;
    }

    KDF2(MC_SHA2, HASH_TYPE_NIST256, &KEY, AESKEY_NIST256, &Z0, NULL);

    printf("Alice's DH Key=  0x");
    OCT_output(&KEY);
    printf("Servers DH Key=  0x");
    OCT_output(&KEY);

#if CURVETYPE_NIST256 != MONTGOMERY

    char ds[EGS_NIST256], p1[30], p2[30], v[2 * EFS_NIST256 + 1], m[32], c[64], t[32], cs[EGS_NIST256];
    octet DS = {0, sizeof(ds), ds};
    octet CS = {0, sizeof(cs), cs};
    octet P1 = {0, sizeof(p1), p1};
    octet P2 = {0, sizeof(p2), p2};
    octet V = {0, sizeof(v), v};
    octet M = {0, sizeof(m), m};
    octet C = {0, sizeof(c), c};
    octet T = {0, sizeof(t), t};

    printf("Testing ECIES\n");

    P1.len = 3;
    P1.val[0] = 0x0;
    P1.val[1] = 0x1;
    P1.val[2] = 0x2;
    P2.len = 4;
    P2.val[0] = 0x0;
    P2.val[1] = 0x1;
    P2.val[2] = 0x2;
    P2.val[3] = 0x3;

    M.len = 17;
    for (i = 0; i <= 16; i++) M.val[i] = i;

    ECP_ECIES_ENCRYPT(HASH_TYPE_NIST256, &P1, &P2, RNG, &W1, &M, 12, &V, &C, &T);

    printf("Ciphertext= \n");
    printf("V= 0x");
    OCT_output(&V);
    printf("C= 0x");
    OCT_output(&C);
    printf("T= 0x");
    OCT_output(&T);

    if (!ECP_ECIES_DECRYPT(HASH_TYPE_NIST256, &P1, &P2, &V, &C, &T, &S1, &M))
    {
        printf("*** ECIES Decryption Failed\n");
        return 0;
    }
    else printf("Decryption succeeded\n");

    printf("Message is 0x");
    OCT_output(&M);


    printf("Testing ECDSA\n");

    if (ECP_SP_DSA(HASH_TYPE_NIST256, RNG, NULL, &S0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Signature Failed\n");
        return 0;
    }

    printf("Signature C = 0x");
    OCT_output(&CS);
    printf("Signature D = 0x");
    OCT_output(&DS);

    if (ECP_VP_DSA(HASH_TYPE_NIST256, &W0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Verification Failed\n");
        return 0;
    }
    else
    {
        printf("ECDSA Signature/Verification succeeded\n");
    }

#endif

    return 1;
}

int ecdh_Ed448(csprng *RNG)
{
    using namespace Ed448;

    int i, res;
    unsigned long ran;
    char *pp = (char *)"M0ng00se";
    // These octets are automatically protected against buffer overflow attacks
    // Note salt must be big enough to include an appended word
    // Note ECIES ciphertext C must be big enough to include at least 1 appended block
    // Recall EFS_Ed448 is field size in bytes. So EFS_Ed448=32 for 256-bit curve
    char s0[2 * EGS_Ed448], s1[EGS_Ed448], w0[2 * EFS_Ed448 + 1], w1[2 * EFS_Ed448 + 1], z0[EFS_Ed448], z1[EFS_Ed448], key[AESKEY_Ed448], salt[40], pw[40];
    octet S0 = {0, sizeof(s0), s0};
    octet S1 = {0, sizeof(s1), s1};
    octet W0 = {0, sizeof(w0), w0};
    octet W1 = {0, sizeof(w1), w1};
    octet Z0 = {0, sizeof(z0), z0};
    octet Z1 = {0, sizeof(z1), z1};
    octet KEY = {0, sizeof(key), key};
    octet SALT = {0, sizeof(salt), salt};
    octet PW = {0, sizeof(pw), pw};

    SALT.len = 8;
    for (i = 0; i < 8; i++) SALT.val[i] = i + 1; // set Salt

    printf("Alice's Passphrase= %s\n", pp);

    OCT_empty(&PW);
    OCT_jstring(&PW, pp);  // set Password from string

    // private key S0 of size EGS_Ed448 bytes derived from Password and Salt

    PBKDF2(MC_SHA2, HASH_TYPE_Ed448, &S0, EGS_Ed448, &PW, &SALT, 1000);

    printf("Alices private key= 0x");
    OCT_output(&S0);

    // Generate Key pair S/W

    ECP_KEY_PAIR_GENERATE(NULL, &S0, &W0);
    printf("Alices public key= 0x");
    OCT_output(&W0);

    res = ECP_PUBLIC_KEY_VALIDATE(&W0);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }

    // Random private key for other party
    ECP_KEY_PAIR_GENERATE(RNG, &S1, &W1);
    res = ECP_PUBLIC_KEY_VALIDATE(&W1);
    if (res != 0)
    {
        printf("ECP Public Key is invalid!\n");
        return 0;
    }
    printf("Servers private key= 0x");
    OCT_output(&S1);
    printf("Servers public key= 0x");
    OCT_output(&W1);

    // Calculate common key using DH - IEEE 1363 method

    ECP_SVDP_DH(&S0, &W1, &Z0, 0);
    ECP_SVDP_DH(&S1, &W0, &Z1, 0);

    if (!OCT_comp(&Z0, &Z1))
    {
        printf("*** ECPSVDP-DH Failed\n");
        return 0;
    }

    KDF2(MC_SHA2, HASH_TYPE_Ed448, &KEY, AESKEY_Ed448, &Z0, NULL);

    printf("Alice's DH Key=  0x");
    OCT_output(&KEY);
    printf("Servers DH Key=  0x");
    OCT_output(&KEY);

#if CURVETYPE_Ed448 != MONTGOMERY

    char ds[EGS_Ed448], p1[30], p2[30], v[2 * EFS_Ed448 + 1], m[32], c[64], t[32], cs[EGS_Ed448];
    octet DS = {0, sizeof(ds), ds};
    octet CS = {0, sizeof(cs), cs};
    octet P1 = {0, sizeof(p1), p1};
    octet P2 = {0, sizeof(p2), p2};
    octet V = {0, sizeof(v), v};
    octet M = {0, sizeof(m), m};
    octet C = {0, sizeof(c), c};
    octet T = {0, sizeof(t), t};

    printf("Testing ECIES\n");

    P1.len = 3;
    P1.val[0] = 0x0;
    P1.val[1] = 0x1;
    P1.val[2] = 0x2;
    P2.len = 4;
    P2.val[0] = 0x0;
    P2.val[1] = 0x1;
    P2.val[2] = 0x2;
    P2.val[3] = 0x3;

    M.len = 17;
    for (i = 0; i <= 16; i++) M.val[i] = i;

    ECP_ECIES_ENCRYPT(HASH_TYPE_Ed448, &P1, &P2, RNG, &W1, &M, 12, &V, &C, &T);

    printf("Ciphertext= \n");
    printf("V= 0x");
    OCT_output(&V);
    printf("C= 0x");
    OCT_output(&C);
    printf("T= 0x");
    OCT_output(&T);

    if (!ECP_ECIES_DECRYPT(HASH_TYPE_Ed448, &P1, &P2, &V, &C, &T, &S1, &M))
    {
        printf("*** ECIES Decryption Failed\n");
        return 0;
    }
    else printf("Decryption succeeded\n");

    printf("Message is 0x");
    OCT_output(&M);


    printf("Testing ECDSA\n");

    if (ECP_SP_DSA(HASH_TYPE_Ed448, RNG, NULL, &S0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Signature Failed\n");
        return 0;
    }

    printf("Signature C = 0x");
    OCT_output(&CS);
    printf("Signature D = 0x");
    OCT_output(&DS);

    if (ECP_VP_DSA(HASH_TYPE_Ed448, &W0, &M, &CS, &DS) != 0)
    {
        printf("***ECDSA Verification Failed\n");
        return 0;
    }
    else
    {
        printf("ECDSA Signature/Verification succeeded\n");
    }

#endif

    return 1;
}
#endif

int rsa_2048(csprng *RNG)
{
    using namespace RSA2048;

    int i,valid;
    unsigned long ran;
    char m[RFS_RSA2048], ml[RFS_RSA2048], c[RFS_RSA2048], e[RFS_RSA2048], s[RFS_RSA2048];
    rsa_public_key pub;
    rsa_private_key priv;

    octet M = {0, sizeof(m), m};
    octet ML = {0, sizeof(ml), ml};
    octet C = {0, sizeof(c), c};
    octet E = {0, sizeof(e), e};
    octet S = {0, sizeof(s), s};

    printf("Generating public/private key pair\n");
    RSA_KEY_PAIR(RNG, 65537, &priv, &pub, NULL, NULL);

    printf("Encrypting test string\n");
    OCT_jstring(&M, (char *)"Hello World\n");

    OAEP_ENCODE(HASH_TYPE_RSA_RSA2048, &M, RNG, NULL, &E); // OAEP encode message m to e

    RSA_ENCRYPT(&pub, &E, &C);   // encrypt encoded message
    printf("Ciphertext= ");
    OCT_output(&C);

    printf("Decrypting test string\n");
    RSA_DECRYPT(&priv, &C, &ML); // ... and then decrypt it
    printf("Decrypted\n");
    OAEP_DECODE(HASH_TYPE_RSA_RSA2048, NULL, &ML);  // decode it
    printf("Decoded\n");
    OCT_output_string(&ML);


    PSS_ENCODE(HASH_TYPE_RSA_RSA2048, &M, RNG, &C);
    //printf("T= 0x");OCT_output(&C);
    if (PSS_VERIFY(HASH_TYPE_RSA_RSA2048, &M, &C))
        printf("PSS encoding OK\n");
    else
        printf("PSS Encoding FAILED\n");


// Signature
    printf("Signing message\n");
    PKCS15(HASH_TYPE_RSA_RSA2048, &M, &C);

    RSA_DECRYPT(&priv, &C, &S); // create signature in S

    printf("Signature= ");
    OCT_output(&S);



// Verification
    valid=0;
    RSA_ENCRYPT(&pub, &S, &ML);
    PKCS15(HASH_TYPE_RSA_RSA2048, &M, &C);

    if (OCT_comp(&C, &ML)) valid=1;
    else {
        PKCS15b(HASH_TYPE_RSA_RSA2048, &M, &C);
        if (OCT_comp(&C, &ML)) valid=1;
    }

    if (valid) printf("Signature is valid\n");
    else printf("Signature is INVALID\n");

    RSA_PRIVATE_KEY_KILL(&priv);

    OCT_clear(&M);
    OCT_clear(&ML);   // clean up afterwards
    OCT_clear(&C);
    OCT_clear(&E);

    return 1;
}


int main()
{
    int i, res;
    unsigned long ran;

    char raw[100];
    octet RAW = {0, sizeof(raw), raw};
    csprng RNG;                // Crypto Strong RNG

    time((time_t *)&ran);

    RAW.len = 100;              // fake random seed source
    RAW.val[0] = ran;
    RAW.val[1] = ran >> 8;
    RAW.val[2] = ran >> 16;
    RAW.val[3] = ran >> 24;
    for (i = 0; i < 100; i++) RAW.val[i] = i;

    CREATE_CSPRNG(&RNG, &RAW);  // initialise strong RNG

    printf("\nTesting ECDH protocols for curve Ed25519\n");
    ecdh_Ed25519(&RNG);
#if CHUNK!=16
    printf("\nTesting ECDH protocols for curve NIST256\n");
    ecdh_NIST256(&RNG);
    printf("\nTesting ECDH protocols for curve Ed448\n");
    ecdh_Ed448(&RNG);
#endif
    printf("\nTesting RSA protocols for 2048-bit RSA\n");
    rsa_2048(&RNG);

    KILL_CSPRNG(&RNG);
}

