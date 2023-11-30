#ifndef MAIN_H
#define MAIN_H
#include <pair_BLS12383.h>
#include <bls_BLS12383.h>
#include <ecp_NIST256.h>
#include <randapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <cstdarg>
#include <string>
#include <vector>
// C25519
//using namespace B256_56;
//using namespace C25519;
//BLS12381-PAIRING
using namespace B384_58;
using namespace BLS12383;
//using namespace NIST256;
using namespace core;
using namespace std;

void initRNG(csprng *rng);
void randBigInt(BIG *big);
void hashtoZp256(BIG num, octet *ct);
void hashtoZp384(BIG num, octet *ct,BIG q);
void hashtoStr384(char* str, octet *ct);
void hashtoDStr384(char* str, octet *ct);
void testForBLS12381WithPairing();
void testForNIST256();
#endif