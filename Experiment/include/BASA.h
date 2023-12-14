//
// Created by Miracle on 2023/12/9.
//

#include "common.h"


typedef struct {
    BIG hid;
    BIG q;
    BIG N;
    ECP P1;
    ECP2 P2;
    ECP2 P_pub_s;
}Params;


typedef struct {
    BIG h;
    ECP S;
}Signature;



typedef struct {
    BIG ID;
    long deadline;
}XID;
