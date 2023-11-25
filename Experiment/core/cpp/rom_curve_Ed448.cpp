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
#include "arch.h"
#include "ecp_Ed448.h"

namespace Ed448 {

/* Curve Ed448 */

#if CHUNK==16

#error Not supported

#endif

#if CHUNK==32

using namespace B448_29;

const int CURVE_Cof_I=4;
const BIG CURVE_Cof= {0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0};
const int CURVE_B_I= -39081;
const BIG CURVE_B= {0x1FFF6756,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FDFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFF};
const BIG CURVE_Order= {0xB5844F3,0x1BC61495,0x1163D548,0x1984E51B,0x3690216,0xDA4D76B,0xFA7113B,0x1FEF9944,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x7FF};
//const BIG CURVE_Gx= {0x15555555,0xAAAAAAA,0x15555555,0xAAAAAAA,0x15555555,0xAAAAAAA,0x15555555,0x152AAAAA,0xAAAAAAA,0x15555555,0xAAAAAAA,0x15555555,0xAAAAAAA,0x15555555,0xAAAAAAA,0x1555};
//const BIG CURVE_Gy= {0xA9386ED,0x1757DE6F,0x13681AF6,0x19657DA3,0x3098BBB,0x12C19D15,0x12E03595,0xE515B18,0x17B7E36D,0x1AC426E,0xDBB5E8,0x10D8560,0x159D6205,0xB8246D9,0x17A58D2B,0x15C0};
const BIG CURVE_Gx= {0x70CC05E,0x1135415E,0x24E389,0x1701C316,0x6511433,0xD7B955B,0x11904AB8,0x4947A74,0x7EA6DE3,0x23878BB,0x785195C,0x57E6DB5,0x1D15A62,0x1686F691,0x5C319AF,0x9E3};
const BIG CURVE_Gy= {0x1230FA14,0x43CADF,0x15F22B66,0x1A26589D,0x39C4FDB,0x1F8E733E,0xB5CEB4F,0x3C0B418,0x87789C,0x1B651CC2,0x12FA9CDC,0xD938EC4,0x7620375,0x1B5E1244,0x1D19C5BA,0xD27};
const BIG CURVE_HTPC= {0x1FFFFFFE,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FDFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFFFFFF,0x1FFF};
#endif

#if CHUNK==64

using namespace B448_58;

const int CURVE_Cof_I=4;
const BIG CURVE_Cof= {0x4L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
const int CURVE_B_I= -39081;
const BIG CURVE_B= {0x3FFFFFFFFFF6756L,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FBFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFL};
const BIG CURVE_Order= {0x378C292AB5844F3L,0x3309CA37163D548L,0x1B49AED63690216L,0x3FDF3288FA7113BL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0xFFFFFFFFFFL};
//const BIG CURVE_Gx= {0x155555555555555L,0x155555555555555L,0x155555555555555L,0x2A5555555555555L,0x2AAAAAAAAAAAAAAL,0x2AAAAAAAAAAAAAAL,0x2AAAAAAAAAAAAAAL,0x2AAAAAAAAAAL};
//const BIG CURVE_Gy= {0x2EAFBCDEA9386EDL,0x32CAFB473681AF6L,0x25833A2A3098BBBL,0x1CA2B6312E03595L,0x35884DD7B7E36DL,0x21B0AC00DBB5E8L,0x17048DB359D6205L,0x2B817A58D2BL};
const BIG CURVE_Gx= {0x226A82BC70CC05EL,0x2E03862C024E389L,0x1AF72AB66511433L,0x928F4E91904AB8L,0x470F1767EA6DE3L,0xAFCDB6A785195CL,0x2D0DED221D15A62L,0x13C65C319AFL};
const BIG CURVE_Gy= {0x8795BF230FA14L,0x344CB13B5F22B66L,0x3F1CE67C39C4FDBL,0x7816830B5CEB4FL,0x36CA3984087789CL,0x1B271D892FA9CDCL,0x36BC24887620375L,0x1A4FD19C5BAL};
const BIG CURVE_HTPC= {0x3FFFFFFFFFFFFFEL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FBFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFFFFFL,0x3FFFFFFFFFFL};
#endif

}
