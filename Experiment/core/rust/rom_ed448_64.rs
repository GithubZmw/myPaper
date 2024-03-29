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

use crate::arch::Chunk;
use crate::ed448::big::NLEN;

// Base Bits= 58
// Goldilocks modulus
pub const MODULUS: [Chunk; NLEN] = [
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FBFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFF,
];
pub const ROI: [Chunk; NLEN] = [
    0x3FFFFFFFFFFFFFE,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FBFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFF,
];
pub const R2MODP: [Chunk; NLEN] = [0x200000000, 0x0, 0x0, 0x0, 0x3000000, 0x0, 0x0, 0x0];
pub const MCONST: Chunk = 0x1;

// Goldilocks curve
pub const CURVE_COF_I: isize = 4;
pub const CURVE_B_I: isize = -39081;
pub const CURVE_COF: [Chunk; NLEN] = [0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
pub const CURVE_B: [Chunk; NLEN] = [
    0x3FFFFFFFFFF6756,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FBFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFF,
];
pub const CURVE_ORDER: [Chunk; NLEN] = [
    0x378C292AB5844F3,
    0x3309CA37163D548,
    0x1B49AED63690216,
    0x3FDF3288FA7113B,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFF,
    0xFFFFFFFFFF,
];
/*
pub const CURVE_GX: [Chunk; NLEN] = [
    0x155555555555555,
    0x155555555555555,
    0x155555555555555,
    0x2A5555555555555,
    0x2AAAAAAAAAAAAAA,
    0x2AAAAAAAAAAAAAA,
    0x2AAAAAAAAAAAAAA,
    0x2AAAAAAAAAA,
];
pub const CURVE_GY: [Chunk; NLEN] = [
    0x2EAFBCDEA9386ED,
    0x32CAFB473681AF6,
    0x25833A2A3098BBB,
    0x1CA2B6312E03595,
    0x35884DD7B7E36D,
    0x21B0AC00DBB5E8,
    0x17048DB359D6205,
    0x2B817A58D2B,
];*/
pub const CURVE_GX:[Chunk;NLEN]=[0x226A82BC70CC05E,0x2E03862C024E389,0x1AF72AB66511433,0x928F4E91904AB8,0x470F1767EA6DE3,0xAFCDB6A785195C,0x2D0DED221D15A62,0x13C65C319AF];
pub const CURVE_GY:[Chunk;NLEN]=[0x8795BF230FA14,0x344CB13B5F22B66,0x3F1CE67C39C4FDB,0x7816830B5CEB4F,0x36CA3984087789C,0x1B271D892FA9CDC,0x36BC24887620375,0x1A4FD19C5BA];
pub const CURVE_HTPC:[Chunk;NLEN]=[0x3FFFFFFFFFFFFFE,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FBFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFFFFFF,0x3FFFFFFFFFF];
