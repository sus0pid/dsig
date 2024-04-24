#include "haraka.h"
#include <stdio.h>

_Thread_local u128 haraka_rc[40];
_Thread_local int haraka_loaded = 0;

void load_constants() {
  if (haraka_loaded) {
    return;
  }
  haraka_rc[0] = _mm_set_epi32((int)0x0684704c,(int)0xe620c00a,(int)0xb2c5fef0,(int)0x75817b9d);
  haraka_rc[1] = _mm_set_epi32((int)0x8b66b4e1,(int)0x88f3a06b,(int)0x640f6ba4,(int)0x2f08f717);
  haraka_rc[2] = _mm_set_epi32((int)0x3402de2d,(int)0x53f28498,(int)0xcf029d60,(int)0x9f029114);
  haraka_rc[3] = _mm_set_epi32((int)0x0ed6eae6,(int)0x2e7b4f08,(int)0xbbf3bcaf,(int)0xfd5b4f79);
  haraka_rc[4] = _mm_set_epi32((int)0xcbcfb0cb,(int)0x4872448b,(int)0x79eecd1c,(int)0xbe397044);
  haraka_rc[5] = _mm_set_epi32((int)0x7eeacdee,(int)0x6e9032b7,(int)0x8d5335ed,(int)0x2b8a057b);
  haraka_rc[6] = _mm_set_epi32((int)0x67c28f43,(int)0x5e2e7cd0,(int)0xe2412761,(int)0xda4fef1b);
  haraka_rc[7] = _mm_set_epi32((int)0x2924d9b0,(int)0xafcacc07,(int)0x675ffde2,(int)0x1fc70b3b);
  haraka_rc[8] = _mm_set_epi32((int)0xab4d63f1,(int)0xe6867fe9,(int)0xecdb8fca,(int)0xb9d465ee);
  haraka_rc[9] = _mm_set_epi32((int)0x1c30bf84,(int)0xd4b7cd64,(int)0x5b2a404f,(int)0xad037e33);
  haraka_rc[10] = _mm_set_epi32((int)0xb2cc0bb9,(int)0x941723bf,(int)0x69028b2e,(int)0x8df69800);
  haraka_rc[11] = _mm_set_epi32((int)0xfa0478a6,(int)0xde6f5572,(int)0x4aaa9ec8,(int)0x5c9d2d8a);
  haraka_rc[12] = _mm_set_epi32((int)0xdfb49f2b,(int)0x6b772a12,(int)0x0efa4f2e,(int)0x29129fd4);
  haraka_rc[13] = _mm_set_epi32((int)0x1ea10344,(int)0xf449a236,(int)0x32d611ae,(int)0xbb6a12ee);
  haraka_rc[14] = _mm_set_epi32((int)0xaf044988,(int)0x4b050084,(int)0x5f9600c9,(int)0x9ca8eca6);
  haraka_rc[15] = _mm_set_epi32((int)0x21025ed8,(int)0x9d199c4f,(int)0x78a2c7e3,(int)0x27e593ec);
  haraka_rc[16] = _mm_set_epi32((int)0xbf3aaaf8,(int)0xa759c9b7,(int)0xb9282ecd,(int)0x82d40173);
  haraka_rc[17] = _mm_set_epi32((int)0x6260700d,(int)0x6186b017,(int)0x37f2efd9,(int)0x10307d6b);
  haraka_rc[18] = _mm_set_epi32((int)0x5aca45c2,(int)0x21300443,(int)0x81c29153,(int)0xf6fc9ac6);
  haraka_rc[19] = _mm_set_epi32((int)0x9223973c,(int)0x226b68bb,(int)0x2caf92e8,(int)0x36d1943a);
  haraka_rc[20] = _mm_set_epi32((int)0xd3bf9238,(int)0x225886eb,(int)0x6cbab958,(int)0xe51071b4);
  haraka_rc[21] = _mm_set_epi32((int)0xdb863ce5,(int)0xaef0c677,(int)0x933dfddd,(int)0x24e1128d);
  haraka_rc[22] = _mm_set_epi32((int)0xbb606268,(int)0xffeba09c,(int)0x83e48de3,(int)0xcb2212b1);
  haraka_rc[23] = _mm_set_epi32((int)0x734bd3dc,(int)0xe2e4d19c,(int)0x2db91a4e,(int)0xc72bf77d);
  haraka_rc[24] = _mm_set_epi32((int)0x43bb47c3,(int)0x61301b43,(int)0x4b1415c4,(int)0x2cb3924e);
  haraka_rc[25] = _mm_set_epi32((int)0xdba775a8,(int)0xe707eff6,(int)0x03b231dd,(int)0x16eb6899);
  haraka_rc[26] = _mm_set_epi32((int)0x6df3614b,(int)0x3c755977,(int)0x8e5e2302,(int)0x7eca472c);
  haraka_rc[27] = _mm_set_epi32((int)0xcda75a17,(int)0xd6de7d77,(int)0x6d1be5b9,(int)0xb88617f9);
  haraka_rc[28] = _mm_set_epi32((int)0xec6b43f0,(int)0x6ba8e9aa,(int)0x9d6c069d,(int)0xa946ee5d);
  haraka_rc[29] = _mm_set_epi32((int)0xcb1e6950,(int)0xf957332b,(int)0xa2531159,(int)0x3bf327c1);
  haraka_rc[30] = _mm_set_epi32((int)0x2cee0c75,(int)0x00da619c,(int)0xe4ed0353,(int)0x600ed0d9);
  haraka_rc[31] = _mm_set_epi32((int)0xf0b1a5a1,(int)0x96e90cab,(int)0x80bbbabc,(int)0x63a4a350);
  haraka_rc[32] = _mm_set_epi32((int)0xae3db102,(int)0x5e962988,(int)0xab0dde30,(int)0x938dca39);
  haraka_rc[33] = _mm_set_epi32((int)0x17bb8f38,(int)0xd554a40b,(int)0x8814f3a8,(int)0x2e75b442);
  haraka_rc[34] = _mm_set_epi32((int)0x34bb8a5b,(int)0x5f427fd7,(int)0xaeb6b779,(int)0x360a16f6);
  haraka_rc[35] = _mm_set_epi32((int)0x26f65241,(int)0xcbe55438,(int)0x43ce5918,(int)0xffbaafde);
  haraka_rc[36] = _mm_set_epi32((int)0x4ce99a54,(int)0xb9f3026a,(int)0xa2ca9cf7,(int)0x839ec978);
  haraka_rc[37] = _mm_set_epi32((int)0xae51a51a,(int)0x1bdff7be,(int)0x40c06e28,(int)0x22901235);
  haraka_rc[38] = _mm_set_epi32((int)0xa0c1613c,(int)0xba7ed22b,(int)0xc173bc0f,(int)0x48a659cf);
  haraka_rc[39] = _mm_set_epi32((int)0x756acc03,(int)0x02288288,(int)0x4ad6bdfd,(int)0xe9c59da1);
  haraka_loaded = 1;
}

// Inner (load + rounds)
static inline void haraka256_inner(u128* s, const unsigned char *in) {
  load_constants();
  u128 tmp;

  LOAD2(s, in)

  // Round 1
  AES2(s, 0)
  MIX2(s)
  // Round 2
  AES2(s, 4)
  MIX2(s)
  // Round 3
  AES2(s, 8)
  MIX2(s)
  // Round 4
  AES2(s, 12)
  MIX2(s)
  // Round 5
  AES2(s, 16)
  MIX2(s)
}

static inline void haraka256_4x_inner(u128* s0, u128* s1, u128* s2, u128* s3, const unsigned char *in) {
  load_constants();
  u128 tmp;

  LOAD2_4x(s0, s1, s2, s3, in)

  // Round 1
  AES2_4x(s0, s1, s2, s3, 0)
  MIX2_4x(s0, s1, s2, s3)
  // Round 2
  AES2_4x(s0, s1, s2, s3, 4)
  MIX2_4x(s0, s1, s2, s3)
  // Round 3
  AES2_4x(s0, s1, s2, s3, 8)
  MIX2_4x(s0, s1, s2, s3)
  // Round 4
  AES2_4x(s0, s1, s2, s3, 12)
  MIX2_4x(s0, s1, s2, s3)
  // Round 5
  AES2_4x(s0, s1, s2, s3, 16)
  MIX2_4x(s0, s1, s2, s3)
}

static inline void haraka512_inner(u128* s, const unsigned char *in) {
  load_constants();
  u128 tmp;

  LOAD4(s, in)

  // Round 1
  AES4(s, 0)
  MIX4(s)
  // Round 2
  AES4(s, 8)
  MIX4(s)
  // Round 3
  AES4(s, 16)
  MIX4(s)
  // Round 4
  AES4(s, 24)
  MIX4(s)
  // Round 5
  AES4(s, 32)
  MIX4(s)
}

static inline void haraka512_4x_inner(u128* s0, u128* s1, u128* s2, u128* s3, const unsigned char* in) {
  load_constants();
  u128 tmp;

  LOAD4_4x(s0, s1, s2, s3, in)

  // Round 1
  AES4_4x(s0, s1, s2, s3, 0)
  MIX4_4x(s0, s1, s2, s3)
  // Round 2
  AES4_4x(s0, s1, s2, s3, 8)
  MIX4_4x(s0, s1, s2, s3)
  // Round 3
  AES4_4x(s0, s1, s2, s3, 16)
  MIX4_4x(s0, s1, s2, s3)
  // Round 4
  AES4_4x(s0, s1, s2, s3, 24)
  MIX4_4x(s0, s1, s2, s3)
  // Round 5
  AES4_4x(s0, s1, s2, s3, 32)
  MIX4_4x(s0, s1, s2, s3)
}

// Full output versions
void haraka256(unsigned char *out, const unsigned char *in) {
  u128 s[2];

  haraka256_inner(s, in);

  FULLXOR(s, in)
  FULLSTORE(out, s)
}

void haraka256_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][2];

  haraka256_4x_inner(s[0], s[1], s[2], s[3], in);

  // Feed Forward
  FULLXOR_4x(s, in)
  FULLSTORE_4x(out, s)
}

void haraka512(unsigned char *out, const unsigned char *in) {
  u128 s[4];

  haraka512_inner(s, in);

  FULL_XOR_TRUNCATE(s, in)
  FULLSTORE(out, s)
}

void haraka512_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][4];

  haraka512_4x_inner(s[0], s[1], s[2], s[3], in);

  FULL_XOR_TRUNCATE_4x(s, in)
  FULLSTORE_4x(out, s)
}

// Truncated output versions
void half_haraka256(unsigned char *out, const unsigned char *in) {
  u128 s[2];

  haraka256_inner(s, in);

  HALFXOR(s, in)
  HALFSTORE(out, s)
}

void mid_haraka256(unsigned char *out, const unsigned char *in) {
  u128 s[2];

  haraka256_inner(s, in);

  MIDXOR(s, in)
  MIDSTORE(out, s)
}

void half_haraka512(unsigned char *out, const unsigned char *in) {
  u128 s[4];

  haraka512_inner(s, in);

  HALF_XOR_TRUNCATE(s, in)
  HALFSTORE(out, s)
}

void mid_haraka512(unsigned char *out, const unsigned char *in) {
  u128 s[4];

  haraka512_inner(s, in);

  MID_XOR_TRUNCATE(s, in)
  MIDSTORE(out, s)
}

// Truncated output versions
void half_haraka256_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][2];

  haraka256_4x_inner(s[0], s[1], s[2], s[3], in);

  HALFXOR_4x(s, in)
  HALFSTORE_4x(out, s)
}

void mid_haraka256_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][2];

  haraka256_4x_inner(s[0], s[1], s[2], s[3], in);

  MIDXOR_4x(s, in)
  MIDSTORE_4x(out, s)
}

void half_haraka512_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][4];

  haraka512_4x_inner(s[0], s[1], s[2], s[3], in);

  HALF_XOR_TRUNCATE_4x(s, in)
  HALFSTORE_4x(out, s)
}

void mid_haraka512_4x(unsigned char *out, const unsigned char *in) {
  u128 s[4][4];

  haraka512_4x_inner(s[0], s[1], s[2], s[3], in);

  MID_XOR_TRUNCATE_4x(s, in)
  MIDSTORE_4x(out, s)
}