/*
Optimized Implementations for Haraka256 and Haraka512
*/
#ifndef HARAKA_H_
#define HARAKA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "immintrin.h"
#include <stdint.h>

#define NUMROUNDS 5

#define u16 uint16_t
#define u64 uint64_t
#define u128 __m128i

#define LOAD(src) _mm_load_si128((u128 const*)(src))

#define LOAD2(s, in) \
  s[0] = LOAD(in); \
  s[1] = LOAD(in + 16);

#define LOAD2_4x(s0, s1, s2, s3, in) \
  LOAD2(s0, in) \
  LOAD2(s1, in + 32) \
  LOAD2(s2, in + 64) \
  LOAD2(s3, in + 96)

#define LOAD4(s, in) \
  s[0] = LOAD(in); \
  s[1] = LOAD(in + 16); \
  s[2] = LOAD(in + 32); \
  s[3] = LOAD(in + 48);

#define LOAD4_4x(s0, s1, s2, s3, in) \
  LOAD4(s0, in) \
  LOAD4(s1, in + 64) \
  LOAD4(s2, in + 128) \
  LOAD4(s3, in + 192)

#define AES(s, rc) \
  s = _mm_aesenc_si128(s, rc);

#define AES_4x(s0, s1, s2, s3, rci) \
  { \
    u128 rc = haraka_rc[rci]; \
    AES(s0, rc) \
    AES(s1, rc) \
    AES(s2, rc) \
    AES(s3, rc) \
  }

#define AES2(s, rci) \
  AES(s[0], haraka_rc[rci + 0]) \
  AES(s[1], haraka_rc[rci + 1]) \
  AES(s[0], haraka_rc[rci + 2]) \
  AES(s[1], haraka_rc[rci + 3])

#define AES2_4x(s0, s1, s2, s3, rci) \
  AES_4x(s0[0], s1[0], s2[0], s3[0], rci + 0) \
  AES_4x(s0[1], s1[1], s2[1], s3[1], rci + 1) \
  AES_4x(s0[0], s1[0], s2[0], s3[0], rci + 2) \
  AES_4x(s0[1], s1[1], s2[1], s3[1], rci + 3)

#define AES4(s, rci) \
  AES(s[0], haraka_rc[rci + 0]) \
  AES(s[1], haraka_rc[rci + 1]) \
  AES(s[2], haraka_rc[rci + 2]) \
  AES(s[3], haraka_rc[rci + 3]) \
  AES(s[0], haraka_rc[rci + 4]) \
  AES(s[1], haraka_rc[rci + 5]) \
  AES(s[2], haraka_rc[rci + 6]) \
  AES(s[3], haraka_rc[rci + 7])

#define AES4_4x(s0, s1, s2, s3, rci) \
  AES_4x(s0[0], s1[0], s2[0], s3[0], rci + 0) \
  AES_4x(s0[1], s1[1], s2[1], s3[1], rci + 1) \
  AES_4x(s0[2], s1[2], s2[2], s3[2], rci + 2) \
  AES_4x(s0[3], s1[3], s2[3], s3[3], rci + 3) \
  AES_4x(s0[0], s1[0], s2[0], s3[0], rci + 4) \
  AES_4x(s0[1], s1[1], s2[1], s3[1], rci + 5) \
  AES_4x(s0[2], s1[2], s2[2], s3[2], rci + 6) \
  AES_4x(s0[3], s1[3], s2[3], s3[3], rci + 7)

#define MIX2(s) \
  tmp  = _mm_unpacklo_epi32(s[0], s[1]); \
  s[1] = _mm_unpackhi_epi32(s[0], s[1]); \
  s[0] = tmp;

#define MIX2_4x(s0, s1, s2, s3) \
  MIX2(s0) \
  MIX2(s1) \
  MIX2(s2) \
  MIX2(s3)

#define MIX4(s) \
  tmp  = _mm_unpacklo_epi32(s[0], s[1]); \
  s[0] = _mm_unpackhi_epi32(s[0], s[1]); \
  s[1] = _mm_unpacklo_epi32(s[2], s[3]); \
  s[2] = _mm_unpackhi_epi32(s[2], s[3]); \
  s[3] = _mm_unpacklo_epi32(s[0], s[2]); \
  s[0] = _mm_unpackhi_epi32(s[0], s[2]); \
  s[2] = _mm_unpackhi_epi32(s[1], tmp); \
  s[1] = _mm_unpacklo_epi32(s[1], tmp);

#define MIX4_4x(s0, s1, s2, s3) \
  MIX4(s0) \
  MIX4(s1) \
  MIX4(s2) \
  MIX4(s3)

#define XOR(s, in) s = _mm_xor_si128(s, LOAD(in));

#define FULLXOR(s, in) \
  XOR(s[0], in) \
  XOR(s[1], in + 16) \

#define HALFXOR(s, in) \
  XOR(s[0], in)

#define MIDXOR(s, in) \
  XOR(s[0], in) \
  ((u16*)s)[8] ^= *(u16*)(in + 16);


#define STORE(dest,src) _mm_storeu_si128((u128 *)(dest),src);

#define FULLSTORE(out, s) \
  STORE(out, s[0]) \
  STORE(out + 16, s[1])

#define HALFSTORE(out, s) \
  STORE(out, s[0])

#define MIDSTORE(out, s) \
  STORE(out, s[0]) \
  *(u16*)(out + 16) = ((u16*)(s))[8];

#define FULL_XOR_TRUNCATE(s, in) \
  ((u64*)(s))[0] = ((u64*)(s + 0))[1] ^ *(u64*)(in +  8); \
  ((u64*)(s))[1] = ((u64*)(s + 1))[1] ^ *(u64*)(in + 24); \
  ((u64*)(s))[2] = ((u64*)(s + 2))[0] ^ *(u64*)(in + 32); \
  ((u64*)(s))[3] = ((u64*)(s + 3))[0] ^ *(u64*)(in + 48);

#define HALF_XOR_TRUNCATE(s, in) \
  ((u64*)(s))[0] = ((u64*)(s + 0))[1] ^ *(u64*)((in) +  8); \
  ((u64*)(s))[1] = ((u64*)(s + 1))[1] ^ *(u64*)((in) + 24);

#define MID_XOR_TRUNCATE(s, in) \
  HALF_XOR_TRUNCATE(s, in) \
  ((u16*)(s))[8] = ((u16*)(s + 2))[0] ^ *(u16*)((in) + 32);

#define FULLXOR_4x(s, in) \
  FULLXOR(s[0], in + 0) \
  FULLXOR(s[1], in + 32) \
  FULLXOR(s[2], in + 64) \
  FULLXOR(s[3], in + 96)

#define HALFXOR_4x(s, in) \
  HALFXOR(s[0], in + 0) \
  HALFXOR(s[1], in + 32) \
  HALFXOR(s[2], in + 64) \
  HALFXOR(s[3], in + 96)

#define MIDXOR_4x(s, in) \
  MIDXOR(s[0], in + 0) \
  MIDXOR(s[1], in + 32) \
  MIDXOR(s[2], in + 64) \
  MIDXOR(s[3], in + 96)

#define FULLSTORE_4x(out, s) \
  FULLSTORE(out + 0, s[0]) \
  FULLSTORE(out + 32, s[1]) \
  FULLSTORE(out + 64, s[2]) \
  FULLSTORE(out + 96, s[3])

#define HALFSTORE_4x(out, s) \
  HALFSTORE(out + 0, s[0]) \
  HALFSTORE(out + 16, s[1]) \
  HALFSTORE(out + 32, s[2]) \
  HALFSTORE(out + 48, s[3])

#define MIDSTORE_4x(out, s) \
  MIDSTORE(out + 0, s[0]) \
  MIDSTORE(out + 18, s[1]) \
  MIDSTORE(out + 36, s[2]) \
  MIDSTORE(out + 54, s[3])

#define FULL_XOR_TRUNCATE_4x(s, in) \
  FULL_XOR_TRUNCATE(s[0], in + 0) \
  FULL_XOR_TRUNCATE(s[1], in + 64) \
  FULL_XOR_TRUNCATE(s[2], in + 128) \
  FULL_XOR_TRUNCATE(s[3], in + 192)

#define HALF_XOR_TRUNCATE_4x(s, in) \
  HALF_XOR_TRUNCATE(s[0], in + 0) \
  HALF_XOR_TRUNCATE(s[1], in + 64) \
  HALF_XOR_TRUNCATE(s[2], in + 128) \
  HALF_XOR_TRUNCATE(s[3], in + 192)

#define MID_XOR_TRUNCATE_4x(s, in) \
  MID_XOR_TRUNCATE(s[0], in + 0) \
  MID_XOR_TRUNCATE(s[1], in + 64) \
  MID_XOR_TRUNCATE(s[2], in + 128) \
  MID_XOR_TRUNCATE(s[3], in + 192)

void load_constants();

void haraka256(unsigned char *out, const unsigned char *in);
void haraka256_4x(unsigned char *out, const unsigned char *in);

void haraka512(unsigned char *out, const unsigned char *in);
void haraka512_4x(unsigned char *out, const unsigned char *in);

void half_haraka256(unsigned char *out, const unsigned char *in);
void half_haraka512(unsigned char *out, const unsigned char *in);
void mid_haraka256(unsigned char *out, const unsigned char *in);
void mid_haraka512(unsigned char *out, const unsigned char *in);

void half_haraka256_4x(unsigned char *out, const unsigned char *in);
void half_haraka512_4x(unsigned char *out, const unsigned char *in);
void mid_haraka256_4x(unsigned char *out, const unsigned char *in);
void mid_haraka512_4x(unsigned char *out, const unsigned char *in);

#ifdef __cplusplus
}
#endif

#endif