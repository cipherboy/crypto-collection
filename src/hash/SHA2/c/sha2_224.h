/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha2_224 hash algorithm per RFC 4634. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha2_224 m;
 *     sha2_224_init(&m);
 *     sha2_224_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha2_224_sum returns the resulting sha2_224 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha2_224 m;
 *     sha2_224_init(&m);
 *     sha2_224_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha2_224_finalize(&m);
*/

#pragma once
#ifndef CC_SHA2_224_H
#define CC_SHA2_224_H

#include "stdint.h"
#include "string.h"

/*
 * struct sha2_224
 *
 * uint8_t digest[28]  -- public; digest after finalization
 *
 * uint32_t h[8]       -- internal; hash state variables
 * uint64_t len        -- internal; length of input
 * uint8_t partial[64] -- internal; partial block of input
 * size_t p_len        -- internal; length of partial block
*/
struct sha2_224 {
    uint8_t digest[28];

    uint32_t h[8];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

/*
 * sha2_224 sha2_224_rotl32
 *
 * The rotate left (circular left shift) operation ROTL^n(x), where
 * x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTL^n(X) = (x<<n) OR (x>>w-n)
*/
extern inline uint32_t sha2_224_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

/*
 * sha2_224 sha2_224_rotr32
 *
 * The rotate right (circular right shift) operation ROTR^n(x),
 * where x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTR^n(x) = (x>>n) OR (x<<(w-n))
*/
extern inline uint32_t sha2_224_rotr32(uint32_t data, uint32_t count)
{
    return ((data << (32 - count)) | (data >> count));
}

/*
 * sha2_224 sha2_224_ch
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
*/
extern inline uint32_t sha2_224_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

/*
 * sha2_224 sha2_224_mj
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
*/
extern inline uint32_t sha2_224_mj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/*
 * sha2_224 sha2_224_bsig0
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
*/
extern inline uint32_t sha2_224_bsig0(uint32_t x)
{
    return sha2_224_rotr32(x, 2) ^ sha2_224_rotr32(x, 13) ^ sha2_224_rotr32(x,
            22);
}

/*
 * sha2_224 sha2_224_bsig1
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
*/
extern inline uint32_t sha2_224_bsig1(uint32_t x)
{
    return sha2_224_rotr32(x, 6) ^ sha2_224_rotr32(x, 11) ^ sha2_224_rotr32(x,
            25);
}

/*
 * sha2_224 sha2_224_ssig0
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
*/
extern inline uint32_t sha2_224_ssig0(uint32_t x)
{
    return sha2_224_rotr32(x, 7) ^ sha2_224_rotr32(x, 18) ^ (x >> 3);
}

/*
 * sha2_224 sha2_224_ssig1
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
*/
extern inline uint32_t sha2_224_ssig1(uint32_t x)
{
    return sha2_224_rotr32(x, 17) ^ sha2_224_rotr32(x, 19) ^ (x >> 10);
}

extern inline void sha2_224_core(struct sha2_224* m)
{
    size_t t = 0;
    uint32_t w[64];
    uint32_t h[8];
    uint32_t tmp1;
    uint32_t tmp2;

    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
        0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
        0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
        0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
        0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
        0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
        0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
        0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // Message has to be processed as a big endian integer
    for (t = 0; t < 16; t++) {
        w[t] = (((
                     uint32_t) m->partial[t * 4 + 0]) << 24) | (((
                                 uint32_t) m->partial[t * 4 + 1]) << 16) | (((
                                             uint32_t) m->partial[t * 4 + 2]) << 8) | (((
                                                     uint32_t) m->partial[t * 4 + 3]) << 0);
    }

    for (t = 16; t < 64; t++) {
        w[t] = sha2_224_ssig1(w[t - 2]) + w[t - 7] + sha2_224_ssig0(
                   w[t - 15]) + w[t - 16];
    }

    // Duplicate state into temporary variables
    h[0] = m->h[0];
    h[1] = m->h[1];
    h[2] = m->h[2];
    h[3] = m->h[3];
    h[4] = m->h[4];
    h[5] = m->h[5];
    h[6] = m->h[6];
    h[7] = m->h[7];

    for (t = 0; t < 64; t++) {
        tmp1 = h[7] + sha2_224_bsig1(h[4]) + sha2_224_ch(h[4], h[5],
                h[6]) + K[t] + w[t];
        tmp2 = sha2_224_bsig0(h[0]) + sha2_224_mj(h[0], h[1], h[2]);

        h[7] = h[6];
        h[6] = h[5];
        h[5] = h[4];
        h[4] = h[3] + tmp1;
        h[3] = h[2];
        h[2] = h[1];
        h[1] = h[0];
        h[0] = tmp1 + tmp2;
    }

    // Add temporary variables back into state.
    m->h[0] += h[0];
    m->h[1] += h[1];
    m->h[2] += h[2];
    m->h[3] += h[3];
    m->h[4] += h[4];
    m->h[5] += h[5];
    m->h[6] += h[6];
    m->h[7] += h[7];
}

extern inline void sha2_224_init(struct sha2_224* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 28; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->h[0] = 0xc1059ed8;
    m->h[1] = 0x367cd507;
    m->h[2] = 0x3070dd17;
    m->h[3] = 0xf70e5939;
    m->h[4] = 0xffc00b31;
    m->h[5] = 0x68581511;
    m->h[6] = 0x64f98fa7;
    m->h[7] = 0xbefa4fa4;

    m->len = 0;
    m->p_len = 0;
}

extern inline void sha2_224_update(struct sha2_224* m, char* msg,
                                   uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;
            sha2_224_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void sha2_224_finalize(struct sha2_224* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha2_224_core(m);
    } else {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;
    }

    for (; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0x00;
    }

    // Bytes to bits
    m->len *= 8;

    // Little endian representation of m->len
    m->partial[56] = (uint8_t) (m->len >> 56);
    m->partial[57] = (uint8_t) (m->len >> 48);
    m->partial[58] = (uint8_t) (m->len >> 40);
    m->partial[59] = (uint8_t) (m->len >> 32);
    m->partial[60] = (uint8_t) (m->len >> 24);
    m->partial[61] = (uint8_t) (m->len >> 16);
    m->partial[62] = (uint8_t) (m->len >>  8);
    m->partial[63] = (uint8_t) (m->len >>  0);

    sha2_224_core(m);

    for (m->p_len = 0; m->p_len < 7; m->p_len++) {
        m->digest[(m->p_len * 4) + 0] = (uint8_t) (m->h[m->p_len] >> 24);
        m->digest[(m->p_len * 4) + 1] = (uint8_t) (m->h[m->p_len] >> 16);
        m->digest[(m->p_len * 4) + 2] = (uint8_t) (m->h[m->p_len] >> 8);
        m->digest[(m->p_len * 4) + 3] = (uint8_t) (m->h[m->p_len] >> 0);
    }

    m->p_len = 0;
}

/*
 * sha2_224 sha2_224_sum
 *
 * Computes the sha2_224 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha2_224_sum(struct sha2_224* m, char* msg)
{
    sha2_224_init(m);
    sha2_224_update(m, msg, strlen(msg));
    sha2_224_finalize(m);
    return m->digest;
}

#endif // CC_sha2_224_H
