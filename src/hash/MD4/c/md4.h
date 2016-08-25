/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the md4 hash algorithm per RFC 1186. See docs for the
 * specification.
**/

#pragma once
#ifndef CC_MD4_H
#define CC_MD4_H

#include "stdint.h"
#include "string.h"
#include "stdio.h"

typedef struct {
    uint8_t digest[16];

    uint32_t s[4];
    uint64_t len;

    uint8_t partial[64];
    uint64_t p_len;
} md4;

static inline uint32_t md4_f(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((Y ^ Z) & X) ^ Z;
}

static inline uint32_t md4_g(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Y) | (X & Z) | (Y & Z);
}

static inline uint32_t md4_h(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X ^ Y) ^ Z;
}

static inline uint32_t rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

static inline void md4_core(md4* m)
{
    int i = 0;
    uint32_t x[16];
    uint32_t s[4];

    for (i = 0; i < 16; i++) {
        x[i] = (((
                     uint32_t) m->partial[i*4 + 3]) << 24) | (((
                                 uint32_t) m->partial[i*4 + 2]) << 16) | (((
                                             uint32_t) m->partial[i*4 + 1]) << 8) | (((
                                                     uint32_t) m->partial[i*4 + 0]) << 0);
    }

    // Duplicate state
    s[0] = m->s[0];
    s[1] = m->s[1];
    s[2] = m->s[2];
    s[3] = m->s[3];

    // Round 1
    s[0] = rotl32(s[0]+md4_f(s[1], s[2], s[3])+x[0], 3);
    s[3] = rotl32(s[3]+md4_f(s[0], s[1], s[2])+x[1], 7);
    s[2] = rotl32(s[2]+md4_f(s[3], s[0], s[1])+x[2], 11);
    s[1] = rotl32(s[1]+md4_f(s[2], s[3], s[0])+x[3], 19);
    s[0] = rotl32(s[0]+md4_f(s[1], s[2], s[3])+x[4], 3);
    s[3] = rotl32(s[3]+md4_f(s[0], s[1], s[2])+x[5], 7);
    s[2] = rotl32(s[2]+md4_f(s[3], s[0], s[1])+x[6], 11);
    s[1] = rotl32(s[1]+md4_f(s[2], s[3], s[0])+x[7], 19);
    s[0] = rotl32(s[0]+md4_f(s[1], s[2], s[3])+x[8], 3);
    s[3] = rotl32(s[3]+md4_f(s[0], s[1], s[2])+x[9], 7);
    s[2] = rotl32(s[2]+md4_f(s[3], s[0], s[1])+x[10], 11);
    s[1] = rotl32(s[1]+md4_f(s[2], s[3], s[0])+x[11], 19);
    s[0] = rotl32(s[0]+md4_f(s[1], s[2], s[3])+x[12], 3);
    s[3] = rotl32(s[3]+md4_f(s[0], s[1], s[2])+x[13], 7);
    s[2] = rotl32(s[2]+md4_f(s[3], s[0], s[1])+x[14], 11);
    s[1] = rotl32(s[1]+md4_f(s[2], s[3], s[0])+x[15], 19);

    // Round 2
    s[0] = rotl32(s[0]+md4_g(s[1], s[2], s[3])+x[0]+0x5A827999, 3);
    s[3] = rotl32(s[3]+md4_g(s[0], s[1], s[2])+x[4]+0x5A827999, 5);
    s[2] = rotl32(s[2]+md4_g(s[3], s[0], s[1])+x[8]+0x5A827999, 9);
    s[1] = rotl32(s[1]+md4_g(s[2], s[3], s[0])+x[12]+0x5A827999, 13);
    s[0] = rotl32(s[0]+md4_g(s[1], s[2], s[3])+x[1]+0x5A827999, 3);
    s[3] = rotl32(s[3]+md4_g(s[0], s[1], s[2])+x[5]+0x5A827999, 5);
    s[2] = rotl32(s[2]+md4_g(s[3], s[0], s[1])+x[9]+0x5A827999, 9);
    s[1] = rotl32(s[1]+md4_g(s[2], s[3], s[0])+x[13]+0x5A827999, 13);
    s[0] = rotl32(s[0]+md4_g(s[1], s[2], s[3])+x[2]+0x5A827999, 3);
    s[3] = rotl32(s[3]+md4_g(s[0], s[1], s[2])+x[6]+0x5A827999, 5);
    s[2] = rotl32(s[2]+md4_g(s[3], s[0], s[1])+x[10]+0x5A827999, 9);
    s[1] = rotl32(s[1]+md4_g(s[2], s[3], s[0])+x[14]+0x5A827999, 13);
    s[0] = rotl32(s[0]+md4_g(s[1], s[2], s[3])+x[3]+0x5A827999, 3);
    s[3] = rotl32(s[3]+md4_g(s[0], s[1], s[2])+x[7]+0x5A827999, 5);
    s[2] = rotl32(s[2]+md4_g(s[3], s[0], s[1])+x[11]+0x5A827999, 9);
    s[1] = rotl32(s[1]+md4_g(s[2], s[3], s[0])+x[15]+0x5A827999, 13);

    // Round 3
    s[0] = rotl32(s[0]+md4_h(s[1], s[2], s[3])+x[0]+0x6ED9EBA1, 3);
    s[3] = rotl32(s[3]+md4_h(s[0], s[1], s[2])+x[8]+0x6ED9EBA1, 9);
    s[2] = rotl32(s[2]+md4_h(s[3], s[0], s[1])+x[4]+0x6ED9EBA1, 11);
    s[1] = rotl32(s[1]+md4_h(s[2], s[3], s[0])+x[12]+0x6ED9EBA1, 15);
    s[0] = rotl32(s[0]+md4_h(s[1], s[2], s[3])+x[2]+0x6ED9EBA1, 3);
    s[3] = rotl32(s[3]+md4_h(s[0], s[1], s[2])+x[10]+0x6ED9EBA1, 9);
    s[2] = rotl32(s[2]+md4_h(s[3], s[0], s[1])+x[6]+0x6ED9EBA1, 11);
    s[1] = rotl32(s[1]+md4_h(s[2], s[3], s[0])+x[14]+0x6ED9EBA1, 15);
    s[0] = rotl32(s[0]+md4_h(s[1], s[2], s[3])+x[1]+0x6ED9EBA1, 3);
    s[3] = rotl32(s[3]+md4_h(s[0], s[1], s[2])+x[9]+0x6ED9EBA1, 9);
    s[2] = rotl32(s[2]+md4_h(s[3], s[0], s[1])+x[5]+0x6ED9EBA1, 11);
    s[1] = rotl32(s[1]+md4_h(s[2], s[3], s[0])+x[13]+0x6ED9EBA1, 15);
    s[0] = rotl32(s[0]+md4_h(s[1], s[2], s[3])+x[3]+0x6ED9EBA1, 3);
    s[3] = rotl32(s[3]+md4_h(s[0], s[1], s[2])+x[11]+0x6ED9EBA1, 9);
    s[2] = rotl32(s[2]+md4_h(s[3], s[0], s[1])+x[7]+0x6ED9EBA1, 11);
    s[1] = rotl32(s[1]+md4_h(s[2], s[3], s[0])+x[15]+0x6ED9EBA1, 15);

    // Add back to md4 state.
    m->s[0] += s[0];
    m->s[1] += s[1];
    m->s[2] += s[2];
    m->s[3] += s[3];
}

extern inline void md4_init(md4* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 16; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->s[0] = 0x67452301;
    m->s[1] = 0xEFCDAB89;
    m->s[2] = 0x98BADCFE;
    m->s[3] = 0x10325476;

    m->len = 0;
    m->p_len = 0;
}

extern inline void md4_update(md4* m, char* msg, uint64_t len)
{
    int i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;
            md4_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void md4_finalize(md4* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        md4_core(m);
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
    m->partial[56] = (uint8_t) (m->len >> 0);
    m->partial[57] = (uint8_t) (m->len >> 8);
    m->partial[58] = (uint8_t) (m->len >> 16);
    m->partial[59] = (uint8_t) (m->len >> 24);
    m->partial[60] = (uint8_t) (m->len >> 32);
    m->partial[61] = (uint8_t) (m->len >> 40);
    m->partial[62] = (uint8_t) (m->len >> 48);
    m->partial[63] = (uint8_t) (m->len >> 56);

    md4_core(m);

    for (m->p_len = 0; m->p_len < 4; m->p_len++) {
        m->digest[(m->p_len*4)+0] = (uint8_t) (m->s[m->p_len] >> 0);
        m->digest[(m->p_len*4)+1] = (uint8_t) (m->s[m->p_len] >> 8);
        m->digest[(m->p_len*4)+2] = (uint8_t) (m->s[m->p_len] >> 16);
        m->digest[(m->p_len*4)+3] = (uint8_t) (m->s[m->p_len] >> 24);
    }

    m->p_len = 0;
}

extern inline uint8_t* md4_sum(md4* m, char* msg)
{
    md4_init(m);
    md4_update(m, msg, strlen(msg));
    md4_finalize(m);
    return m->digest;
}

#endif // CC_MD4_H
