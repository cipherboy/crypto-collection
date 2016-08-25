/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the md5 hash algorithm per RFC 1321. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct md5 m;
 *     md5_init(&m);
 *     md5_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, md5_sum returns the resulting md5 digest
 *
 *
 * Alternative usage:
 *
 *     struct md5 m;
 *     md5_init(&m);
 *     md5_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     md5_finalize(&m);
*/

#pragma once
#ifndef CC_MD5_H
#define CC_MD5_H

#include "stdint.h"
#include "string.h"

struct md5 {
    uint8_t digest[16];

    uint32_t s[4];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

extern inline uint32_t md5_f(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((Y ^ Z) & X) ^ Z;
}

extern inline uint32_t md5_g(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((X ^ Y) & Z) ^ Y;
}

extern inline uint32_t md5_h(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X ^ Y) ^ Z;
}

extern inline uint32_t md5_i(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (Y ^ (X | (~Z)));
}

extern inline uint32_t md5_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

extern inline void md5_core(struct md5* m)
{
    size_t i = 0;
    uint32_t x[16];
    uint32_t s[4];

    // Message has to be processed as a little endian integer
    for (i = 0; i < 16; i++) {
        x[i] = (((
                     uint32_t) m->partial[i * 4 + 3]) << 24) | (((
                                 uint32_t) m->partial[i * 4 + 2]) << 16) | (((
                                             uint32_t) m->partial[i * 4 + 1]) << 8) | (((
                                                     uint32_t) m->partial[i * 4 + 0]) << 0);
    }

    // Duplicate state into temporary variables
    s[0] = m->s[0];
    s[1] = m->s[1];
    s[2] = m->s[2];
    s[3] = m->s[3];

	// Round 1
	s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 0] + 0xd76aa478,   7);
	s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 1] + 0xe8c7b756,  12);
	s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[ 2] + 0x242070db,  17);
	s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[ 3] + 0xc1bdceee,  22);
	s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 4] + 0xf57c0faf,   7);
	s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 5] + 0x4787c62a,  12);
	s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[ 6] + 0xa8304613,  17);
	s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[ 7] + 0xfd469501,  22);
	s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 8] + 0x698098d8,   7);
	s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 9] + 0x8b44f7af,  12);
	s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[10] + 0xffff5bb1,  17);
	s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[11] + 0x895cd7be,  22);
	s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[12] + 0x6b901122,   7);
	s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[13] + 0xfd987193,  12);
	s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[14] + 0xa679438e,  17);
	s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[15] + 0x49b40821,  22);

	// Round 2
	s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 1] + 0xf61e2562,   5);
	s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[ 6] + 0xc040b340,   9);
	s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[11] + 0x265e5a51,  14);
	s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 0] + 0xe9b6c7aa,  20);
	s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 5] + 0xd62f105d,   5);
	s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[10] + 0x02441453,   9);
	s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[15] + 0xd8a1e681,  14);
	s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 4] + 0xe7d3fbc8,  20);
	s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 9] + 0x21e1cde6,   5);
	s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[14] + 0xc33707d6,   9);
	s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[ 3] + 0xf4d50d87,  14);
	s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 8] + 0x455a14ed,  20);
	s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[13] + 0xa9e3e905,   5);
	s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[ 2] + 0xfcefa3f8,   9);
	s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[ 7] + 0x676f02d9,  14);
	s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[12] + 0x8d2a4c8a,  20);

	// Round 3
	s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 5] + 0xfffa3942,   4);
	s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 8] + 0x8771f681,  11);
	s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[11] + 0x6d9d6122,  16);
	s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[14] + 0xfde5380c,  23);
	s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 1] + 0xa4beea44,   4);
	s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 4] + 0x4bdecfa9,  11);
	s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[ 7] + 0xf6bb4b60,  16);
	s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[10] + 0xbebfbc70,  23);
	s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[13] + 0x289b7ec6,   4);
	s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 0] + 0xeaa127fa,  11);
	s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[ 3] + 0xd4ef3085,  16);
	s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[ 6] + 0x04881d05,  23);
	s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 9] + 0xd9d4d039,   4);
	s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[12] + 0xe6db99e5,  11);
	s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[15] + 0x1fa27cf8,  16);
	s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[ 2] + 0xc4ac5665,  23);

	// Round 4
	s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 0] + 0xf4292244,   6);
	s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[ 7] + 0x432aff97,  10);
	s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[14] + 0xab9423a7,  15);
	s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 5] + 0xfc93a039,  21);
	s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[12] + 0x655b59c3,   6);
	s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[ 3] + 0x8f0ccc92,  10);
	s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[10] + 0xffeff47d,  15);
	s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 1] + 0x85845dd1,  21);
	s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 8] + 0x6fa87e4f,   6);
	s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[15] + 0xfe2ce6e0,  10);
	s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[ 6] + 0xa3014314,  15);
	s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[13] + 0x4e0811a1,  21);
	s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 4] + 0xf7537e82,   6);
	s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[11] + 0xbd3af235,  10);
	s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[ 2] + 0x2ad7d2bb,  15);
	s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 9] + 0xeb86d391,  21);

    // Add temporary variables back into state.
    m->s[0] += s[0];
    m->s[1] += s[1];
    m->s[2] += s[2];
    m->s[3] += s[3];
}

extern inline void md5_init(struct md5* m)
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

extern inline void md5_update(struct md5* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;
            md5_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void md5_finalize(struct md5* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        md5_core(m);
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

    md5_core(m);

    for (m->p_len = 0; m->p_len < 4; m->p_len++) {
        m->digest[(m->p_len * 4) + 0] = (uint8_t) (m->s[m->p_len] >> 0);
        m->digest[(m->p_len * 4) + 1] = (uint8_t) (m->s[m->p_len] >> 8);
        m->digest[(m->p_len * 4) + 2] = (uint8_t) (m->s[m->p_len] >> 16);
        m->digest[(m->p_len * 4) + 3] = (uint8_t) (m->s[m->p_len] >> 24);
    }

    m->p_len = 0;
}

/*
 * md5 md5_sum
 *
 * Computes the md5 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* md5_sum(struct md5* m, char* msg)
{
    md5_init(m);
    md5_update(m, msg, strlen(msg));
    md5_finalize(m);
    return m->digest;
}

#endif // CC_MD5_H
