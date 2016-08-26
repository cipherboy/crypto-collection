/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha1 hash algorithm per RFC 1321. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha1 m;
 *     sha1_init(&m);
 *     sha1_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha1_sum returns the resulting sha1 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha1 m;
 *     sha1_init(&m);
 *     sha1_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha1_finalize(&m);
*/

#pragma once
#ifndef CC_sha1_H
#define CC_sha1_H

#include "stdint.h"
#include "string.h"

struct sha1 {
    uint8_t digest[20];

    uint32_t h[5];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

extern inline uint32_t sha1_f(size_t t, uint32_t B, uint32_t C, uint32_t D)
{
    if (t <= 19) {
        return (B & C) | ((~B) & D);
    } else if (20 <= t && t <= 39) {
        return (B ^ C) ^ D;
    } else if (40 <= t && t <= 59) {
        return (B & C) | (B & D) | (C & D);
    } else {
        return (B ^ C) ^ D;
    }
}

extern inline uint32_t sha1_k(size_t t)
{
    if (t <= 19) {
        return 0x5A827999;
    } else if (20 <= t && t <= 39) {
        return 0x6ED9EBA1;
    } else if (40 <= t && t <= 59) {
        return 0x8F1BBCDC;
    } else {
        return 0xCA62C1D6;
    }
}

extern inline uint32_t sha1_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

extern inline void sha1_core(struct sha1* m)
{
    size_t t = 0;
    uint32_t w[80];
    uint32_t h[5];
    uint32_t temp;

    // Message has to be processed as a little endian integer
    for (t = 0; t < 16; t++) {
        w[t] = (((
                     uint32_t) m->partial[t * 4 + 0]) << 24) | (((
                                 uint32_t) m->partial[t * 4 + 1]) << 16) | (((
                                             uint32_t) m->partial[t * 4 + 2]) << 8) | (((
                                                     uint32_t) m->partial[t * 4 + 3]) << 0);
    }

    for (t = 16; t < 80; t++) {
        w[t] = sha1_rotl32(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }

    // Duplicate state into temporary variables
    h[0] = m->h[0];
    h[1] = m->h[1];
    h[2] = m->h[2];
    h[3] = m->h[3];
    h[4] = m->h[4];

    for (t = 0; t < 80; t++) {
        temp = sha1_rotl32(h[0], 5) + sha1_f(t, h[1], h[2],
                                             h[3]) + h[4] + w[t] + sha1_k(t);
        h[4] = h[3];
        h[3] = h[2];
        h[2] = sha1_rotl32(h[1], 30);
        h[1] = h[0];
        h[0] = temp;
    }

    // Add temporary variables back into state.
    m->h[0] += h[0];
    m->h[1] += h[1];
    m->h[2] += h[2];
    m->h[3] += h[3];
    m->h[4] += h[4];
}

extern inline void sha1_init(struct sha1* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 20; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->h[0] = 0x67452301;
    m->h[1] = 0xEFCDAB89;
    m->h[2] = 0x98BADCFE;
    m->h[3] = 0x10325476;
    m->h[4] = 0xC3D2E1F0;

    m->len = 0;
    m->p_len = 0;
}

extern inline void sha1_update(struct sha1* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;
            sha1_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void sha1_finalize(struct sha1* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha1_core(m);
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

    sha1_core(m);

    for (m->p_len = 0; m->p_len < 5; m->p_len++) {
        m->digest[(m->p_len * 4) + 0] = (uint8_t) (m->h[m->p_len] >> 24);
        m->digest[(m->p_len * 4) + 1] = (uint8_t) (m->h[m->p_len] >> 16);
        m->digest[(m->p_len * 4) + 2] = (uint8_t) (m->h[m->p_len] >> 8);
        m->digest[(m->p_len * 4) + 3] = (uint8_t) (m->h[m->p_len] >> 0);
    }

    m->p_len = 0;
}

/*
 * sha1 sha1_sum
 *
 * Computes the sha1 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha1_sum(struct sha1* m, char* msg)
{
    sha1_init(m);
    sha1_update(m, msg, strlen(msg));
    sha1_finalize(m);
    return m->digest;
}

#endif // CC_sha1_H
