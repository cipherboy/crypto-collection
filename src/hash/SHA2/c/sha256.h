/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha256 hash algorithm per RFC 1321. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha256 m;
 *     sha256_init(&m);
 *     sha256_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha256_sum returns the resulting sha256 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha256 m;
 *     sha256_init(&m);
 *     sha256_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha256_finalize(&m);
*/

#pragma once
#ifndef CC_sha256_H
#define CC_sha256_H

#include "stdint.h"
#include "string.h"

struct sha256 {
    uint8_t digest[32];

    uint32_t h[5];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

extern inline uint32_t sha256_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

extern inline uint32_t sha256_rotr32(uint32_t data, uint32_t count)
{
    return ((data << (32 - count)) | (data >> count));
}

extern inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

extern inline uint32_t sha256_mj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

extern inline uint32_t sha256_bsig0(uint32_t x)
{
    return sha256_rotr32(x, 2) ^ sha256_rotr32(x, 13) ^ sha256_rotr32(x, 22);
}

extern inline uint32_t sha256_bsig1(uint32_t x)
{
    return sha256_rotr32(x, 6) ^ sha256_rotr32(x, 11) ^ sha256_rotr32(x, 25);
}

extern inline uint32_t sha256_ssig0(uint32_t x)
{
    return sha256_rotr32(x, 7) ^ sha256_rotr32(x, 18) ^ (x >> 3);
}

extern inline uint32_t sha256_ssig1(uint32_t x)
{
    return sha256_rotr32(x, 17) ^ sha256_rotr32(x, 19) ^ (x >> 11);
}

extern inline void sha256_core(struct sha256* m)
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


    // Duplicate state into temporary variables
    h[0] = m->h[0];
    h[1] = m->h[1];
    h[2] = m->h[2];
    h[3] = m->h[3];
    h[4] = m->h[4];

    // Add temporary variables back into state.
    m->h[0] += h[0];
    m->h[1] += h[1];
    m->h[2] += h[2];
    m->h[3] += h[3];
    m->h[4] += h[4];
}

extern inline void sha256_init(struct sha256* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 32; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->len = 0;
    m->p_len = 0;
}

extern inline void sha256_update(struct sha256* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;
            sha256_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void sha256_finalize(struct sha256* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha256_core(m);
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

    sha256_core(m);

    for (m->p_len = 0; m->p_len < 8; m->p_len++) {
        m->digest[(m->p_len * 4) + 0] = (uint8_t) (m->h[m->p_len] >> 24);
        m->digest[(m->p_len * 4) + 1] = (uint8_t) (m->h[m->p_len] >> 16);
        m->digest[(m->p_len * 4) + 2] = (uint8_t) (m->h[m->p_len] >> 8);
        m->digest[(m->p_len * 4) + 3] = (uint8_t) (m->h[m->p_len] >> 0);
    }

    m->p_len = 0;
}

/*
 * sha256 sha256_sum
 *
 * Computes the sha256 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha256_sum(struct sha256* m, char* msg)
{
    sha256_init(m);
    sha256_update(m, msg, strlen(msg));
    sha256_finalize(m);
    return m->digest;
}

#endif // CC_sha256_H
