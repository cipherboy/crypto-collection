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

struct md5 {
    uint8_t digest[16];

    uint32_t s[4];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
}

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



#endif // CC_MD5_H
