/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha2_512 hash algorithm per RFC 1321. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha2_512 m;
 *     sha2_512_init(&m);
 *     sha2_512_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha2_512_sum returns the resulting sha2_512 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha2_512 m;
 *     sha2_512_init(&m);
 *     sha2_512_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha2_512_finalize(&m);
*/

#pragma once
#ifndef CC_SHA2_512_H
#define CC_SHA2_512_H

#include "stdint.h"
#include "string.h"

struct sha2_512 {
    uint8_t digest[64];

    uint64_t h[8];
    uint64_t len;

    uint8_t partial[128];
    size_t p_len;
};

extern inline uint64_t sha2_512_rotl64(uint64_t data, uint64_t count)
{
    return ((data << count) | (data >> (64 - count)));
}

extern inline uint64_t sha2_512_rotr64(uint64_t data, uint64_t count)
{
    return ((data << (64 - count)) | (data >> count));
}

extern inline uint64_t sha2_512_ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ ((~x) & z);
}

extern inline uint64_t sha2_512_mj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

extern inline uint64_t sha2_512_bsig0(uint64_t x)
{
    return sha2_512_rotr64(x, 28) ^ sha2_512_rotr64(x, 34) ^ sha2_512_rotr64(x,
            39);
}

extern inline uint64_t sha2_512_bsig1(uint64_t x)
{
    return sha2_512_rotr64(x, 14) ^ sha2_512_rotr64(x, 18) ^ sha2_512_rotr64(x,
            41);
}

extern inline uint64_t sha2_512_ssig0(uint64_t x)
{
    return sha2_512_rotr64(x, 1) ^ sha2_512_rotr64(x, 8) ^ (x >> 7);
}

extern inline uint64_t sha2_512_ssig1(uint64_t x)
{
    return sha2_512_rotr64(x, 19) ^ sha2_512_rotr64(x, 61) ^ (x >> 6);
}

extern inline void sha2_512_core(struct sha2_512* m)
{
    size_t t = 0;
    uint64_t w[80];
    uint64_t h[8];
    uint64_t tmp1;
    uint64_t tmp2;

    static const uint64_t K[80] = {
        0x428A2F98D728AE22ll, 0x7137449123EF65CDll, 0xB5C0FBCFEC4D3B2Fll,
        0xE9B5DBA58189DBBCll, 0x3956C25BF348B538ll, 0x59F111F1B605D019ll,
        0x923F82A4AF194F9Bll, 0xAB1C5ED5DA6D8118ll, 0xD807AA98A3030242ll,
        0x12835B0145706FBEll, 0x243185BE4EE4B28Cll, 0x550C7DC3D5FFB4E2ll,
        0x72BE5D74F27B896Fll, 0x80DEB1FE3B1696B1ll, 0x9BDC06A725C71235ll,
        0xC19BF174CF692694ll, 0xE49B69C19EF14AD2ll, 0xEFBE4786384F25E3ll,
        0x0FC19DC68B8CD5B5ll, 0x240CA1CC77AC9C65ll, 0x2DE92C6F592B0275ll,
        0x4A7484AA6EA6E483ll, 0x5CB0A9DCBD41FBD4ll, 0x76F988DA831153B5ll,
        0x983E5152EE66DFABll, 0xA831C66D2DB43210ll, 0xB00327C898FB213Fll,
        0xBF597FC7BEEF0EE4ll, 0xC6E00BF33DA88FC2ll, 0xD5A79147930AA725ll,
        0x06CA6351E003826Fll, 0x142929670A0E6E70ll, 0x27B70A8546D22FFCll,
        0x2E1B21385C26C926ll, 0x4D2C6DFC5AC42AEDll, 0x53380D139D95B3DFll,
        0x650A73548BAF63DEll, 0x766A0ABB3C77B2A8ll, 0x81C2C92E47EDAEE6ll,
        0x92722C851482353Bll, 0xA2BFE8A14CF10364ll, 0xA81A664BBC423001ll,
        0xC24B8B70D0F89791ll, 0xC76C51A30654BE30ll, 0xD192E819D6EF5218ll,
        0xD69906245565A910ll, 0xF40E35855771202All, 0x106AA07032BBD1B8ll,
        0x19A4C116B8D2D0C8ll, 0x1E376C085141AB53ll, 0x2748774CDF8EEB99ll,
        0x34B0BCB5E19B48A8ll, 0x391C0CB3C5C95A63ll, 0x4ED8AA4AE3418ACBll,
        0x5B9CCA4F7763E373ll, 0x682E6FF3D6B2B8A3ll, 0x748F82EE5DEFB2FCll,
        0x78A5636F43172F60ll, 0x84C87814A1F0AB72ll, 0x8CC702081A6439ECll,
        0x90BEFFFA23631E28ll, 0xA4506CEBDE82BDE9ll, 0xBEF9A3F7B2C67915ll,
        0xC67178F2E372532Bll, 0xCA273ECEEA26619Cll, 0xD186B8C721C0C207ll,
        0xEADA7DD6CDE0EB1Ell, 0xF57D4F7FEE6ED178ll, 0x06F067AA72176FBAll,
        0x0A637DC5A2C898A6ll, 0x113F9804BEF90DAEll, 0x1B710B35131C471Bll,
        0x28DB77F523047D84ll, 0x32CAAB7B40C72493ll, 0x3C9EBE0A15C9BEBCll,
        0x431D67C49C100D4Cll, 0x4CC5D4BECB3E42B6ll, 0x597F299CFC657E2All,
        0x5FCB6FAB3AD6FAECll, 0x6C44198C4A475817ll
    };

    // Message has to be processed as a big endian integer
    for (t = 0; t < 16; t++) {
        w[t] = (((
                     uint64_t) m->partial[t * 8 + 0]) << 56) | (((
                                 uint64_t) m->partial[t * 8 + 1]) << 48) | (((
                                             uint64_t) m->partial[t * 8 + 2]) << 40) | (((
                                                     uint64_t) m->partial[t * 8 + 3]) << 32) | (((
                                                             uint64_t) m->partial[t * 8 + 4]) << 24) | (((
                                                                     uint64_t) m->partial[t * 8 + 5]) << 16) | (((
                                                                             uint64_t) m->partial[t * 8 + 6]) << 8) | (((
                                                                                     uint64_t) m->partial[t * 8 + 7]) << 0);
    }

    for (t = 16; t < 80; t++) {
        w[t] = sha2_512_ssig1(w[t - 2]) + w[t - 7] + sha2_512_ssig0(
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

    for (t = 0; t < 80; t++) {
        tmp1 = h[7] + sha2_512_bsig1(h[4]) + sha2_512_ch(h[4], h[5],
                h[6]) + K[t] + w[t];
        tmp2 = sha2_512_bsig0(h[0]) + sha2_512_mj(h[0], h[1], h[2]);

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

extern inline void sha2_512_init(struct sha2_512* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 128; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->h[0] = 0x6a09e667f3bcc908ll;
    m->h[1] = 0xbb67ae8584caa73bll;
    m->h[2] = 0x3c6ef372fe94f82bll;
    m->h[3] = 0xa54ff53a5f1d36f1ll;
    m->h[4] = 0x510e527fade682d1ll;
    m->h[5] = 0x9b05688c2b3e6c1fll;
    m->h[6] = 0x1f83d9abfb41bd6bll;
    m->h[7] = 0x5be0cd19137e2179ll;

    m->len = 0;
    m->p_len = 0;
}

extern inline void sha2_512_update(struct sha2_512* m, char* msg,
                                   uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 128) {
            m->p_len = 0;
            sha2_512_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

extern inline void sha2_512_finalize(struct sha2_512* m)
{
    if (m->p_len > 119) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 128; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha2_512_core(m);
    } else {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;
    }

    for (; m->p_len < 128; m->p_len++) {
        m->partial[m->p_len] = 0x00;
    }

    // Bytes to bits
    m->len *= 8;

    // Little endian representation of m->len
    m->partial[120] = (uint8_t) (m->len >> 56);
    m->partial[121] = (uint8_t) (m->len >> 48);
    m->partial[122] = (uint8_t) (m->len >> 40);
    m->partial[123] = (uint8_t) (m->len >> 32);
    m->partial[124] = (uint8_t) (m->len >> 24);
    m->partial[125] = (uint8_t) (m->len >> 16);
    m->partial[126] = (uint8_t) (m->len >>  8);
    m->partial[127] = (uint8_t) (m->len >>  0);

    sha2_512_core(m);

    for (m->p_len = 0; m->p_len < 8; m->p_len++) {
        m->digest[(m->p_len * 8) + 0] = (uint8_t) (m->h[m->p_len] >> 56);
        m->digest[(m->p_len * 8) + 1] = (uint8_t) (m->h[m->p_len] >> 48);
        m->digest[(m->p_len * 8) + 2] = (uint8_t) (m->h[m->p_len] >> 42);
        m->digest[(m->p_len * 8) + 3] = (uint8_t) (m->h[m->p_len] >> 32);
        m->digest[(m->p_len * 8) + 4] = (uint8_t) (m->h[m->p_len] >> 24);
        m->digest[(m->p_len * 8) + 5] = (uint8_t) (m->h[m->p_len] >> 16);
        m->digest[(m->p_len * 8) + 6] = (uint8_t) (m->h[m->p_len] >> 8);
        m->digest[(m->p_len * 8) + 7] = (uint8_t) (m->h[m->p_len] >> 0);
    }

    m->p_len = 0;
}

/*
 * sha2_512 sha2_512_sum
 *
 * Computes the sha2_512 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha2_512_sum(struct sha2_512* m, char* msg)
{
    sha2_512_init(m);
    sha2_512_update(m, msg, strlen(msg));
    sha2_512_finalize(m);
    return m->digest;
}

#endif // CC_sha2_512_H
