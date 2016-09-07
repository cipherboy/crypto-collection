/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha2_384 hash algorithm per RFC 4634. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha2_384 m;
 *     sha2_384_init(&m);
 *     sha2_384_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha2_384_sum returns the resulting sha2_384 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha2_384 m;
 *     sha2_384_init(&m);
 *     sha2_384_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha2_384_finalize(&m);
*/

#pragma once
#ifndef CC_SHA2_384_H
#define CC_SHA2_384_H

#include "stdint.h"
#include "string.h"

/*
 * struct sha2_384
 *
 * uint8_t digest[48]   -- public; digest after finalization
 *
 * uint64_t h[8]        -- internal; hash state variables
 * uint64_t len         -- internal; length of input
 * uint8_t partial[128] -- internal; partial block of input
 * size_t p_len         -- internal; length of partial block
*/
struct sha2_384 {
    uint8_t digest[48];

    uint64_t h[8];
    uint64_t len;

    uint8_t partial[128];
    size_t p_len;
};

/*
 * sha2_384 sha2_384_rotl64
 *
 * The rotate left (circular left shift) operation ROTL^n(x), where
 * x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTL^n(X) = (x<<n) OR (x>>w-n)
*/
extern inline uint64_t sha2_384_rotl64(uint64_t data, uint64_t count)
{
    return ((data << count) | (data >> (64 - count)));
}

/*
 * sha2_384 sha2_384_rotr64
 *
 * The rotate right (circular right shift) operation ROTR^n(x),
 * where x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTR^n(x) = (x>>n) OR (x<<(w-n))
*/
extern inline uint64_t sha2_384_rotr64(uint64_t data, uint64_t count)
{
    return ((data << (64 - count)) | (data >> count));
}

/*
 * sha2_384 sha2_384_ch
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
*/
extern inline uint64_t sha2_384_ch(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ ((~x) & z);
}

/*
 * sha2_384 sha2_384_mj
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
*/
extern inline uint64_t sha2_384_mj(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/*
 * sha2_384 sha2_384_bsig0
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)
*/
extern inline uint64_t sha2_384_bsig0(uint64_t x)
{
    return sha2_384_rotr64(x, 28) ^ sha2_384_rotr64(x, 34) ^ sha2_384_rotr64(x,
            39);
}

/*
 * sha2_384 sha2_384_bsig1
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)
*/
extern inline uint64_t sha2_384_bsig1(uint64_t x)
{
    return sha2_384_rotr64(x, 14) ^ sha2_384_rotr64(x, 18) ^ sha2_384_rotr64(x,
            41);
}

/*
 * sha2_384 sha2_384_ssig0
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)
*/
extern inline uint64_t sha2_384_ssig0(uint64_t x)
{
    return sha2_384_rotr64(x, 1) ^ sha2_384_rotr64(x, 8) ^ (x >> 7);
}

/*
 * sha2_384 sha2_384_ssig1
 *
 * SHA-384 and SHA-512 each use six logical functions, where each
 * function operates on 64-bit words, which are represented as x, y, and
 * z.  The result of each function is a new 64-bit word.
 *
 * SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)
*/
extern inline uint64_t sha2_384_ssig1(uint64_t x)
{
    return sha2_384_rotr64(x, 19) ^ sha2_384_rotr64(x, 61) ^ (x >> 6);
}

/*
 * sha2_384 sha2_384_core
 *
 * Core of sha2_384 hash function; operates on a single round from m->partial
 * and updates hash state in m->s.
 * SHA-384 and SHA-512 perform identical processing on message blocks
 * and differ only in how H(0) is initialized and how they produce their
 * final output.  They may be used to hash a message, M, having a length
 * of L bits, where 0 <= L < 2^128.  The algorithm uses (1) a message
 * schedule of eighty 64-bit words, (2) eight working variables of 64
 * bits each, and (3) a hash value of eight 64-bit words.

 * The words of the message schedule are labeled W0, W1, ..., W79.  The
 * eight working variables are labeled a, b, c, d, e, f, g, and h.  The
 * words of the hash value are labeled H(i)0, H(i)1, ..., H(i)7, which
 * will hold the initial hash value, H(0), replaced by each successive
 * intermediate hash value (after each message block is processed),
 * H(i), and ending with the final hash value, H(N) after all N blocks
 * are processed.

 * The input message is padded as described in Section 4.2 above, then
 * parsed into 1024-bit blocks, which are considered to be composed of
 * 16 64-bit words M(i)0, M(i)1, ..., M(i)15.  The following
 * computations are then performed for each of the N message blocks.
 * All addition is performed modulo 2^64.
 *
 *     For i = 1 to N
 *       1. Prepare the message schedule W:
 *          For t = 0 to 15
 *             Wt = M(i)t
 *          For t = 16 to 79
 *             Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(t-15) + W(t-16)
 *
 *       2. Initialize the working variables:
 *          a = H(i-1)0
 *          b = H(i-1)1
 *          c = H(i-1)2
 *          d = H(i-1)3
 *          e = H(i-1)4
 *          f = H(i-1)5
 *          g = H(i-1)6
 *          h = H(i-1)7
 *
 *       3. Perform the main hash computation:
 *          For t = 0 to 79
 *             T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
 *             T2 = BSIG0(a) + MAJ(a,b,c)
 *             h = g
 *             g = f
 *             f = e
 *             e = d + T1
 *             d = c
 *             c = b
 *             b = a
 *             a = T1 + T2
 *
 *       4. Compute the intermediate hash value H(i):
 *          H(i)0 = a + H(i-1)0
 *          H(i)1 = b + H(i-1)1
 *          H(i)2 = c + H(i-1)2
 *          H(i)3 = d + H(i-1)3
 *          H(i)4 = e + H(i-1)4
 *          H(i)5 = f + H(i-1)5
 *          H(i)6 = g + H(i-1)6
 *          H(i)7 = h + H(i-1)7
 *
 * After the above computations have been sequentially performed for all
 * of the blocks in the message, the final output is calculated.  For
 * SHA-512, this is the concatenation of all of H(N)0, H(N)1, through
 * H(N)7.  For SHA-384, this is the concatenation of H(N)0, H(N)1,
 * through H(N)5.
*/
extern inline void sha2_384_core(struct sha2_384* m)
{
    size_t t = 0;
    uint64_t w[80];
    uint64_t h[8];
    uint64_t tmp1;
    uint64_t tmp2;

    /*
     * SHA-384 and SHA-512 use the same sequence of eighty constant 64-bit
     * words, K0, K1, ... K79.  These words represent the first sixty-four
     * bits of the fractional parts of the cube roots of the first eighty
     * prime numbers.  In hex, these constant words are as follows (from
     * left to right):
     *
     * 428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
     * 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
     * d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
     * 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
     * e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
     * 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
     * 983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
     * c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
     * 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
     * 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
     * a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
     * d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
     * 19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
     * 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
     * 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
     * 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
     * ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
     * 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
     * 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
     * 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
    */
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
        w[t] = sha2_384_ssig1(w[t - 2]) + w[t - 7] + sha2_384_ssig0(
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
        tmp1 = h[7] + sha2_384_bsig1(h[4]) + sha2_384_ch(h[4], h[5],
                h[6]) + K[t] + w[t];
        tmp2 = sha2_384_bsig0(h[0]) + sha2_384_mj(h[0], h[1], h[2]);

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

/*
 * sha2_384 sha2_384_init
 *
 * Initializes sha2_384 struct with initial state seed, empties partial and digest
 *
 * For SHA-384, the initial hash value, H(0), consists of the following
 * eight 64-bit words, in hex.  These words were obtained by taking the
 * first sixty-four bits of the fractional parts of the square roots of
 * the ninth through sixteenth prime numbers.
 *
 *     H(0)0 = cbbb9d5dc1059ed8
 *     H(0)1 = 629a292a367cd507
 *     H(0)2 = 9159015a3070dd17
 *     H(0)3 = 152fecd8f70e5939
 *     H(0)4 = 67332667ffc00b31
 *     H(0)5 = 8eb44a8768581511
 *     H(0)6 = db0c2e0d64f98fa7
 *     H(0)7 = 47b5481dbefa4fa4
*/
extern inline void sha2_384_init(struct sha2_384* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 48; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 128; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->h[0] = 0xcbbb9d5dc1059ed8ll;
    m->h[1] = 0x629a292a367cd507ll;
    m->h[2] = 0x9159015a3070dd17ll;
    m->h[3] = 0x152fecd8f70e5939ll;
    m->h[4] = 0x67332667ffc00b31ll;
    m->h[5] = 0x8eb44a8768581511ll;
    m->h[6] = 0xdb0c2e0d64f98fa7ll;
    m->h[7] = 0x47b5481dbefa4fa4ll;

    m->len = 0;
    m->p_len = 0;
}

/*
 * sha2_384 sha2_384_update
 *
 * Updates the state of the sha2_384 struct with new values
*/
extern inline void sha2_384_update(struct sha2_384* m, char* msg,
                                   uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 128) {
            m->p_len = 0;

            // Once we finish a buffer, call the core sha2_384 function to update
            // state and recompute the current hash value.
            sha2_384_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

/*
 * sha2_384 sha2_384_finalize
 *
 * Finalizes the sha2_384 structure; pads the partial block as necessary. Also
 * generates the message digest.
 *
 * Suppose a message has length L < 2^128.  Before it is input to the
 * hash function, the message is padded on the right as follows:
 *
 * a.  "1" is appended.  Example: if the original message is
 *     "01010000", this is padded to "010100001".
 *
 * b.  K "0"s are appended where K is the smallest, non-negative
 *     solution to the equation
 *
 *          L + 1 + K = 896 (mod 1024)
 *
 * c.  Then append the 128-bit block that is L in binary
 *     representation.  After appending this block, the length of the
 *     message will be a multiple of 1024 bits.
 *
 *     Example:  Suppose the original message is the bit string
 *
 *          01100001 01100010 01100011 01100100 01100101
 *
 *     After step (a) this gives
 *
 *          01100001 01100010 01100011 01100100 01100101 1
 *
 *     Since L = 40, the number of bits in the above is 41 and K = 855
 *     "0"s are appended, making the total now 896.  This gives the
 *     following in hex:
 *
 *          61626364 65800000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *
 *     The 128-bit representation of L = 40 is hex 00000000 00000000
 *     00000000 00000028.  Hence the final padded message is the
 *     following hex:
 *
 *          61626364 65800000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000028
*/
extern inline void sha2_384_finalize(struct sha2_384* m)
{
    if (m->p_len > 119) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 128; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha2_384_core(m);
    } else {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;
    }

    for (; m->p_len < 128; m->p_len++) {
        m->partial[m->p_len] = 0x00;
    }

    // Bytes to bits
    m->len *= 8;

    // Big endian representation of m->len
    m->partial[120] = (uint8_t) (m->len >> 56);
    m->partial[121] = (uint8_t) (m->len >> 48);
    m->partial[122] = (uint8_t) (m->len >> 40);
    m->partial[123] = (uint8_t) (m->len >> 32);
    m->partial[124] = (uint8_t) (m->len >> 24);
    m->partial[125] = (uint8_t) (m->len >> 16);
    m->partial[126] = (uint8_t) (m->len >>  8);
    m->partial[127] = (uint8_t) (m->len >>  0);

    sha2_384_core(m);

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
 * sha2_384 sha2_384_sum
 *
 * Computes the sha2_384 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha2_384_sum(struct sha2_384* m, char* msg)
{
    sha2_384_init(m);
    sha2_384_update(m, msg, strlen(msg));
    sha2_384_finalize(m);
    return m->digest;
}

#endif // CC_sha2_384_H
