/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha2_256 hash algorithm per RFC 4634. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct sha2_256 m;
 *     sha2_256_init(&m);
 *     sha2_256_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, sha2_256_sum returns the resulting sha2_256 digest
 *
 *
 * Alternative usage:
 *
 *     struct sha2_256 m;
 *     sha2_256_init(&m);
 *     sha2_256_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     sha2_256_finalize(&m);
*/

#pragma once
#ifndef CC_SHA2_256_H
#define CC_SHA2_256_H

#include "stdint.h"
#include "string.h"

/*
 * struct sha2_256
 *
 * uint8_t digest[32]  -- public; digest after finalization
 *
 * uint32_t h[8]       -- internal; hash state variables
 * uint64_t len        -- internal; length of input
 * uint8_t partial[64] -- internal; partial block of input
 * size_t p_len        -- internal; length of partial block
*/
struct sha2_256 {
    uint8_t digest[32];

    uint32_t h[8];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

/*
 * sha2_256 sha2_256_rotl32
 *
 * The rotate left (circular left shift) operation ROTL^n(x), where
 * x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTL^n(X) = (x<<n) OR (x>>w-n)
*/
extern inline uint32_t sha2_256_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

/*
 * sha2_256 sha2_256_rotr32
 *
 * The rotate right (circular right shift) operation ROTR^n(x),
 * where x is a w-bit word and n is an integer with 0 <= n < w, is
 * defined by
 *     ROTR^n(x) = (x>>n) OR (x<<(w-n))
*/
extern inline uint32_t sha2_256_rotr32(uint32_t data, uint32_t count)
{
    return ((data << (32 - count)) | (data >> count));
}

/*
 * sha2_256 sha2_256_ch
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)
*/
extern inline uint32_t sha2_256_ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

/*
 * sha2_256 sha2_256_mj
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
*/
extern inline uint32_t sha2_256_mj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/*
 * sha2_256 sha2_256_bsig0
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
*/
extern inline uint32_t sha2_256_bsig0(uint32_t x)
{
    return sha2_256_rotr32(x, 2) ^ sha2_256_rotr32(x, 13) ^ sha2_256_rotr32(x,
            22);
}

/*
 * sha2_256 sha2_256_bsig1
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
*/
extern inline uint32_t sha2_256_bsig1(uint32_t x)
{
    return sha2_256_rotr32(x, 6) ^ sha2_256_rotr32(x, 11) ^ sha2_256_rotr32(x,
            25);
}

/*
 * sha2_256 sha2_256_ssig0
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * SSIG0(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
*/
extern inline uint32_t sha2_256_ssig0(uint32_t x)
{
    return sha2_256_rotr32(x, 7) ^ sha2_256_rotr32(x, 18) ^ (x >> 3);
}

/*
 * sha2_256 sha2_256_ssig1
 *
 * SHA-224 and SHA-256 use six logical functions, where each function
 * operates on 32-bit words, which are represented as x, y, and z. The
 * result of each function is a new 32-bit word.
 *
 * SSIG1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)
*/
extern inline uint32_t sha2_256_ssig1(uint32_t x)
{
    return sha2_256_rotr32(x, 17) ^ sha2_256_rotr32(x, 19) ^ (x >> 10);
}

/*
 * sha2_256 sha2_256_core
 *
 * Core of sha2_256 hash function; operates on a single round from m->partial
 * and updates hash state in m->s.
 *
 * SHA-224 and SHA-256 perform identical processing on messages blocks
 * and differ only in how H(0) is initialized and how they produce their
 * final output.  They may be used to hash a message, M, having a length
 * of L bits, where 0 <= L < 2^64.  The algorithm uses (1) a message
 * schedule of sixty-four 32-bit words, (2) eight working variables of
 * 32 bits each, and (3) a hash value of eight 32-bit words.
 *
 * The words of the message schedule are labeled W0, W1, ..., W63.  The
 * eight working variables are labeled a, b, c, d, e, f, g, and h.  The
 * words of the hash value are labeled H(i)0, H(i)1, ..., H(i)7, which
 * will hold the initial hash value, H(0), replaced by each successive
 * intermediate hash value (after each message block is processed),
 * H(i), and ending with the final hash value, H(N), after all N blocks
 * are processed.  They also use two temporary words, T1 and T2.
 *
 * The input message is padded as described in Section 4.1 above then
 * parsed into 512-bit blocks, which are considered to be composed of 16
 * 32-bit words M(i)0, M(i)1, ..., M(i)15.  The following computations
 * are then performed for each of the N message blocks.  All addition is
 * performed modulo 2^32.
 *
 *     For i = 1 to N
 *
 *         1. Prepare the message schedule W:
 *          For t = 0 to 15
 *             Wt = M(i)t
 *          For t = 16 to 63
 *             Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(t-15) + W(t-16)
 *
 *         2. Initialize the working variables:
 *          a = H(i-1)0
 *          b = H(i-1)1
 *          c = H(i-1)2
 *          d = H(i-1)3
 *          e = H(i-1)4
 *          f = H(i-1)5
 *          g = H(i-1)6
 *          h = H(i-1)7
 *
 *         3. Perform the main hash computation:
 *          For t = 0 to 63
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
 *         4. Compute the intermediate hash value H(i):
 *              H(i)0 = a + H(i-1)0
 *              H(i)1 = b + H(i-1)1
 *              H(i)2 = c + H(i-1)2
 *              H(i)3 = d + H(i-1)3
 *              H(i)4 = e + H(i-1)4
 *              H(i)5 = f + H(i-1)5
 *              H(i)6 = g + H(i-1)6
 *              H(i)7 = h + H(i-1)7
 *
 * After the above computations have been sequentially performed for all
 * of the blocks in the message, the final output is calculated.  For
 * SHA-256, this is the concatenation of all of H(N)0, H(N)1, through
 * H(N)7.  For SHA-224, this is the concatenation of H(N)0, H(N)1,
 * through H(N)6.
*/
extern inline void sha2_256_core(struct sha2_256* m)
{
    size_t t = 0;
    uint32_t w[64];
    uint32_t h[8];
    uint32_t tmp1;
    uint32_t tmp2;

    /*
     * SHA-224 and SHA-256 use the same sequence of sixty-four constant
     * 32-bit words, K0, K1, ..., K63.  These words represent the first
     * thirty-two bits of the fractional parts of the cube roots of the
     * first sixty-four prime numbers.  In hex, these constant words are as
     * follows (from left to right):
     *
     *     428a2f98 71374491 b5c0fbcf e9b5dba5
     *     3956c25b 59f111f1 923f82a4 ab1c5ed5
     *     d807aa98 12835b01 243185be 550c7dc3
     *     72be5d74 80deb1fe 9bdc06a7 c19bf174
     *     e49b69c1 efbe4786 0fc19dc6 240ca1cc
     *     2de92c6f 4a7484aa 5cb0a9dc 76f988da
     *     983e5152 a831c66d b00327c8 bf597fc7
     *     c6e00bf3 d5a79147 06ca6351 14292967
     *     27b70a85 2e1b2138 4d2c6dfc 53380d13
     *     650a7354 766a0abb 81c2c92e 92722c85
     *     a2bfe8a1 a81a664b c24b8b70 c76c51a3
     *     d192e819 d6990624 f40e3585 106aa070
     *     19a4c116 1e376c08 2748774c 34b0bcb5
    */
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
        w[t] = sha2_256_ssig1(w[t - 2]) + w[t - 7] + sha2_256_ssig0(
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
        tmp1 = h[7] + sha2_256_bsig1(h[4]) + sha2_256_ch(h[4], h[5],
                h[6]) + K[t] + w[t];
        tmp2 = sha2_256_bsig0(h[0]) + sha2_256_mj(h[0], h[1], h[2]);

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
 * sha2_256 sha2_256_init
 *
 * Initializes sha2_256 struct with initial state seed, empties partial and digest
 *
 * For SHA-256, the initial hash value, H(0), consists of the following
 * eight 32-bit words, in hex.  These words were obtained by taking the
 * first thirty-two bits of the fractional parts of the square roots of
 * the first eight prime numbers.
 *
 *      H(0)0 = 6a09e667
 *      H(0)1 = bb67ae85
 *      H(0)2 = 3c6ef372
 *      H(0)3 = a54ff53a
 *      H(0)4 = 510e527f
 *      H(0)5 = 9b05688c
 *      H(0)6 = 1f83d9ab
 *      H(0)7 = 5be0cd19
*/
extern inline void sha2_256_init(struct sha2_256* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 32; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    m->h[0] = 0x6a09e667;
    m->h[1] = 0xbb67ae85;
    m->h[2] = 0x3c6ef372;
    m->h[3] = 0xa54ff53a;
    m->h[4] = 0x510e527f;
    m->h[5] = 0x9b05688c;
    m->h[6] = 0x1f83d9ab;
    m->h[7] = 0x5be0cd19;

    m->len = 0;
    m->p_len = 0;
}

/*
 * sha2_256 sha2_256_update
 *
 * Updates the state of the sha2_256 struct with new values
*/
extern inline void sha2_256_update(struct sha2_256* m, char* msg,
                                   uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;

            // Once we finish a buffer, call the core sha2_256 function to update
            // state and recompute the current hash value.
            sha2_256_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

/*
 * sha2_256 sha2_256_finalize
 *
 * Finalizes the sha2_256 structure; pads the partial block as necessary. Also
 * generates the message digest.
 *
 * Suppose a message has length L < 2^64.  Before it is input to the
 * hash function, the message is padded on the right as follows:
 *
 * a.  "1" is appended.  Example: if the original message is
 *     "01010000", this is padded to "010100001".
 *
 * b.  K "0"s are appended where K is the smallest, non-negative
 *     solution to the equation
 *
 *         L + 1 + K = 448 (mod 512)
 *
 * c.  Then append the 64-bit block that is L in binary representation.
 *     After appending this block, the length of the message will be a
 *     multiple of 512 bits.
 *
 *      Example:  Suppose the original message is the bit string
 *
 *           01100001 01100010 01100011 01100100 01100101
 *
 *      After step (a), this gives
 *
 *           01100001 01100010 01100011 01100100 01100101 1
 *
 *      Since L = 40, the number of bits in the above is 41 and K = 407
 *      "0"s are appended, making the total now 448.  This gives the
 *      following in hex:
 *
 *           61626364 65800000 00000000 00000000
 *           00000000 00000000 00000000 00000000
 *           00000000 00000000 00000000 00000000
 *           00000000 00000000
 *
 *      The 64-bit representation of L = 40 is hex 00000000 00000028.
 *      Hence the final padded message is the following hex:
 *
 *           61626364 65800000 00000000 00000000
 *           00000000 00000000 00000000 00000000
 *           00000000 00000000 00000000 00000000
 *           00000000 00000000 00000000 00000028
*/
extern inline void sha2_256_finalize(struct sha2_256* m)
{
    if (m->p_len > 55) {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha2_256_core(m);
    } else {
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;
    }

    for (; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0x00;
    }

    // Bytes to bits
    m->len *= 8;

    // Big endian representation of m->len
    m->partial[56] = (uint8_t) (m->len >> 56);
    m->partial[57] = (uint8_t) (m->len >> 48);
    m->partial[58] = (uint8_t) (m->len >> 40);
    m->partial[59] = (uint8_t) (m->len >> 32);
    m->partial[60] = (uint8_t) (m->len >> 24);
    m->partial[61] = (uint8_t) (m->len >> 16);
    m->partial[62] = (uint8_t) (m->len >>  8);
    m->partial[63] = (uint8_t) (m->len >>  0);

    sha2_256_core(m);

    for (m->p_len = 0; m->p_len < 8; m->p_len++) {
        m->digest[(m->p_len * 4) + 0] = (uint8_t) (m->h[m->p_len] >> 24);
        m->digest[(m->p_len * 4) + 1] = (uint8_t) (m->h[m->p_len] >> 16);
        m->digest[(m->p_len * 4) + 2] = (uint8_t) (m->h[m->p_len] >> 8);
        m->digest[(m->p_len * 4) + 3] = (uint8_t) (m->h[m->p_len] >> 0);
    }

    m->p_len = 0;
}

/*
 * sha2_256 sha2_256_sum
 *
 * Computes the sha2_256 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* sha2_256_sum(struct sha2_256* m, char* msg)
{
    sha2_256_init(m);
    sha2_256_update(m, msg, strlen(msg));
    sha2_256_finalize(m);
    return m->digest;
}

#endif // CC_sha2_256_H
