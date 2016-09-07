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

/*
 * struct md5
 *
 * uint8_t digest[16]  -- public; digest after finalization
 *
 * uint32_t s[4]       -- internal; hash state variables
 * uint64_t len        -- internal; length of input
 * uint8_t partial[64] -- internal; partial block of input
 * size_t p_len        -- internal; length of partial block
*/
struct md5 {
    uint8_t digest[16];

    uint32_t s[4];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

/*
 * md5 function f
 *
 * if X then Y, else if not X, Z
 *
 * In each bit position F acts as a conditional: if X then Y else Z.
 * The function F could have been defined using + instead of v since XY
 * and not(X)Z will never have 1’s in the same bit position.) It is
 * interesting to note that if the bits of X, Y, and Z are independent
 * and unbiased, the each bit of F(X,Y,Z) will be independent and
 * unbiased.
*/
extern inline uint32_t md5_f(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((Y ^ Z) & X) ^ Z;
}

/*
 * md5 function g
 *
 * if Z then X, else if not Z, Y
 *
 * The functions G, H, and I are similar to the function F, in that they
 * act in "bitwise parallel" to produce their output from the bits of X,
 * Y, and Z, in such a manner that if the corresponding bits of X, Y,
 * and Z are independent and unbiased, then each bit of G(X,Y,Z),
 * H(X,Y,Z), and I(X,Y,Z) will be independent and unbiased.
*/
extern inline uint32_t md5_g(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((X ^ Y) & Z) ^ Y;
}

/*
 * md5 function h
 *
 * pairity over X, Y, and Z
 *
 * The functions G, H, and I are similar to the function F, in that they
 * act in "bitwise parallel" to produce their output from the bits of X,
 * Y, and Z, in such a manner that if the corresponding bits of X, Y,
 * and Z are independent and unbiased, then each bit of G(X,Y,Z),
 * H(X,Y,Z), and I(X,Y,Z) will be independent and unbiased. Note that
 * the function H is the bit-wise "xor" or "parity" function of its
 * inputs.
*/
extern inline uint32_t md5_h(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X ^ Y) ^ Z;
}

/*
 * md5 function i
 *
 * Y xor (X or not Z)
 *
 * The functions G, H, and I are similar to the function F, in that they
 * act in "bitwise parallel" to produce their output from the bits of X,
 * Y, and Z, in such a manner that if the corresponding bits of X, Y,
 * and Z are independent and unbiased, then each bit of G(X,Y,Z),
 * H(X,Y,Z), and I(X,Y,Z) will be independent and unbiased.
*/
extern inline uint32_t md5_i(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (Y ^ (X | (~Z)));
}


/*
 * md5 md5_rotl32
 *
 * Rotates a 32-bit unsigned integer, data, to the left by count bits
 *
 * Let X <<< s denote the 32-bit value obtained by circularly
 * shifting (rotating) X left by s bit positions.
*/
extern inline uint32_t md5_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

/*
 * md5 md5_core
 *
 * Core of md5 hash function; operates on a single round from m->partial
 * and updates hash state in m->s.
 *
 *    Do the following:
 *
 *    # Process each 16-word block.
 *    For i = 0 to N/16-1 do
 *
 *    # Copy block i into X.
 *        For j = 0 to 15 do
 *        Set X[j] to M[i*16+j].
 *        end # of loop on j
 *
 *        # Save A as AA, B as BB, C as CC, and D as DD.
 *        AA = A
 *        BB = B
 *        CC = C
 *        DD = D
 *
 *        # Round 1.
 *        # Let [abcd k s i] denote the operation
 *        #    a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s).
 *        # Do the following 16 operations.
 *        [ABCD  0  7  1]  [DABC  1 12  2]  [CDAB  2 17  3]  [BCDA  3 22  4]
 *        [ABCD  4  7  5]  [DABC  5 12  6]  [CDAB  6 17  7]  [BCDA  7 22  8]
 *        [ABCD  8  7  9]  [DABC  9 12 10]  [CDAB 10 17 11]  [BCDA 11 22 12]
 *        [ABCD 12  7 13]  [DABC 13 12 14]  [CDAB 14 17 15]  [BCDA 15 22 16]
 *
 *        # Round 2.
 *        # Let [abcd k s i] denote the operation
 *        # a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s).
 *        # Do the following 16 operations.
 *        [ABCD  1  5 17]  [DABC  6  9 18]  [CDAB 11 14 19]  [BCDA  0 20 20]
 *        [ABCD  5  5 21]  [DABC 10  9 22]  [CDAB 15 14 23]  [BCDA  4 20 24]
 *        [ABCD  9  5 25]  [DABC 14  9 26]  [CDAB  3 14 27]  [BCDA  8 20 28]
 *        [ABCD 13  5 29]  [DABC  2  9 30]  [CDAB  7 14 31]  [BCDA 12 20 32]
 *
 *        # Round 3.
 *        # Let [abcd k s t] denote the operation
 *        #    a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s).
 *        # Do the following 16 operations.
 *        [ABCD  5  4 33]  [DABC  8 11 34]  [CDAB 11 16 35]  [BCDA 14 23 36]
 *        [ABCD  1  4 37]  [DABC  4 11 38]  [CDAB  7 16 39]  [BCDA 10 23 40]
 *        [ABCD 13  4 41]  [DABC  0 11 42]  [CDAB  3 16 43]  [BCDA  6 23 44]
 *        [ABCD  9  4 45]  [DABC 12 11 46]  [CDAB 15 16 47]  [BCDA  2 23 48]
 *
 *        # Round 4.
 *        # Let [abcd k s t] denote the operation
 *        #    a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s).
 *        # Do the following 16 operations.
 *        [ABCD  0  6 49]  [DABC  7 10 50]  [CDAB 14 15 51]  [BCDA  5 21 52]
 *        [ABCD 12  6 53]  [DABC  3 10 54]  [CDAB 10 15 55]  [BCDA  1 21 56]
 *        [ABCD  8  6 57]  [DABC 15 10 58]  [CDAB  6 15 59]  [BCDA 13 21 60]
 *        [ABCD  4  6 61]  [DABC 11 10 62]  [CDAB  2 15 63]  [BCDA  9 21 64]
 *
 *        # Then perform the following additions. (That is increment each
 *        #  of the four registers by the value it had before this block
 *        #  was started.)
 *        A = A + AA
 *        B = B + BB
 *        C = C + CC
 *        D = D + DD
 *
 *    end # of loop on i
*/
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
    s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 0] + 0xd76aa478,
                             7);
    s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 1] + 0xe8c7b756,
                             12);
    s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[ 2] + 0x242070db,
                             17);
    s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[ 3] + 0xc1bdceee,
                             22);
    s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 4] + 0xf57c0faf,
                             7);
    s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 5] + 0x4787c62a,
                             12);
    s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[ 6] + 0xa8304613,
                             17);
    s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[ 7] + 0xfd469501,
                             22);
    s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[ 8] + 0x698098d8,
                             7);
    s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[ 9] + 0x8b44f7af,
                             12);
    s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[10] + 0xffff5bb1,
                             17);
    s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[11] + 0x895cd7be,
                             22);
    s[0] = s[1] + md5_rotl32(s[0] + md5_f(s[1], s[2], s[3]) + x[12] + 0x6b901122,
                             7);
    s[3] = s[0] + md5_rotl32(s[3] + md5_f(s[0], s[1], s[2]) + x[13] + 0xfd987193,
                             12);
    s[2] = s[3] + md5_rotl32(s[2] + md5_f(s[3], s[0], s[1]) + x[14] + 0xa679438e,
                             17);
    s[1] = s[2] + md5_rotl32(s[1] + md5_f(s[2], s[3], s[0]) + x[15] + 0x49b40821,
                             22);

    // Round 2
    s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 1] + 0xf61e2562,
                             5);
    s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[ 6] + 0xc040b340,
                             9);
    s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[11] + 0x265e5a51,
                             14);
    s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 0] + 0xe9b6c7aa,
                             20);
    s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 5] + 0xd62f105d,
                             5);
    s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[10] + 0x02441453,
                             9);
    s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[15] + 0xd8a1e681,
                             14);
    s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 4] + 0xe7d3fbc8,
                             20);
    s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[ 9] + 0x21e1cde6,
                             5);
    s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[14] + 0xc33707d6,
                             9);
    s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[ 3] + 0xf4d50d87,
                             14);
    s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[ 8] + 0x455a14ed,
                             20);
    s[0] = s[1] + md5_rotl32(s[0] + md5_g(s[1], s[2], s[3]) + x[13] + 0xa9e3e905,
                             5);
    s[3] = s[0] + md5_rotl32(s[3] + md5_g(s[0], s[1], s[2]) + x[ 2] + 0xfcefa3f8,
                             9);
    s[2] = s[3] + md5_rotl32(s[2] + md5_g(s[3], s[0], s[1]) + x[ 7] + 0x676f02d9,
                             14);
    s[1] = s[2] + md5_rotl32(s[1] + md5_g(s[2], s[3], s[0]) + x[12] + 0x8d2a4c8a,
                             20);

    // Round 3
    s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 5] + 0xfffa3942,
                             4);
    s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 8] + 0x8771f681,
                             11);
    s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[11] + 0x6d9d6122,
                             16);
    s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[14] + 0xfde5380c,
                             23);
    s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 1] + 0xa4beea44,
                             4);
    s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 4] + 0x4bdecfa9,
                             11);
    s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[ 7] + 0xf6bb4b60,
                             16);
    s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[10] + 0xbebfbc70,
                             23);
    s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[13] + 0x289b7ec6,
                             4);
    s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[ 0] + 0xeaa127fa,
                             11);
    s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[ 3] + 0xd4ef3085,
                             16);
    s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[ 6] + 0x04881d05,
                             23);
    s[0] = s[1] + md5_rotl32(s[0] + md5_h(s[1], s[2], s[3]) + x[ 9] + 0xd9d4d039,
                             4);
    s[3] = s[0] + md5_rotl32(s[3] + md5_h(s[0], s[1], s[2]) + x[12] + 0xe6db99e5,
                             11);
    s[2] = s[3] + md5_rotl32(s[2] + md5_h(s[3], s[0], s[1]) + x[15] + 0x1fa27cf8,
                             16);
    s[1] = s[2] + md5_rotl32(s[1] + md5_h(s[2], s[3], s[0]) + x[ 2] + 0xc4ac5665,
                             23);

    // Round 4
    s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 0] + 0xf4292244,
                             6);
    s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[ 7] + 0x432aff97,
                             10);
    s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[14] + 0xab9423a7,
                             15);
    s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 5] + 0xfc93a039,
                             21);
    s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[12] + 0x655b59c3,
                             6);
    s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[ 3] + 0x8f0ccc92,
                             10);
    s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[10] + 0xffeff47d,
                             15);
    s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 1] + 0x85845dd1,
                             21);
    s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 8] + 0x6fa87e4f,
                             6);
    s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[15] + 0xfe2ce6e0,
                             10);
    s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[ 6] + 0xa3014314,
                             15);
    s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[13] + 0x4e0811a1,
                             21);
    s[0] = s[1] + md5_rotl32(s[0] + md5_i(s[1], s[2], s[3]) + x[ 4] + 0xf7537e82,
                             6);
    s[3] = s[0] + md5_rotl32(s[3] + md5_i(s[0], s[1], s[2]) + x[11] + 0xbd3af235,
                             10);
    s[2] = s[3] + md5_rotl32(s[2] + md5_i(s[3], s[0], s[1]) + x[ 2] + 0x2ad7d2bb,
                             15);
    s[1] = s[2] + md5_rotl32(s[1] + md5_i(s[2], s[3], s[0]) + x[ 9] + 0xeb86d391,
                             21);

    // Add temporary variables back into state.
    m->s[0] += s[0];
    m->s[1] += s[1];
    m->s[2] += s[2];
    m->s[3] += s[3];
}

/*
 * md5 md5_init
 *
 * Initializes md5 struct with initial state seed, empties partial and digest
 *
 * A four-word buffer (A,B,C,D) is used to compute the message digest.
 * Here each of A, B, C, D is a 32-bit register. These registers are
 * initialized to the following values in hexadecimal, low-order bytes
 * first):
 *
 *   word A:  01 23 45 67
 *   word B:  89 ab cd ef
 *   word C:  fe dc ba 98
 *   word D:  76 54 32 10
*/
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

/*
 * md5 md5_update
 *
 * Updates the state of the md5 struct with new values
*/
extern inline void md5_update(struct md5* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;

            // Once we finish a buffer, call the core md5 function to update
            // state and recompute the current hash value.
            md5_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}


/*
 * md5 md5_finalize
 *
 * Finalizes the md5 structure; pads the partial block as necessary. Also
 * generates the message digest.
 *
 * The message is "padded" (extended) so that its length (in bits) is
 * congruent to 448, modulo 512. That is, the message is extended so
 * that it is just 64 bits shy of being a multiple of 512 bits long.
 * Padding is always performed, even if the length of the message is
 * already congruent to 448, modulo 512.
 * Padding is performed as follows: a single "1" bit is appended to the
 * message, and then "0" bits are appended so that the length in bits of
 * the padded message becomes congruent to 448, modulo 512. In all, at
 * least one bit and at most 512 bits are appended.
 *
 * A 64-bit representation of b (the length of the message before the
 * padding bits were added) is appended to the result of the previous
 * step. In the unlikely event that b is greater than 2^64, then only
 * the low-order 64 bits of b are used. (These bits are appended as two
 * 32-bit words and appended low-order word first in accordance with the
 * previous conventions.)
 *
 * At this point the resulting message (after padding with bits and with
 * b) has a length that is an exact multiple of 512 bits. Equivalently,
 * this message has a length that is an exact multiple of 16 (32-bit)
 * words. Let M[0 ... N-1] denote the words of the resulting message,
 * where N is a multiple of 16.
*/
extern inline void md5_finalize(struct md5* m)
{
    // There are two cases: where a message buffer is too full to fit the 0b10*
    // padding with 64-bit length, and one where it can.
    if (m->p_len > 55) {
        // If the length is too short, add the 0b10* and pad out the block,
        // then call the core md5 function to update state.
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        md5_core(m);
    } else {
        // Enough room, so just add the 0b10* and increment the length.
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;
    }

    // Finish off the block with zeroes.
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

    // Update the md5 state one last time.
    md5_core(m);

    // Convert from the internal state to a little-endian representation
    // as the digest. Left as uint8 values; can be converted to hex or base64
    // as desired.
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
