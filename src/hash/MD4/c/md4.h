/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the md4 hash algorithm per RFC 1186. See docs for the
 * specification.
 *
 *
 * Usage:
 *
 *     struct md4 m;
 *     md4_init(&m);
 *     md4_sum("The quick brown fox jumps over the lazy dog");
 *     // Note, md4_sum returns the resulting md4 digest
 *
 *
 * Alternative usage:
 *
 *     struct md4 m;
 *     md4_init(&m);
 *     md4_update(&m, "The quick brown fox jumps over the lazy dog", 43);
 *     md4_finalize(&m);
*/

#pragma once
#ifndef CC_MD4_H
#define CC_MD4_H

#include "stdint.h"
#include "string.h"

/*
 * struct md4
 *
 * uint8_t digest[16]  -- public; digest after finalization
 *
 * uint32_t s[4]       -- internal; hash state variables
 * uint64_t len        -- internal; length of input
 * uint8_t partial[64] -- internal; partial block of input
 * size_t p_len        -- internal; length of partial block
*/
struct md4 {
    uint8_t digest[16];

    uint32_t s[4];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

/*
 * md4 function f
 *
 * if X then Y, else if not X, Z
 *
 * In each bit position f acts as a conditional: if x then y else
 * z.  (The function f could have been defined using + instead of
 * v since XY and not(X)Z will never have 1’s in the same bit
 * position.)
*/
extern inline uint32_t md4_f(uint32_t X, uint32_t Y, uint32_t Z)
{
    return ((Y ^ Z) & X) ^ Z;
}

/*
 * md4 function g
 *
 * majority function over X, Y, Z
 *
 * In each bit position g acts as a majority function:
 * if at least two of x, y, z are on, then g has a one in that bit
 * position, else g has a zero. It is interesting to note that if
 * the bits of X, Y, and Z are independent and unbiased, the each
 * bit of f(X,Y,Z) will be independent and unbiased, and similarly
 * each bit of g(X,Y,Z) will be independent and unbiased.
*/
extern inline uint32_t md4_g(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X & Y) | (X & Z) | (Y & Z);
}

/*
 * md4 function h
 *
 * parity function over X, Y, Z
 *
 * The
 * function h is the bit-wise "xor" or "parity" function; it has
 * properties similar to those of f and g.
*/
extern inline uint32_t md4_h(uint32_t X, uint32_t Y, uint32_t Z)
{
    return (X ^ Y) ^ Z;
}

/*
 * md4 md4_rotl32
 *
 * Rotates a 32-bit unsigned integer, data, to the left by count bits
 *
 * Let X <<< s denote the 32-bit value obtained by circularly
 * shifting (rotating) X left by s bit positions.
*/
extern inline uint32_t md4_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

/*
 * md4 md4_core
 *
 * Core of md4 hash function; operates on a single round from m->partial
 * and updates hash state in m->s.
 *
 * Do the following:
 *
 * For i = 0 to N/16-1 do  * process each 16-word block *
 *      For j = 0 to 15 do: * copy block i into X *
 *          Set X[j] to M[i*16+j].
 *      end * of loop on j *
 *      Save A as AA, B as BB, C as CC, and D as DD.
 *
 *      [Round 1]
 *      Let [A B C D i s] denote the operation
 *      A = (A + f(B,C,D) + X[i]) <<< s  .
 *
 *      Do the following 16 operations:
 *          [A B C D 0 3]
 *          [D A B C 1 7]
 *          [C D A B 2 11]
 *          [B C D A 3 19]
 *          [A B C D 4 3]
 *          [D A B C 5 7]
 *          [C D A B 6 11]
 *          [B C D A 7 19]
 *          [A B C D 8 3]
 *          [D A B C 9 7]
 *          [C D A B 10 11]
 *          [B C D A 11 19]
 *          [A B C D 12 3]
 *          [D A B C 13 7]
 *          [C D A B 14 11]
 *          [B C D A 15 19]
 *
 *      [Round 2]
 *      Let [A B C D i s] denote the operation
 *      A = (A + g(B,C,D) + X[i] + 5A827999) <<< s .
 *      (The value 5A..99 is a hexadecimal 32-bit
 *      constant, written with the high-order digit
 *      first. This constant represents the square
 *      root of 2.  The octal value of this constant
 *      is 013240474631.  See Knuth, The Art of
 *      Programming, Volume 2 (Seminumerical
 *      Algorithms), Second Edition (1981),
 *      Addison-Wesley.  Table 2, page 660.)
 *
 *      Do the following 16 operations:
 *          [A B C D 0  3]
 *          [D A B C 4  5]
 *          [C D A B 8  9]
 *          [B C D A 12 13]
 *          [A B C D 1  3]
 *          [D A B C 5  5]
 *          [C D A B 9  9]
 *          [B C D A 13 13]
 *          [A B C D 2  3]
 *          [D A B C 6  5]
 *          [C D A B 10 9]
 *          [B C D A 14 13]
 *          [A B C D 3  3]
 *          [D A B C 7  5]
 *          [C D A B 11 9]
 *          [B C D A 15 13]
 *
 *      [Round 3]
 *      Let [A B C D i s] denote the operation
 *      A = (A + h(B,C,D) + X[i] + 6ED9EBA1) <<< s .
 *      (The value 6E..A1 is a hexadecimal 32-bit
 *      constant, written with the high-order digit
 *      first.  This constant represents the square
 *      root of 3.  The octal value of this constant
 *      is 015666365641.  See Knuth, The Art of
 *      Programming, Volume 2 (Seminumerical
 *      Algorithms), Second Edition (1981),
 *      Addison-Wesley.  Table 2, page 660.)
 *
 *      Do the following 16 operations:
 *          [A B C D 0  3]
 *          [D A B C 8  9]
 *          [C D A B 4  11]
 *          [B C D A 12 15]
 *          [A B C D 2  3]
 *          [D A B C 10 9]
 *          [C D A B 6  11]
 *          [B C D A 14 15]
 *          [A B C D 1  3]
 *          [D A B C 9  9]
 *          [C D A B 5  11]
 *          [B C D A 13 15]
 *          [A B C D 3  3]
 *          [D A B C 11 9]
 *          [C D A B 7  11]
 *          [B C D A 15 15]
 *
 *      Then perform the following additions:
 *      A = A + AA
 *      B = B + BB
 *      C = C + CC
 *      D = D + DD
 *      (That is, each of the four registers is incremented by
 *      the value it had before this block was started.)
 * end * end of loop on i *
*/
extern inline void md4_core(struct md4* m)
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
    s[0] = md4_rotl32(s[0] + md4_f(s[1], s[2], s[3]) + x[ 0],  3);
    s[3] = md4_rotl32(s[3] + md4_f(s[0], s[1], s[2]) + x[ 1],  7);
    s[2] = md4_rotl32(s[2] + md4_f(s[3], s[0], s[1]) + x[ 2], 11);
    s[1] = md4_rotl32(s[1] + md4_f(s[2], s[3], s[0]) + x[ 3], 19);
    s[0] = md4_rotl32(s[0] + md4_f(s[1], s[2], s[3]) + x[ 4],  3);
    s[3] = md4_rotl32(s[3] + md4_f(s[0], s[1], s[2]) + x[ 5],  7);
    s[2] = md4_rotl32(s[2] + md4_f(s[3], s[0], s[1]) + x[ 6], 11);
    s[1] = md4_rotl32(s[1] + md4_f(s[2], s[3], s[0]) + x[ 7], 19);
    s[0] = md4_rotl32(s[0] + md4_f(s[1], s[2], s[3]) + x[ 8],  3);
    s[3] = md4_rotl32(s[3] + md4_f(s[0], s[1], s[2]) + x[ 9],  7);
    s[2] = md4_rotl32(s[2] + md4_f(s[3], s[0], s[1]) + x[10], 11);
    s[1] = md4_rotl32(s[1] + md4_f(s[2], s[3], s[0]) + x[11], 19);
    s[0] = md4_rotl32(s[0] + md4_f(s[1], s[2], s[3]) + x[12],  3);
    s[3] = md4_rotl32(s[3] + md4_f(s[0], s[1], s[2]) + x[13],  7);
    s[2] = md4_rotl32(s[2] + md4_f(s[3], s[0], s[1]) + x[14], 11);
    s[1] = md4_rotl32(s[1] + md4_f(s[2], s[3], s[0]) + x[15], 19);

    // Round 2
    s[0] = md4_rotl32(s[0] + md4_g(s[1], s[2], s[3]) + x[ 0] + 0x5A827999,  3);
    s[3] = md4_rotl32(s[3] + md4_g(s[0], s[1], s[2]) + x[ 4] + 0x5A827999,  5);
    s[2] = md4_rotl32(s[2] + md4_g(s[3], s[0], s[1]) + x[ 8] + 0x5A827999,  9);
    s[1] = md4_rotl32(s[1] + md4_g(s[2], s[3], s[0]) + x[12] + 0x5A827999, 13);
    s[0] = md4_rotl32(s[0] + md4_g(s[1], s[2], s[3]) + x[ 1] + 0x5A827999,  3);
    s[3] = md4_rotl32(s[3] + md4_g(s[0], s[1], s[2]) + x[ 5] + 0x5A827999,  5);
    s[2] = md4_rotl32(s[2] + md4_g(s[3], s[0], s[1]) + x[ 9] + 0x5A827999,  9);
    s[1] = md4_rotl32(s[1] + md4_g(s[2], s[3], s[0]) + x[13] + 0x5A827999, 13);
    s[0] = md4_rotl32(s[0] + md4_g(s[1], s[2], s[3]) + x[ 2] + 0x5A827999,  3);
    s[3] = md4_rotl32(s[3] + md4_g(s[0], s[1], s[2]) + x[ 6] + 0x5A827999,  5);
    s[2] = md4_rotl32(s[2] + md4_g(s[3], s[0], s[1]) + x[10] + 0x5A827999,  9);
    s[1] = md4_rotl32(s[1] + md4_g(s[2], s[3], s[0]) + x[14] + 0x5A827999, 13);
    s[0] = md4_rotl32(s[0] + md4_g(s[1], s[2], s[3]) + x[ 3] + 0x5A827999,  3);
    s[3] = md4_rotl32(s[3] + md4_g(s[0], s[1], s[2]) + x[ 7] + 0x5A827999,  5);
    s[2] = md4_rotl32(s[2] + md4_g(s[3], s[0], s[1]) + x[11] + 0x5A827999,  9);
    s[1] = md4_rotl32(s[1] + md4_g(s[2], s[3], s[0]) + x[15] + 0x5A827999, 13);

    // Round 3
    s[0] = md4_rotl32(s[0] + md4_h(s[1], s[2], s[3]) + x[ 0] + 0x6ED9EBA1,  3);
    s[3] = md4_rotl32(s[3] + md4_h(s[0], s[1], s[2]) + x[ 8] + 0x6ED9EBA1,  9);
    s[2] = md4_rotl32(s[2] + md4_h(s[3], s[0], s[1]) + x[ 4] + 0x6ED9EBA1, 11);
    s[1] = md4_rotl32(s[1] + md4_h(s[2], s[3], s[0]) + x[12] + 0x6ED9EBA1, 15);
    s[0] = md4_rotl32(s[0] + md4_h(s[1], s[2], s[3]) + x[ 2] + 0x6ED9EBA1,  3);
    s[3] = md4_rotl32(s[3] + md4_h(s[0], s[1], s[2]) + x[10] + 0x6ED9EBA1,  9);
    s[2] = md4_rotl32(s[2] + md4_h(s[3], s[0], s[1]) + x[ 6] + 0x6ED9EBA1, 11);
    s[1] = md4_rotl32(s[1] + md4_h(s[2], s[3], s[0]) + x[14] + 0x6ED9EBA1, 15);
    s[0] = md4_rotl32(s[0] + md4_h(s[1], s[2], s[3]) + x[ 1] + 0x6ED9EBA1,  3);
    s[3] = md4_rotl32(s[3] + md4_h(s[0], s[1], s[2]) + x[ 9] + 0x6ED9EBA1,  9);
    s[2] = md4_rotl32(s[2] + md4_h(s[3], s[0], s[1]) + x[ 5] + 0x6ED9EBA1, 11);
    s[1] = md4_rotl32(s[1] + md4_h(s[2], s[3], s[0]) + x[13] + 0x6ED9EBA1, 15);
    s[0] = md4_rotl32(s[0] + md4_h(s[1], s[2], s[3]) + x[ 3] + 0x6ED9EBA1,  3);
    s[3] = md4_rotl32(s[3] + md4_h(s[0], s[1], s[2]) + x[11] + 0x6ED9EBA1,  9);
    s[2] = md4_rotl32(s[2] + md4_h(s[3], s[0], s[1]) + x[ 7] + 0x6ED9EBA1, 11);
    s[1] = md4_rotl32(s[1] + md4_h(s[2], s[3], s[0]) + x[15] + 0x6ED9EBA1, 15);

    // Add temporary variables back into state.
    m->s[0] += s[0];
    m->s[1] += s[1];
    m->s[2] += s[2];
    m->s[3] += s[3];
}

/*
 * md4 md4_init
 *
 * Initializes md4 struct with initial state seed, empties partial and digest
 *
 * A 4-word buffer (A,B,C,D) is used to compute the message
 * digest.  Here each of A,B,C,D are 32-bit registers.  These
 * registers are initialized to the following values in
 * hexadecimal, low-order bytes first):
 *
 *   word A:  01 23 45 67
 *   word B:  89 ab cd ef
 *   word C:  fe dc ba 98
 *   word D:  76 54 32 10
*/
extern inline void md4_init(struct md4* m)
{
    m->p_len = 0;
    for (m->p_len = 0; m->p_len < 16; m->p_len++) {
        m->digest[m->p_len] = 0;
    }
    for (m->p_len = 0; m->p_len < 64; m->p_len++) {
        m->partial[m->p_len] = 0;
    }

    // Magic values from the specification.
    m->s[0] = 0x67452301;
    m->s[1] = 0xEFCDAB89;
    m->s[2] = 0x98BADCFE;
    m->s[3] = 0x10325476;

    m->len = 0;
    m->p_len = 0;
}

/*
 * md4 md4_update
 *
 * Updates the state of the md4 struct with new values
*/
extern inline void md4_update(struct md4* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;

            // Once we finish a buffer, call the core md4 function to update
            // state and recompute the current hash value.
            md4_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

/*
 * md4 md4_finalize
 *
 * Finalizes the md4 structure; pads the partial block as necessary. Also
 * generates the message digest.
 *
 * The message is "padded" (extended) so that its length (in bits)
 * is congruent to 448, modulo 512.  That is, the message is
 * extended so that it is just 64 bits shy of being a multiple of
 * 512 bits long.  Padding is always performed, even if the length
 * of the message is already congruent to 448, modulo 512 (in
 * which case 512 bits of padding are added).
 *
 * Padding is performed as follows: a single "1" bit is appended
 * to the message, and then enough zero bits are appended so that
 * the length in bits of the padded message becomes congruent to
 * 448, modulo 512.
 *
 * The message digest produced as output is A,B,C,D.  That is, we
 * begin with the low-order byte of A, and end with the high-order
 * byte of D.
 * This completes the description of MD4.  A reference
 * implementation in C is given in the Appendix.
*/
extern inline void md4_finalize(struct md4* m)
{
    // There are two cases: where a message buffer is too full to fit the 0b10*
    // padding with 64-bit length, and one where it can.
    if (m->p_len > 55) {
        // If the length is too short, add the 0b10* and pad out the block,
        // then call the core md4 function to update state.
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        md4_core(m);
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

    // Update the md4 state one last time.
    md4_core(m);

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
 * md4 md4_sum
 *
 * Computes the md4 sum of the msg and finalizes the digest, which is returned.
*/
extern inline uint8_t* md4_sum(struct md4* m, char* msg)
{
    // Reinitialize the structure, add the message, and finalize the hash.
    md4_init(m);
    md4_update(m, msg, strlen(msg));
    md4_finalize(m);

    return m->digest;
}

#endif // CC_MD4_H
