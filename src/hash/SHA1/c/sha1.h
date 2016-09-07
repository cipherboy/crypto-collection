/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the sha1 hash algorithm per RFC 3174. See docs for the
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
#ifndef CC_SHA1_H
#define CC_SHA1_H

#include "stdint.h"
#include "string.h"

/*
 * struct sha1
 *
 * uint8_t digest[20]  -- public; digest after finalization
 *
 * uint32_t h[5]       -- internal; hash state variables
 * uint64_t len        -- internal; length of input
 * uint8_t partial[64] -- internal; partial block of input
 * size_t p_len        -- internal; length of partial block
*/
struct sha1 {
    uint8_t digest[20];

    uint32_t h[5];
    uint64_t len;

    uint8_t partial[64];
    size_t p_len;
};

/*
 * sha1 function f
 *
 * f is a piecewise function combining various bitwise operations.
 *
 * A sequence of logical functions f(0), f(1),..., f(79) is used in
 * SHA-1. Each f(t), 0 <= t <= 79, operates on three 32-bit words B, C,
 * D and produces a 32-bit word as output. f(t;B,C,D) is defined as
 * follows: for words B, C, D,
 *
 *     f(t;B,C,D) = (B AND C) OR ((NOT B) AND D) ( 0 <= t <= 19)
 *     f(t;B,C,D) = B XOR C XOR D (20 <= t <= 39)
 *     f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D) (40 <= t <= 59)
 *     f(t;B,C,D) = B XOR C XOR D (60 <= t <= 79).
*/
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

/*
 * sha1 function k
 *
 * k is a piecewise function defining various constant values used.
 *
 * A sequence of constant words K(0), K(1), ... , K(79) is used in the
 * SHA-1. In hex these are given by
 *
 *     K(t) = 5A827999 ( 0 <= t <= 19)
 *     K(t) = 6ED9EBA1 (20 <= t <= 39)
 *     K(t) = 8F1BBCDC (40 <= t <= 59)
 *     K(t) = CA62C1D6 (60 <= t <= 79).
*/
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

/*
 * sha1 sha1_rotl32
 *
 * The circular left shift operation S^n(X), where X is a word and n
 * is an integer with 0 <= n < 32, is defined by
 *
 *     S^n(X) = (X << n) OR (X >> 32-n).
 * In the above, X << n is obtained as follows: discard the left-most
 * n bits of X and then pad the result with n zeroes on the right
 * (the result will still be 32 bits). X >> n is obtained by
 * discarding the right-most n bits of X and then padding the result
 * with n zeroes on the left. Thus S^n(X) is equivalent to a
 * circular shift of X by n positions to the left.
*/
extern inline uint32_t sha1_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}


/*
 * sha1 sha1_core
 *
 * Core of sha1 hash function; operates on a single round from m->partial
 * and updates hash state in m->s.
 *
 * Now M(1), M(2), ... , M(n) are processed.  To process M(i), we
 * proceed as follows:
 *    a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0)
 *       is the left-most word.
 *
 *    b. For t = 16 to 79 let
 *       W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
 *
 *    c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
 *
 *    d. For t = 0 to 79 do
 *       TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
 *       E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
 *
 *    e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
 *       + E.
*/
extern inline void sha1_core(struct sha1* m)
{
    size_t t = 0;
    uint32_t w[80];
    uint32_t h[5];
    uint32_t temp;

    // Message has to be processed as a big endian integer
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

/*
 * sha1 sha1_init
 *
 * Initializes sha1 struct with initial state seed, empties partial and digest
 *
 * A four-word buffer (A,B,C,D) is used to compute the message digest.
 * Here each of A, B, C, D is a 32-bit register. These registers are
 * initialized to the following values in hexadecimal, low-order bytes
 * first):
 *
 * Before processing any blocks, the H's are initialized as follows: in
 * hex,
 *    H0 = 67452301
 *    H1 = EFCDAB89
 *    H2 = 98BADCFE
 *    H3 = 10325476
 *    H4 = C3D2E1F0.
*/
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

/*
 * sha1 sha1_update
 *
 * Updates the state of the sha1 struct with new values
*/
extern inline void sha1_update(struct sha1* m, char* msg, uint64_t len)
{
    size_t i = 0;

    m->len += len;
    for (i = 0; i < len; i++) {
        if (m->p_len == 64) {
            m->p_len = 0;

            // Once we finish a buffer, call the core sha1 function to update
            // state and recompute the current hash value.
            sha1_core(m);
        }

        m->partial[m->p_len] = (uint8_t)((unsigned char) msg[i]);
        m->p_len += 1;
    }
}

/*
 * sha1 sha1_finalize
 *
 * Finalizes the sha1 structure; pads the partial block as necessary. Also
 * generates the message digest.
 *
 * 4. Message Padding
 *
 *     SHA-1 is used to compute a message digest for a message or data file
 *     that is provided as input.  The message or data file should be
 *     considered to be a bit string.  The length of the message is the
 *     number of bits in the message (the empty message has length 0).  If
 *     the number of bits in a message is a multiple of 8, for compactness
 *     we can represent the message in hex.  The purpose of message padding
 *     is to make the total length of a padded message a multiple of 512.
 *     SHA-1 sequentially processes blocks of 512 bits when computing the
 *     message digest.  The following specifies how this padding shall be
 *     performed.  As a summary, a "1" followed by m "0"s followed by a 64-
 *     bit integer are appended to the end of the message to produce a
 *     padded message of length 512 * n.  The 64-bit integer is the length
 *     of the original message.  The padded message is then processed by the
 *     SHA-1 as n 512-bit blocks.
 *
 *
 *     Suppose a message has length l < 2^64.  Before it is input to the
 *     SHA-1, the message is padded on the right as follows:
 *
 *     a. "1" is appended.  Example: if the original message is "01010000",
 *       this is padded to "010100001".
 *
 *     b. "0"s are appended.  The number of "0"s will depend on the original
 *       length of the message.  The last 64 bits of the last 512-bit block
 *       are reserved
 *
 *       for the length l of the original message.
 *
 *       Example:  Suppose the original message is the bit string:
 *
 *          01100001 01100010 01100011 01100100 01100101.
 *
 *       After step (a) this gives:
 *
 *          01100001 01100010 01100011 01100100 01100101 1.
 *
 *       Since l = 40, the number of bits in the above is 41 and 407 "0"s
 *       are appended, making the total now 448.  This gives (in hex)
 *
 *          61626364 65800000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000.
 *
 *     c. Obtain the 2-word representation of l, the number of bits in the
 *       original message.  If l < 2^32 then the first word is all zeroes.
 *       Append these two words to the padded message.
 *
 *       Example: Suppose the original message is as in (b).  Then l = 40
 *       (note that l is computed before any padding).  The two-word
 *       representation of 40 is hex 00000000 00000028.  Hence the final
 *       padded message is hex
 *
 *          61626364 65800000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000000
 *          00000000 00000000 00000000 00000028.
 *
 *       The padded message will contain 16 * n words for some n > 0.
 *       The padded message is regarded as a sequence of n blocks M(1) ,
 *       M(2), first characters (or bits) of the message.
*/
extern inline void sha1_finalize(struct sha1* m)
{
    // There are two cases: where a message buffer is too full to fit the 0b10*
    // padding with 64-bit length, and one where it can.
    if (m->p_len > 55) {
        // If the length is too short, add the 0b10* and pad out the block,
        // then call the core sha1 function to update state.
        m->partial[m->p_len] = 0x80;
        m->p_len += 1;

        for (; m->p_len < 64; m->p_len++) {
            m->partial[m->p_len] = 0x00;
        }

        m->p_len = 0;
        sha1_core(m);
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

    // Big endian representation of m->len
    m->partial[56] = (uint8_t) (m->len >> 56);
    m->partial[57] = (uint8_t) (m->len >> 48);
    m->partial[58] = (uint8_t) (m->len >> 40);
    m->partial[59] = (uint8_t) (m->len >> 32);
    m->partial[60] = (uint8_t) (m->len >> 24);
    m->partial[61] = (uint8_t) (m->len >> 16);
    m->partial[62] = (uint8_t) (m->len >>  8);
    m->partial[63] = (uint8_t) (m->len >>  0);

    // Update the sha1 state one last time.
    sha1_core(m);

    // Convert from the internal state to a big-endian representation
    // as the digest. Left as uint8 values; can be converted to hex or base64
    // as desired.
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
