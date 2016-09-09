/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the RC2 encryption algorithm per RFC 2268. See docs for
 * the specification.
*/

#pragma once
#ifndef CC_RC2_H
#define CC_RC2_H

#include "stdlib.h"
#include "stdint.h"

/*
 * Constants for RC2 algorithm: hexadecimal digits of Pi
 *
 * Here PITABLE[0], ..., PITABLE[255] is an array of "random" bytes
 * based on the digits of PI = 3.14159... . More precisely, the array
 * PITABLE is a random permutation of the values 0, ..., 255.
*/
const uint8_t rc2_initial_pitable[256] = {
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79,
    0x4a, 0xa0, 0xd8, 0x9d, 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e,
    0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 0x17, 0x9a, 0x59, 0xf5,
    0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22,
    0x5c, 0x6b, 0x4e, 0x82, 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c,
    0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 0x12, 0x75, 0xca, 0x1f,
    0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b,
    0xbc, 0x94, 0x43, 0x03, 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7,
    0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 0x08, 0xe8, 0xea, 0xde,
    0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e,
    0x04, 0x18, 0xa4, 0xec, 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc,
    0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 0x99, 0x7c, 0x3a, 0x85,
    0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10,
    0x67, 0x6c, 0xba, 0xc9, 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c,
    0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 0x0d, 0x38, 0x34, 0x1b,
    0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68,
    0xfe, 0x7f, 0xc1, 0xad
};

/*
 * struct rc2
 *
 * uint16_t R[4]   -- public; encrypted or decrypted data
 *
 * union key: internal
 *  uint16_t K[64] -- internal; little endian integer subkey
 *  uint8_t L[128] -- internal; subkey bytes
 *
 * uint16_t s[4] -- internal; round shift amounts
 * size_t j      -- internal; key position index
*/
struct rc2 {
    union {
        uint16_t K[64];
        uint8_t L[128];
    } key;

    uint16_t R[4];
    uint16_t s[4];
    size_t j;
};

/*
 * rc2 rc2_rotl16
 *
 * Here the expression "x rol k" denotes the 16-bit word x rotated left
 * by k bits, with the bits shifted out the top end entering the bottom
 * end.
*/
extern inline uint16_t rc2_rotl16(uint16_t data, uint16_t count)
{
    return ((data << count) | (data >> (16 - count)));
}

/*
 * rc2 rc2_rotr16
 *
 * Here the expression "x ror k" denotes the 16-bit word x rotated right
 * by k bits, with the bits shifted out the bottom end entering the top
 * end.
*/
extern inline uint16_t rc2_rotr16(uint16_t data, uint16_t count)
{
    return ((data << (16 - count)) | (data >> count));
}

/*
 * rc2 rc2_init
 *
 * Initializes the rc2 structure by generating subkeys from the master key.
 *
 * Key expansion
 *
 * Since we will be dealing with eight-bit byte operations as well as
 * 16-bit word operations, we will use two alternative notations
 * for referring to the key buffer:
 *
 *     For word operations, we will refer to the positions of the
 *     buffer as K[0], ..., K[63]; each K[i] is a 16-bit word.
 *
 *     For byte operations, we will refer to the key buffer as
 *     L[0], ..., L[127]; each L[i] is an eight-bit byte.
 *
 * These are alternative views of the same data buffer. At all times it
 * will be true that:
 *     K[i] = L[2*i] + 256*L[2*i+1].
 * (Note that the low-order byte of each K word is given before the
 * high-order byte.)
 *
 * We will assume that exactly T bytes of key are supplied, for some T
 * in the range 1 <= T <= 128. (Our current implementation uses T = 8.)
 * However, regardless of T, the algorithm has a maximum effective key
 * length in bits, denoted T1. That is, the search space is 2^(8*T), or
 * 2^T1, whichever is smaller.
 *
 * The purpose of the key-expansion algorithm is to modify the key
 * buffer so that each bit of the expanded key depends in a complicated
 * way on every bit of the supplied input key.
 *
 * The key expansion algorithm begins by placing the supplied T-byte key
 * into bytes L[0], ..., L[T-1] of the key buffer.
 *
 * The key expansion algorithm then computes the effective key length in
 * bytes T8 and a mask TM based on the effective key length in bits T1.
 * It uses the following operations:
 *
 *     T8 = (T1+7)/8;
 *     TM = 255 MOD 2^(8 + T1 - 8*T8);
 *
 * Thus TM has its 8 - (8*T8 - T1) least significant bits set.
 *
 * For example, with an effective key length of 64 bits, T1 = 64, T8 = 8
 * and TM = 0xff. With an effective key length of 63 bits, T1 = 63, T8
 * = 8 and TM = 0x7f.
 *
 * The key expansion operation consists of the following two loops and
 * intermediate step:
 *
 *     for i = T, T+1, ..., 127 do
 *         L[i] = PITABLE[L[i-1] + L[i-T]];
 *     L[128-T8] = PITABLE[L[128-T8] & TM];
 *     for i = 127-T8, ..., 0 do
 *         L[i] = PITABLE[L[i+1] XOR L[i+T8]];
 *
 * (In the first loop, the addition of L[i-1] and L[i-T] is performed
 * modulo 256.)
 *
 * The "effective key" consists of the values L[128-T8],..., L[127].
 * The intermediate step’s bitwise "and" operation reduces the search
 * space for L[128-T8] so that the effective number of key bits is T1.
 *
 * The expanded key depends only on the effective key bits, regardless
 * of the supplied key K. Since the expanded key is not itself modified
 * during encryption or decryption, as a pragmatic matter one can expand
 * the key just once when encrypting or decrypting a large block of data.
*/
extern inline void rc2_init(struct rc2* r, uint8_t* key, size_t len,
                            size_t effective)
{
    size_t t = 0;
    size_t i = 0;
    size_t T8 = (effective + 7) / 8;
    size_t TM = 255 % (2 << (8 + effective - 8 * T8));

    for (t = 0; t < len; t++) {
        r->key.L[t] = key[t];
    }

    for (t = len; t < 128; t++) {
        r->key.L[t] = rc2_initial_pitable[(r->key.L[t - 1] + r->key.L[i]) % 256];
        i += 1;
    }

    r->key.L[128 - T8] = rc2_initial_pitable[r->key.L[128 - T8] & TM];

    for (t = 127 - T8; t > 0; t--) {
        r->key.L[t] = rc2_initial_pitable[r->key.L[t + 1] ^ r->key.L[t + T8]];
    }
    r->key.L[0] = rc2_initial_pitable[r->key.L[1] ^ r->key.L[T8]];


#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t tmp;
    for (t = 0; t < 64; t++) {
        tmp = r->key.L[(t * 2) + 0];
        r->key.L[(t * 2) + 0] = r->key.L[(t * 2) + 1];
        r->key.L[(t * 2) + 1] = tmp;
    }
#endif
}

/*
 * rc2 rc2_mix
 *
 * Mix up R[i]
 * The primitive "Mix up R[i]" operation is defined as follows, where
 * s[0] is 1, s[1] is 2, s[2] is 3, and s[3] is 5, and where the indices
 * of the array R are always to be considered "modulo 4," so that R[i-1]
 * refers to R[3] if i is 0 (these values are
 * "wrapped around" so that R always has a subscript in the range 0 to 3
 * inclusive):
 *     R[i] = R[i] + K[j] + (R[i-1] & R[i-2]) + ((~R[i-1]) & R[i-3]);
 *     j = j + 1;
 *     R[i] = R[i] rol s[i];
 * In words: The next key word K[j] is added to R[i], and j is advanced.
 * Then R[i-1] is used to create a "composite" word which is added to
 * R[i]. The composite word is identical with R[i-2] in those positions
 * where R[i-1] is one, and identical to R[i-3] in those positions where
 * R[i-1] is zero. Then R[i] is rotated left by s[i] bits (bits rotated
 * out the left end of R[i] are brought back in at the right). Here j is
 * a "global" variable so that K[j] is always the first key word in the
 * expanded key which has not yet been used in a "mix" operation.
*/
extern inline void rc2_mix(struct rc2* r, size_t i)
{
    r->R[i] = r->R[i] + r->key.K[r->j]
              + (r->R[((i - 1) + 4) % 4] & r->R[((i - 2) + 4) % 4])
              + ((~(r->R[((i - 1) + 4) % 4])) & r->R[((i - 3) + 4) % 4]);
    r->j = r->j + 1;

    r->R[i] = rc2_rotl16(r->R[i], r->s[i]);
}

/*
 * rc2 rc2_mix_round
 *
 * Mixing round
 *
 * A "mixing round" consists of the following operations:
 *
 * Mix up R[0]
 * Mix up R[1]
 * Mix up R[2]
 * Mix up R[3]
*/
extern inline void rc2_mix_round(struct rc2* r)
{
    rc2_mix(r, 0);
    rc2_mix(r, 1);
    rc2_mix(r, 2);
    rc2_mix(r, 3);
}

/*
 * rc2 rc2_mash
 * Mash R[i]
 *
 * The primitive "Mash R[i]" operation is defined as follows (using the
 * previous conventions regarding subscripts for R):
 *
 *     R[i] = R[i] + K[R[i-1] & 63];
 *
 * In words: R[i] is "mashed" by adding to it one of the words of the
 * expanded key. The key word to be used is determined by looking at the
 * low-order six bits of R[i-1], and using that as an index into the key
 * array K.
*/
extern inline void rc2_mash(struct rc2* r, size_t i)
{
    r->R[i] = r->R[i] + r->key.K[r->R[((i - 1) + 4) % 4] & 63];
}

/*
 * rc2 rc2_mash_round
 *
 * Mashing round
 *
 * A "mashing round" consists of:
 *
 * Mash R[0]
 * Mash R[1]
 * Mash R[2]
 * Mash R[3]
*/
extern inline void rc2_mash_round(struct rc2* r)
{
    rc2_mash(r, 0);
    rc2_mash(r, 1);
    rc2_mash(r, 2);
    rc2_mash(r, 3);
}

/*
 * rc2 rc2_encrypt
 *
 * Encrypts the 64-bits of data and stores the result in r->R.
 *
 * Encryption algorithm
 *
 * The encryption operation is defined in terms of primitive "mix" and
 * "mash" operations.
 *
 * The entire encryption operation can now be described as follows. Here
 * j is a global integer variable which is affected by the mixing
 * operations.
 *
 *     1. Initialize words R[0], ..., R[3] to contain the 64-bit input value.
 *     2. Expand the key, so that words K[0], ..., K[63] become defined.
 *     3. Initialize j to zero.
 *     4. Perform five mixing rounds.
 *     5. Perform one mashing round.
 *     6. Perform six mixing rounds.
 *     7. Perform one mashing round.
 *     8. Perform five mixing rounds.
 *
 * Note that each mixing round uses four key words, and that there are
 * 16 mixing rounds altogether, so that each key word is used exactly
 * once in a mixing round. The mashing rounds will refer to up to eight
 * of the key words in a data-dependent manner. (There may be
 * repetitions, and the actual set of words referred to will vary from
 * encryption to encryption.)
*/
extern inline void rc2_encrypt(struct rc2* r, uint16_t* data)
{
    r->R[0] = data[0];
    r->R[1] = data[1];
    r->R[2] = data[2];
    r->R[3] = data[3];

    r->s[0] = 1;
    r->s[1] = 2;
    r->s[2] = 3;
    r->s[3] = 5;

    r->j = 0;

    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);

    rc2_mash_round(r);

    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);

    rc2_mash_round(r);

    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
    rc2_mix_round(r);
}

/*
 * rc2 rc2_r_mix
 *
 * R-Mix up R[i]
 *
 * The primitive "R-Mix up R[i]" operation is defined as follows, where
 * s[0] is 1, s[1] is 2, s[2] is 3, and s[3] is 5, and where the indices
 * of the array R are always to be considered "modulo 4," so that R[i-1]
 * refers to R[3] if i is 0 (these values are "wrapped around" so that R
 * always has a subscript in the range 0 to 3 inclusive):
 *
 *     R[i] = R[i] ror s[i];
 *     R[i] = R[i] - K[j] - (R[i-1] & R[i-2]) - ((~R[i-1]) & R[i-3]);
 *     j = j - 1;
 *
 * In words: R[i] is rotated right by s[i] bits (bits rotated out the
 * right end of R[i] are brought back in at the left). Here j is a
 * "global" variable so that K[j] is always the key word with greatest
 * index in the expanded key which has not yet been used in a "r-mix"
 * operation. The key word K[j] is subtracted from R[i], and j is
 * decremented. R[i-1] is used to create a "composite" word which is
 * subtracted from R[i].  The composite word is identical with R[i-2] in
 * those positions where R[i-1] is one, and identical to R[i-3] in those
 * positions where R[i-1] is zero.
*/
extern inline void rc2_r_mix(struct rc2* r, size_t i)
{
    r->R[i] = rc2_rotr16(r->R[i], r->s[i]);
    r->R[i] = r->R[i] - r->key.K[r->j]
              - (r->R[((i - 1) + 4) % 4] & r->R[((i - 2) + 4) % 4])
              - ((~(r->R[((i - 1) + 4) % 4])) & r->R[((i - 3) + 4) % 4]);
    r->j = r->j - 1;

}

/*
 * rc2 rc2_r_mix_round
 *
 * R-Mixing round
 *
 * An "r-mixing round" consists of the following operations:
 *
 * R-Mix up R[3]
 * R-Mix up R[2]
 * R-Mix up R[1]
 * R-Mix up R[0]
*/
extern inline void rc2_r_mix_round(struct rc2* r)
{
    rc2_r_mix(r, 3);
    rc2_r_mix(r, 2);
    rc2_r_mix(r, 1);
    rc2_r_mix(r, 0);
}

/*
 * rc2 rc2_r_mash
 *
 * R-Mash R[i]
 *
 * The primitive "R-Mash R[i]" operation is defined as follows (using
 * the previous conventions regarding subscripts for R):
 *
 *     R[i] = R[i] - K[R[i-1] & 63];
 *
 * In words: R[i] is "r-mashed" by subtracting from it one of the words
 * of the expanded key. The key word to be used is determined by looking
 * at the low-order six bits of R[i-1], and using that as an index into
 * the key array K.
*/
extern inline void rc2_r_mash(struct rc2* r, size_t i)
{
    r->R[i] = r->R[i] - r->key.K[r->R[((i - 1) + 4) % 4] & 63];
}

/*
 * rc2 rc2_r_mash_round
 *
 * R-Mashing round
 *
 * An "r-mashing round" consists of:
 *
 * R-Mash R[3]
 * R-Mash R[2]
 * R-Mash R[1]
 * R-Mash R[0]
*/
extern inline void rc2_r_mash_round(struct rc2* r)
{
    rc2_r_mash(r, 3);
    rc2_r_mash(r, 2);
    rc2_r_mash(r, 1);
    rc2_r_mash(r, 0);
}

/*
 * rc2 rc2_decrypt
 *
 * Decrypts the 64-bits of data and stores the result in r->R.
 *
 * Decryption algorithm
 *
 * The decryption operation is defined in terms of primitive operations
 * that undo the "mix" and "mash" operations of the encryption
 * algorithm. They are named "r-mix" and "r-mash" (r- denotes the
 * reverse operation).
 *
 * The entire decryption operation can now be described as follows.
 * Here j is a global integer variable which is affected by the mixing
 * operations.
 *
 *     1. Initialize words R[0], ..., R[3] to contain the 64-bit ciphertext
 *         value.
 *     2. Expand the key, so that words K[0], ..., K[63] become defined.
 *     3. Initialize j to 63.
 *     4. Perform five r-mixing rounds.
 *     5. Perform one r-mashing round.
 *     6. Perform six r-mixing rounds.
 *     7. Perform one r-mashing round.
 *     8. Perform five r-mixing rounds.
*/
extern inline void rc2_decrypt(struct rc2* r, uint16_t* data)
{
    r->R[0] = data[0];
    r->R[1] = data[1];
    r->R[2] = data[2];
    r->R[3] = data[3];

    r->s[0] = 1;
    r->s[1] = 2;
    r->s[2] = 3;
    r->s[3] = 5;

    r->j = 63;

    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);

    rc2_r_mash_round(r);

    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);

    rc2_r_mash_round(r);

    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
    rc2_r_mix_round(r);
}


#endif
