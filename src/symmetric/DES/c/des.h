/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the des encryption algorithm per FIPS46-3. See docs for
 * the specification.
*/

#pragma once
#ifndef CC_DES_H
#define CC_DES_H

#include "stdint.h"
#include "stdlib.h"
#include "stdio.h"

const uint8_t des_initial_permutation_shifts[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

const uint8_t des_inverse_permutation_shifts[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
};

const uint8_t des_expand_shifts[48] = {
    32,  1,  2,  3,  4,  5,
    4,  5,  6,  7,  8,  9,
    8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
};

const uint8_t des_primitive_functions[8][64] = {
    {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
        0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
        4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    }, {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
        3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
        0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    }, {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
        1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    }, {
        7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
        3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    }, {
        2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
        4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    }, {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
        9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
        4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    }, {
        4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
        1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
        6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    }, {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
        1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
        7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
        2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
};

const uint8_t des_primitive_function_p[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

const uint8_t des_permuted_choice_1[64] = {
    57, 49,  41, 33,  25,  17,  9,
    1, 58,  50, 42,  34,  26, 18,
    10,  2,  59, 51,  43,  35, 27,
    19, 11,   3, 60,  52,  44, 36,
    63, 55,  47, 39,  31,  23, 15,
    7, 62,  54, 46,  38,  30, 22,
    14,  6,  61, 53,  45,  37, 29,
    21, 13,   5, 28,  20,  12,  4
};

const uint8_t des_permuted_choice_2[48] = {
    14, 17, 11, 24,  1,  5,
    3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

const uint8_t des_shift_sizes[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

struct des {
    uint64_t skey[16];
};

extern inline uint32_t des_rotl32(uint32_t data, uint32_t count)
{
    return ((data << count) | (data >> (32 - count)));
}

static inline void des_choice_1_permute(uint32_t* C, uint32_t* D,
                                        uint64_t key)
{
    uint64_t result = 0;
    size_t pos = 0;

    for (pos = 0; pos < 63; pos++) {
        result = result << 1;
        result += (key >> (64 - des_permuted_choice_1[pos])) & 1;
    }

    *C = (uint32_t) (result >> 32);
    *D = (uint32_t) result;
}

static inline void des_choice_2_permute(uint64_t* output, uint32_t C,
                                        uint32_t D)
{
    uint64_t input = ((uint64_t) C << 32) ^ ((uint64_t) D);
    uint64_t result = 0;
    size_t pos = 0;

    printf("input: %16lx\n", input);

    for (pos = 0; pos < 46; pos++) {
        printf("Round: %zu\n", pos);
        printf("b: %16lx\n", result);
        result = result << 1;
        result ^= (input >> (64 - des_permuted_choice_2[pos])) & 1;
        printf("a: %16lx\n\n", result);
    }

    *output = result;
}

static inline void des_initial_permute(uint32_t* left, uint32_t* right,
                                       uint64_t input)
{
    uint64_t result = 0;
    size_t pos = 0;

    for (pos = 0; pos < 64; pos++) {
        result = result << 1;
        result += (input >> (64 - des_initial_permutation_shifts[pos])) & 1;
    }

    *left = (uint32_t) (result >> 32);
    *right = (uint32_t) result;
}

static inline void des_inverse_permute(uint64_t* output, uint32_t left,
                                       uint32_t right)
{
    uint64_t input = ((uint64_t) left << 32) ^ ((uint64_t) right);
    uint64_t result = 0;
    size_t pos = 0;

    for (pos = 0; pos < 64; pos++) {
        result = result << 1;
        result += (input >> (64 - des_inverse_permutation_shifts[pos])) & 1;
    }

    *output = result;
}

static inline uint64_t des_expand(uint32_t input)
{
    uint64_t result = 0;
    size_t pos = 0;

    for (pos = 0; pos < 64; pos++) {
        result = result << 1;
        result += (((uint64_t) input) >> (64 - des_inverse_permutation_shifts[pos])) &
                  1;
    }

    return result;
}

static inline uint32_t des_f(uint32_t input, uint64_t key)
{
    size_t pos = 0;
    uint64_t expanded_input = des_expand(input);
    uint32_t result = 0;

    uint8_t data;
    uint8_t col;
    uint8_t row;

    expanded_input = expanded_input ^ key;

    for (pos = 0; pos < 8; pos++) {
        result = result << 4;
        data = (uint8_t) (expanded_input >> (48 - 6 * (pos + 1)));
        col = (data & 0x1e) >> 1;
        row = ((data & 0x20) >> 5) + data * 0x01;

        result += des_primitive_functions[pos][row * 16 + col];
    }

    return result;
}

static inline void des_init(struct des* d, uint64_t key)
{
    size_t n = 0;
    uint32_t C = 0;
    uint32_t D = 0;

    des_choice_1_permute(&C, &D, key);

    printf("CD: %08x %08x\n", C, D);

    C = des_rotl32(C, des_shift_sizes[0]);
    D = des_rotl32(D, des_shift_sizes[0]);

    printf("CD: %08x %08x\n", C, D);

    for (n = 0; n < 15; n++) {
        printf("CD: %08x %08x\n", C, D);
        des_choice_2_permute(&(d->skey[n]), C, D);

        return;

        C = des_rotl32(C, des_shift_sizes[n + 1]);
        D = des_rotl32(D, des_shift_sizes[n + 1]);

        printf("CD: %08x %08x\n", C, D);
    }

    des_choice_2_permute(&(d->skey[15]), C, D);
}

static inline uint64_t des_encrypt_block(struct des* d, uint64_t input)
{
    uint32_t left_e;
    uint32_t right_e;
    uint32_t left_o;
    uint32_t right_o;
    uint64_t result;
    size_t a = 0;

    des_initial_permute(&left_e, &right_e, input);

    for (a = 0; a < 8; a++) {
        left_e = left_e ^ des_f(right_e, d->skey[a * 2 + 0]);
        left_o = right_e;
        right_o = left_e;

        left_o = left_o ^ des_f(right_o, d->skey[a * 2 + 1]);
        left_e = right_o;
        right_e = left_o;
    }

    des_inverse_permute(&result, left_e, right_e);

    return result;
}

#endif
