/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the RC2 symmetric encryption algorithm.
**/

#include "rc2.h"
#include "stdio.h"
#include "string.h"

void test_rfc_8()
{
    size_t count = 0;
    size_t i = 0;

    struct rc2 r;
    uint8_t key[3][8] = {
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
        {0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    };

    uint16_t plaintext[3][4] = {
        {0x0000, 0x0000, 0x0000, 0x0000},
        {0xffff, 0xffff, 0xffff, 0xffff},
        {0x0010, 0x0000, 0x0000, 0x0100},
    };

    uint16_t ciphertexts[3][4] = {
        {0xb7eb, 0xf973, 0x2793, 0xff8e},
        {0x8b27, 0xe427, 0x2f2e, 0x490d},
        {0x6430, 0xdf9e, 0xe79b, 0xc2d2},
    };

    size_t effective[3] = {63, 64, 64};

    for (count = 0; count < 3; count++) {
        printf("Key: %zu\n", count);

        rc2_init(&r, key[count], 8, effective[count]);
        rc2_encrypt(&r, plaintext[count]);

        printf("Encrypt: \n");
        printf("Actual:   ");
        for (i = 0; i < 4; i++) {
            printf("%04x", r.R[i]);
        }
        printf("\n");

        printf("Expected: ");
        for (i = 0; i < 4; i++) {
            printf("%04x", ciphertexts[count][i]);
        }
        printf("\n\n");
    }
}

void test_rfc_other()
{
    size_t i = 0;

    struct rc2 r;
    uint8_t key_0[1] = {0x88};
    uint8_t key_1[7] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a};
    uint8_t key_2[16] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2};
    uint8_t key_3[16] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2};
    uint8_t key_4[33] = {0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2, 0x16, 0xf8, 0x0a, 0x6f, 0x85, 0x92, 0x05, 0x84, 0xc4, 0x2f, 0xce, 0xb0, 0xbe, 0x25, 0x5d, 0xaf, 0x1e};
    uint16_t plaintext[4] = {0x0000, 0x0000, 0x0000, 0x0000};
    size_t keylen[5] = {1, 7, 16, 16, 33};
    size_t effective[5] = {64, 64, 64, 128, 129};
    uint16_t ciphertexts[5][4] = {
        {0xa861, 0x44a2, 0xacad, 0xf0cc},
        {0xcf6c, 0x0843, 0x4c97, 0x7f26},
        {0x801a, 0x277d, 0xbe2b, 0xb15d},
        {0x6922, 0x2a55, 0xf8b0, 0xa65c},
        {0x785b, 0xa4d3, 0xff3d, 0xf1f1}
    };

    printf("key 0: \n");
    rc2_init(&r, key_0, keylen[0], effective[0]);
    rc2_encrypt(&r, plaintext);

    printf("Encrypt: \n");
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", ciphertexts[0][i]);
    }
    printf("\n\n");


    printf("key 1: \n");
    rc2_init(&r, key_1, keylen[1], effective[1]);
    rc2_encrypt(&r, plaintext);

    printf("Encrypt: \n");
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", ciphertexts[1][i]);
    }
    printf("\n\n");


    printf("key 2: \n");
    rc2_init(&r, key_2, keylen[2], effective[2]);
    rc2_encrypt(&r, plaintext);

    printf("Encrypt: \n");
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", ciphertexts[2][i]);
    }
    printf("\n\n");


    printf("key 3: \n");
    rc2_init(&r, key_3, keylen[3], effective[3]);
    rc2_encrypt(&r, plaintext);

    printf("Encrypt: \n");
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", ciphertexts[3][i]);
    }
    printf("\n\n");
}

int main()
{
    printf("8 Byte Keys:\n");
    test_rfc_8();


    printf("Variable Byte Keys:\n");
    test_rfc_other();

    return 0;
}
