/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the RC2 symmetric encryption algorithm.
**/

#include "rc2.h"
#include "stdio.h"
#include "stdint.h"

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

    uint16_t plaintexts[3][4] = {
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
        rc2_encrypt(&r, plaintexts[count]);

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
        printf("\n");
        printf("Decrypt: \n");
        rc2_decrypt(&r, ciphertexts[count]);
        printf("Actual:   ");
        for (i = 0; i < 4; i++) {
            printf("%04x", r.R[i]);
        }
        printf("\n");

        printf("Expected: ");
        for (i = 0; i < 4; i++) {
            printf("%04x", plaintexts[count][i]);
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
    uint16_t plaintext[4] = {0x0000, 0x0000, 0x0000, 0x0000};
    size_t keylen[4] = {1, 7, 16, 16};
    size_t effective[4] = {64, 64, 64, 128};
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
    printf("\n");
    printf("Decrypt: \n");
    rc2_decrypt(&r, ciphertexts[0]);
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", plaintext[i]);
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
    printf("\n");
    printf("Decrypt: \n");
    rc2_decrypt(&r, ciphertexts[1]);
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", plaintext[i]);
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
    printf("\n");
    printf("Decrypt: \n");
    rc2_decrypt(&r, ciphertexts[2]);
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", plaintext[i]);
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
    printf("\n");
    printf("Decrypt: \n");
    rc2_decrypt(&r, ciphertexts[3]);
    printf("Actual:   ");
    for (i = 0; i < 4; i++) {
        printf("%04x", r.R[i]);
    }
    printf("\n");

    printf("Expected: ");
    for (i = 0; i < 4; i++) {
        printf("%04x", plaintext[i]);
    }
    printf("\n\n");
}

int main()
{
    printf("8 Byte Keys:\n");
    test_rfc_8();


    printf("\n\nVariable Byte Keys:\n");
    test_rfc_other();

    return 0;
}
