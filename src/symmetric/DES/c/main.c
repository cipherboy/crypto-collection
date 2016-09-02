/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the des symmetric encryption algorithm.
**/

#include "des.h"
#include "stdio.h"

int main()
{
    struct des d;
    uint64_t key = 0x8000000000000000ull;
    uint64_t plain = 0x0000000000000000ull;
    uint64_t expected = 0x95A8D72813DAA94Dull;

    des_init(&d, key);

    for (size_t i = 0; i < 16; i++) {
        printf("Subkey[%zu]: %16lx\n", i, d.skey[i] & 0xffffffffffff);
    }

    printf("Key: %16lx\n", key);
    printf("Plaintext: %16lx\n", plain);
    printf("Actual: %16lx\n", des_encrypt_block(&d, plain));
    printf("Expected: %16lx\n", expected);

    return 0;
}
