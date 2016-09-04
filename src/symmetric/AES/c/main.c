/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the aes128 symmetric encryption algorithm.
**/

#include "aes128.h"
#include "stdio.h"
#include "inttypes.h"

int main()
{
    struct aes128 a;
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    aes128_init(&a, key);

    return 0;
}
