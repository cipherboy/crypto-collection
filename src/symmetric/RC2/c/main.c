/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the RC2 symmetric encryption algorithm.
**/

#include "rc2.h"
#include "stdio.h"

int main()
{
    struct rc2 r;
    uint8_t key[8] = {0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint16_t plaintext[4] = {0x010, 0x0000, 0x0000, 0x0100};
    rc2_init(&r, (uint8_t*) key, 8, 64);
    rc2_encrypt(&r, (uint16_t*)  plaintext);
    printf("\n%04x%04x,%04x%04x\n", r.R[0], r.R[1], r.R[2], r.R[3]);
    printf("\n%02x%02x\n", ( r.R[0]) >> 8, ((uint8_t) r.R[0]));
    return 0;
}
