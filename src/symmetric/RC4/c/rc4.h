/*
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the RC4 encryption algorithm. See docs for the
 * specification.
*/

#pragma once
#ifndef CC_RC4_H
#define CC_RC4_H

#include "stdlib.h"
#include "stdio.h"

struct rc4 {
    uint8_t S[256];
    size_t x;
    size_t y;
};

extern inline void rc4_init(struct rc4* r, uint8_t* key, size_t keylen)
{
    size_t i = 0;
    size_t j = 0;
    uint8_t tmp;

    for (i = 0; i < 256; i++) {
        r->S[i] = (uint8_t) i;
    }

    r->x = 0;
    r->y = 0;

    for (i = 0; i < 256; i++) {
        j = (j + r->S[i] + key[i % keylen]) % 256;

        tmp = r->S[i];
        r->S[i] = r->S[j];
        r->S[j] = tmp;
    }
}

extern inline void rc4_stream(struct rc4* r, uint8_t* data, size_t len)
{
    size_t i = 0;
    size_t x = 0;
    uint8_t tmp;

    for (i = 0; i < len; i++) {
        r->x = (r->x + 1) % 256;
        r->y = (r->S[r->x] + r->y) % 256;

        tmp = r->S[r->x];
        r->S[r->x] = r->S[r->y];
        r->S[r->y] = tmp;

        x = (r->S[r->x] + r->S[r->y]) % 256;

        data[i] = r->S[x];
    }
}


#endif
