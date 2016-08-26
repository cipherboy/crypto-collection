/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the sha256 hash algorithm.
**/

#include "sha256.h"
#include "stdio.h"
#include "strings.h"

void test_null()
{
    struct sha256 m;
    sha256_init(&m);
    sha256_update(&m, "", 0);
    sha256_finalize(&m);

    printf("Message:  <null>\nExpected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdog()
{
    struct sha256 m;
    sha256_init(&m);
    sha256_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha256_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdogperiod()
{
    struct sha256 m;
    sha256_init(&m);
    sha256_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha256_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

int main()
{
    test_null();
    test_foxdog();
    test_foxdogperiod();
}
