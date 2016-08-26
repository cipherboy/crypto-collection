/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the sha1 hash algorithm.
**/

#include "sha1.h"
#include "stdio.h"
#include "strings.h"

void test_null()
{
    struct sha1 m;
    sha1_init(&m);
    sha1_update(&m, "", 0);
    sha1_finalize(&m);

    printf("Message:  <null>\nExpected: da39a3ee5e6b4b0d3255bfef95601890afd80709\nResult:   ");

    for (int i = 0; i < 20; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdog()
{
    struct sha1 m;
    sha1_init(&m);
    sha1_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha1_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12\nResult:   ");

    for (int i = 0; i < 20; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdogperiod()
{
    struct sha1 m;
    sha1_init(&m);
    sha1_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha1_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: de9f2c7fd25e1b3afad3e85a0bd17d9b100db4b3\nResult:   ");

    for (int i = 0; i < 20; i ++) {
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
