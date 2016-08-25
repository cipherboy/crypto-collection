/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the md5 hash algorithm.
**/

#include "md4.h"
#include "stdio.h"
#include "strings.h"

void test_null()
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, "", 0);
    md4_finalize(&m);

    printf("Message:  <null>\nExpected: 31d6cfe0d16ae931b73c59d7e0c089c0\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_a()
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, "a", 1);
    md4_finalize(&m);

    printf("Message:  a\nExpected: bde52cb31de33e46245e05fbdbd6fb24\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_abc()
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, "abc", 3);
    md4_finalize(&m);

    printf("Message:  abc\nExpected: a448017aaf21d8525fc10ae87aa6729d\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdog()
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    md4_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 1bee69a46ba811185c194762abaeae90\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxcog()
{
    struct md4 m;
    md4_init(&m);
    md4_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    md4_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: b86e130ce7028da59e672d56ad0113df\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

int main()
{
    test_null();
    test_a();
    test_abc();
    test_foxdog();
    test_foxcog();
}
