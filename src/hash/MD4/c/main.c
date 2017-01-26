/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the md4 hash algorithm.
**/

#include "md4.h"
#include "stdio.h"
#include "strings.h"
#include "time.h"

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

time_t benchmark_driver(int size)
{
    struct md4 m;
    md4_init(&m);

    time_t start = time(NULL);

    for (int i = 0; i < size; i++) {
        md4_update(&m,
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                   "aaaa",
                   1024);
    }

    md4_finalize(&m);

    time_t end = time(NULL);

    printf("Message: \"a\"*1024*%d\nResult:  ", size);

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }
    printf("\n");

    return end - start;
}

void benchmark()
{
    printf("Benchmark: 8GB of data: %ju seconds\n",
           benchmark_driver(8 * 1024 * 1024));
}

int main()
{
    test_null();
    test_a();
    test_abc();
    test_foxdog();
    test_foxcog();
    benchmark();
}
