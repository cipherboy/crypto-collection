/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the sha256 hash algorithm.
**/

#include "sha224.h"
#include "sha256.h"
#include "stdio.h"
#include "strings.h"

void test_sha224_null()
{
    struct sha224 m;
    sha224_init(&m);
    sha224_update(&m, "", 0);
    sha224_finalize(&m);

    printf("Message:  <null>\nExpected: d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha256_null()
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

void test_sha224_foxdog()
{
    struct sha224 m;
    sha224_init(&m);
    sha224_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha224_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha256_foxdog()
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

void test_sha224_foxcog()
{
    struct sha224 m;
    sha224_init(&m);
    sha224_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha224_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha256_foxcog()
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
    printf("\nSHA224\n");
    test_sha224_null();
    test_sha224_foxdog();
    test_sha224_foxcog();

    printf("\nSHA256\n");
    test_sha256_null();
    test_sha256_foxdog();
    test_sha256_foxcog();
}
