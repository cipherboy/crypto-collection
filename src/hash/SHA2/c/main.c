/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the sha2 hash algorithm.
**/

#include "sha2_224.h"
#include "sha2_256.h"
#include "sha2_384.h"
#include "sha2_512.h"
#include "stdio.h"
#include "strings.h"

void test_sha2_224_null()
{
    struct sha2_224 m;
    sha2_224_init(&m);
    sha2_224_update(&m, "", 0);
    sha2_224_finalize(&m);

    printf("Message:  <null>\nExpected: d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_256_null()
{
    struct sha2_256 m;
    sha2_256_init(&m);
    sha2_256_update(&m, "", 0);
    sha2_256_finalize(&m);

    printf("Message:  <null>\nExpected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_384_null()
{
    struct sha2_384 m;
    sha2_384_init(&m);
    sha2_384_update(&m, "", 0);
    sha2_384_finalize(&m);

    printf("Message:  <null>\nExpected: 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b\nResult:   ");

    for (int i = 0; i < 48; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_512_null()
{
    struct sha2_512 m;
    sha2_512_init(&m);
    sha2_512_update(&m, "", 0);
    sha2_512_finalize(&m);

    printf("Message:  <null>\nExpected: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\nResult:   ");

    for (int i = 0; i < 64; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_224_foxdog()
{
    struct sha2_224 m;
    sha2_224_init(&m);
    sha2_224_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha2_224_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_256_foxdog()
{
    struct sha2_256 m;
    sha2_256_init(&m);
    sha2_256_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha2_256_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_384_foxdog()
{
    struct sha2_384 m;
    sha2_384_init(&m);
    sha2_384_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha2_384_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: ca737f1014a48f4c0b6dd43cb177b0afd9e5169367544c494011e3317dbf9a509cb1e5dc1e85a941bbee3d7f2afbc9b1\nResult:   ");

    for (int i = 0; i < 48; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_512_foxdog()
{
    struct sha2_512 m;
    sha2_512_init(&m);
    sha2_512_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha2_512_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6\nResult:   ");

    for (int i = 0; i < 64; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_224_foxcog()
{
    struct sha2_224 m;
    sha2_224_init(&m);
    sha2_224_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha2_224_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_256_foxcog()
{
    struct sha2_256 m;
    sha2_256_init(&m);
    sha2_256_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha2_256_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be\nResult:   ");

    for (int i = 0; i < 32; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_384_foxcog()
{
    struct sha2_384 m;
    sha2_384_init(&m);
    sha2_384_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha2_384_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: 098cea620b0978caa5f0befba6ddcf22764bea977e1c70b3483edfdf1de25f4b40d6cea3cadf00f809d422feb1f0161b\nResult:   ");

    for (int i = 0; i < 48; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_sha2_512_foxcog()
{
    struct sha2_512 m;
    sha2_512_init(&m);
    sha2_512_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha2_512_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: 3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045\nResult:   ");

    for (int i = 0; i < 64; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

int main()
{
    printf("\nSHA224\n");
    test_sha2_224_null();
    test_sha2_224_foxdog();
    test_sha2_224_foxcog();

    printf("\nSHA256\n");
    test_sha2_256_null();
    test_sha2_256_foxdog();
    test_sha2_256_foxcog();

    printf("\nSHA384\n");
    test_sha2_384_null();
    test_sha2_384_foxdog();
    test_sha2_384_foxcog();

    printf("\nSHA512\n");
    test_sha2_512_null();
    test_sha2_512_foxdog();
    test_sha2_512_foxcog();
}
