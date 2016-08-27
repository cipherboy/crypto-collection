/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the sha256 hash algorithm.
**/

#include "sha224.h"
#include "sha256.h"
#include "sha512.h"
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
/*
void test_sha384_null()
{
    struct sha384 m;
    sha384_init(&m);
    sha384_update(&m, "", 0);
    sha384_finalize(&m);

    printf("Message:  <null>\nExpected: d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}*/

void test_sha512_null()
{
    struct sha512 m;
    sha512_init(&m);
    sha512_update(&m, "", 0);
    sha512_finalize(&m);

    printf("Message:  <null>\nExpected: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e\nResult:   ");

    for (int i = 0; i < 64; i ++) {
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
/*
void test_sha384_foxdog()
{
    struct sha384 m;
    sha384_init(&m);
    sha384_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha384_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}
*/
void test_sha512_foxdog()
{
    struct sha512 m;
    sha512_init(&m);
    sha512_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    sha512_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6\nResult:   ");

    for (int i = 0; i < 64; i ++) {
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
/*
void test_sha384_foxcog()
{
    struct sha384 m;
    sha384_init(&m);
    sha384_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha384_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: fee755f44a55f20fb3362cdc3c493615b3cb574ed95ce610ee5b1e9b\nResult:   ");

    for (int i = 0; i < 28; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}*/

void test_sha512_foxcog()
{
    struct sha512 m;
    sha512_init(&m);
    sha512_update(&m, "The quick brown fox jumps over the lazy cog", 43);
    sha512_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy cog\nExpected: 3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045\nResult:   ");

    for (int i = 0; i < 64; i ++) {
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

    printf("\nSHA512\n");
    test_sha512_null();
    test_sha512_foxdog();
    test_sha512_foxcog();
}
