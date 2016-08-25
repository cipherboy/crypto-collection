/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the md5 hash algorithm.
**/

#include "md5.h"
#include "stdio.h"
#include "strings.h"

void test_null()
{
    struct md5 m;
    md5_init(&m);
    md5_update(&m, "", 0);
    md5_finalize(&m);

    printf("Message:  <null>\nExpected: d41d8cd98f00b204e9800998ecf8427e\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdog()
{
    struct md5 m;
    md5_init(&m);
    md5_update(&m, "The quick brown fox jumps over the lazy dog", 43);
    md5_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog\nExpected: 9e107d9d372bb6826bd81d3542a419d6\nResult:   ");

    for (int i = 0; i < 16; i ++) {
        printf("%02x", m.digest[i]);
    }

    printf("\n\n");
}

void test_foxdogperiod()
{
    struct md5 m;
    md5_init(&m);
    md5_update(&m, "The quick brown fox jumps over the lazy dog.", 44);
    md5_finalize(&m);

    printf("Message:  The quick brown fox jumps over the lazy dog.\nExpected: e4d909c290d0fb1ca068ffaddf22cbd0\nResult:   ");

    for (int i = 0; i < 16; i ++) {
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
