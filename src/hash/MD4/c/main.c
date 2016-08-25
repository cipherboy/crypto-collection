/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Tests for the md4 hash algorithm.
**/

#include "md4.h"
#include "stdio.h"
#include "strings.h"

void null() {
	uint8_t* result;
	cc_md4 m;
	cc_md4_init(&m);
	cc_md4_update(&m, "", 0);
	cc_md4_finalize(&m);

	printf("Message:  <null>\nExpected: 31d6cfe0d16ae931b73c59d7e0c089c0\nResult:   ");

	for (int i = 0; i < 16; i ++) {
		printf("%02x", m.digest[i]);
	}

	printf("\n\n");
}

void a() {
	uint8_t* result;
	cc_md4 m;
	cc_md4_init(&m);
	cc_md4_update(&m, "a", 1);
	cc_md4_finalize(&m);

	printf("Message:  a\nExpected: bde52cb31de33e46245e05fbdbd6fb24\nResult:   ");

	for (int i = 0; i < 16; i ++) {
		printf("%02x", m.digest[i]);
	}

	printf("\n\n");
}

void abc() {
	uint8_t* result;
	cc_md4 m;
	cc_md4_init(&m);
	cc_md4_update(&m, "abc", 3);
	cc_md4_finalize(&m);

	printf("Message:  abc\nExpected: a448017aaf21d8525fc10ae87aa6729d\nResult:   ");

	for (int i = 0; i < 16; i ++) {
		printf("%02x", m.digest[i]);
	}

	printf("\n\n");
}

int main() {
	null();
	a();
	abc();
}
