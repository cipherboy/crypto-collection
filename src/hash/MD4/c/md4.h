/**
 * Copyright (C) 2016 Alexander Scheel
 *
 * Implementation of the md4 hash algorithm per RFC 1186. See docs for the
 * specification.
**/

#pragma once
#ifndef CC_MD4_H
#define CC_MD4_H

#include "stdint.h"
#include "string.h"

typedef struct {
	uint8_t digest[16];

	uint32_t s[4];
	uint64_t len;

	uint8_t* partial;
	uint64_t p_len;
} cc_md4;

static inline uint32_t cc_md4_f(uint32_t X, uint32_t Y, uint32_t Z) {
	return ((Y ^ Z) & X) ^ Z;
}

static inline uint32_t cc_md4_g(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X & Y) | (X & Z) | (Y & Z);
}

static inline uint32_t cc_md4_h(uint32_t X, uint32_t Y, uint32_t Z) {
	return (X ^ Y) ^ Z;
}

static inline uint32_t cc_md4_rotl32(uint32_t data, uint32_t count) {
	return ((data << count) | (data >> (32 - count)));
}

extern inline void cc_md4_init(cc_md4* m) {
	int i = 0;
	for (i = 0; i < 16; i++) {
		m->digest[i] = 0;
	}

	m->s[0] = 0x67452301;
	m->s[1] = 0xefcdab89;
	m->s[2] = 0x98BADCFE;
	m->s[3] = 0x10325476;

	m->len = 0;
	m->p_len = 0;
}

extern inline void cc_md4_update(cc_md4* m, unsigned char* msg, uint64_t len) {
}

extern inline void cc_md4_finalize(cc_md4* m) {
}

extern inline uint8_t* cc_md4_sum(cc_md4* m, unsigned char* msg) {
	cc_md4_init(m);
	cc_md4_update(m, msg, strlen(msg));
	cc_md4_finalize(m);
	return m->digest;
}

#endif // CC_MD4_H
