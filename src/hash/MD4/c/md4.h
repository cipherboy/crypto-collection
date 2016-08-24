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

static inline void cc_md4_core(cc_md4* m, uint32_t block[16]) {
	uint32_t s[4];
	// Duplicate state
	s[0] = m->s[0];
	s[1] = m->s[1];
	s[2] = m->s[2];
	s[3] = m->s[3];

	// Round 1
	s[0] = cc_md4_rotl32(s[0]+cc_md4_f(s[1], s[2], s[3])+block[0], 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_f(s[0], s[1], s[2])+block[1], 7);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_f(s[3], s[0], s[1])+block[2], 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_f(s[2], s[3], s[0])+block[3], 19);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_f(s[1], s[2], s[3])+block[4], 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_f(s[0], s[1], s[2])+block[5], 7);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_f(s[3], s[0], s[1])+block[6], 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_f(s[2], s[3], s[0])+block[7], 19);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_f(s[1], s[2], s[3])+block[8], 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_f(s[0], s[1], s[2])+block[9], 7);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_f(s[3], s[0], s[1])+block[10], 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_f(s[2], s[3], s[0])+block[11], 19);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_f(s[1], s[2], s[3])+block[12], 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_f(s[0], s[1], s[2])+block[13], 7);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_f(s[3], s[0], s[1])+block[14], 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_f(s[2], s[3], s[0])+block[15], 19);

	// Round 2
	s[0] = cc_md4_rotl32(s[0]+cc_md4_g(s[1], s[2], s[3])+block[0]+0x5A827999, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_g(s[0], s[1], s[2])+block[4]+0x5A827999, 5);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_g(s[3], s[0], s[1])+block[8]+0x5A827999, 9);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_g(s[2], s[3], s[0])+block[12]+0x5A827999, 13);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_g(s[1], s[2], s[3])+block[1]+0x5A827999, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_g(s[0], s[1], s[2])+block[5]+0x5A827999, 5);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_g(s[3], s[0], s[1])+block[9]+0x5A827999, 9);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_g(s[2], s[3], s[0])+block[13]+0x5A827999, 13);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_g(s[1], s[2], s[3])+block[2]+0x5A827999, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_g(s[0], s[1], s[2])+block[6]+0x5A827999, 5);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_g(s[3], s[0], s[1])+block[10]+0x5A827999, 9);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_g(s[2], s[3], s[0])+block[14]+0x5A827999, 13);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_g(s[1], s[2], s[3])+block[3]+0x5A827999, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_g(s[0], s[1], s[2])+block[7]+0x5A827999, 5);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_g(s[3], s[0], s[1])+block[11]+0x5A827999, 9);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_g(s[2], s[3], s[0])+block[15]+0x5A827999, 13);

	// Round 3
	s[0] = cc_md4_rotl32(s[0]+cc_md4_h(s[1], s[2], s[3])+block[0]+0x6ED9EBA1, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_h(s[0], s[1], s[2])+block[8]+0x6ED9EBA1, 9);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_h(s[3], s[0], s[1])+block[4]+0x6ED9EBA1, 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_h(s[2], s[3], s[0])+block[12]+0x6ED9EBA1, 15);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_h(s[1], s[2], s[3])+block[2]+0x6ED9EBA1, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_h(s[0], s[1], s[2])+block[10]+0x6ED9EBA1, 9);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_h(s[3], s[0], s[1])+block[6]+0x6ED9EBA1, 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_h(s[2], s[3], s[0])+block[14]+0x6ED9EBA1, 15);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_h(s[1], s[2], s[3])+block[1]+0x6ED9EBA1, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_h(s[0], s[1], s[2])+block[9]+0x6ED9EBA1, 9);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_h(s[3], s[0], s[1])+block[5]+0x6ED9EBA1, 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_h(s[2], s[3], s[0])+block[13]+0x6ED9EBA1, 15);
	s[0] = cc_md4_rotl32(s[0]+cc_md4_h(s[1], s[2], s[3])+block[3]+0x6ED9EBA1, 3);
	s[3] = cc_md4_rotl32(s[3]+cc_md4_h(s[0], s[1], s[2])+block[11]+0x6ED9EBA1, 9);
	s[2] = cc_md4_rotl32(s[2]+cc_md4_h(s[3], s[0], s[1])+block[7]+0x6ED9EBA1, 11);
	s[1] = cc_md4_rotl32(s[1]+cc_md4_h(s[2], s[3], s[0])+block[15]+0x6ED9EBA1, 15);

	// Add back to md4 state.
	m->s[0] += s[0];
	m->s[1] += s[1];
	m->s[2] += s[2];
	m->s[3] += s[3];
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

extern inline void cc_md4_update(cc_md4* m, char* msg, uint64_t len) {

}

extern inline void cc_md4_finalize(cc_md4* m) {
}

extern inline uint8_t* cc_md4_sum(cc_md4* m, char* msg) {
	cc_md4_init(m);
	cc_md4_update(m, msg, strlen(msg));
	cc_md4_finalize(m);
	return m->digest;
}

#endif // CC_MD4_H
