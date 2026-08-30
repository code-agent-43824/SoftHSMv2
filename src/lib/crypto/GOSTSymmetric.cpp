/*
 * Copyright (c) 2026 The SoftHSM project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

#include "GOSTSymmetric.h"
#include <string.h>

namespace
{
const unsigned char kuzPi[256] = {
	252,238,221,17,207,110,49,22,251,196,250,218,35,197,4,77,
	233,119,240,219,147,46,153,186,23,54,241,187,20,205,95,193,
	249,24,101,90,226,92,239,33,129,28,60,66,139,1,142,79,
	5,132,2,174,227,106,143,160,6,11,237,152,127,212,211,31,
	235,52,44,81,234,200,72,171,242,42,104,162,253,58,206,204,
	181,112,14,86,8,12,118,18,191,114,19,71,156,183,93,135,
	21,161,150,41,16,123,154,199,243,145,120,111,157,158,178,177,
	50,117,25,61,255,53,138,126,109,84,198,128,195,189,13,87,
	223,245,36,169,62,168,67,201,215,121,214,246,124,34,185,3,
	224,15,236,222,122,148,176,188,220,232,40,80,78,51,10,74,
	167,151,96,115,30,0,98,68,26,184,56,130,100,159,38,65,
	173,69,70,146,39,94,85,47,140,163,165,125,105,213,149,59,
	7,88,179,64,134,172,29,247,48,55,107,228,136,217,231,137,
	225,27,131,73,76,63,248,254,141,83,170,144,202,216,133,97,
	32,113,103,164,45,43,9,91,203,155,37,208,190,229,108,82,
	89,166,116,210,230,244,180,192,209,102,175,194,57,75,99,182
};

const unsigned char kuzL[16] = {
	148,32,133,16,194,192,1,251,1,192,194,16,133,32,148,1
};

const unsigned char magmaPi[8][16] = {
	{12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
	{6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
	{11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
	{12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
	{7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
	{5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
	{8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
	{1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
};

unsigned char gfMul(unsigned char a, unsigned char b)
{
	unsigned char r = 0;
	while (b != 0)
	{
		if (b & 1) r ^= a;
		a = (unsigned char)((a << 1) ^ ((a & 0x80) ? 0xc3 : 0));
		b >>= 1;
	}
	return r;
}

void kuzR(unsigned char x[16])
{
	unsigned char z = 0;
	for (size_t i = 0; i < 16; ++i) z ^= gfMul(x[i], kuzL[i]);
	for (size_t i = 15; i != 0; --i) x[i] = x[i - 1];
	x[0] = z;
}

void kuzRInv(unsigned char x[16])
{
	unsigned char z = x[0];
	for (size_t i = 0; i < 15; ++i)
	{
		x[i] = x[i + 1];
		z ^= gfMul(x[i], kuzL[i]);
	}
	x[15] = z;
}

void kuzLTransform(unsigned char x[16])
{
	for (size_t i = 0; i < 16; ++i) kuzR(x);
}

void kuzLInv(unsigned char x[16])
{
	for (size_t i = 0; i < 16; ++i) kuzRInv(x);
}

void kuzS(unsigned char x[16])
{
	for (size_t i = 0; i < 16; ++i) x[i] = kuzPi[x[i]];
}

void kuzSInv(unsigned char x[16])
{
	static unsigned char inv[256];
	static bool initialized = false;
	if (!initialized)
	{
		for (size_t i = 0; i < 256; ++i) inv[kuzPi[i]] = (unsigned char)i;
		initialized = true;
	}
	for (size_t i = 0; i < 16; ++i) x[i] = inv[x[i]];
}

void xorBlock(unsigned char* a, const unsigned char* b, size_t n)
{
	for (size_t i = 0; i < n; ++i) a[i] ^= b[i];
}

uint32_t loadBE32(const unsigned char* p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void storeBE32(unsigned char* p, uint32_t v)
{
	p[0] = (unsigned char)(v >> 24);
	p[1] = (unsigned char)(v >> 16);
	p[2] = (unsigned char)(v >> 8);
	p[3] = (unsigned char)v;
}

uint32_t rotl32(uint32_t x, unsigned int n)
{
	return (x << n) | (x >> (32 - n));
}

uint32_t magmaG(uint32_t k, uint32_t a)
{
	uint32_t x = k + a;
	uint32_t y = 0;
	for (size_t i = 0; i < 8; ++i)
		y |= (uint32_t)magmaPi[i][(x >> (4 * i)) & 0xf] << (4 * i);
	return rotl32(y, 11);
}
}

GOSTSymmetric::GOSTSymmetric(Cipher cipher) : cipher(cipher), keyed(false)
{
	memset(kuzRoundKeys, 0, sizeof(kuzRoundKeys));
	memset(magmaKey, 0, sizeof(magmaKey));
}

GOSTSymmetric::~GOSTSymmetric()
{
	volatile unsigned char* p = reinterpret_cast<volatile unsigned char*>(kuzRoundKeys);
	for (size_t i = 0; i < sizeof(kuzRoundKeys); ++i) p[i] = 0;
	p = reinterpret_cast<volatile unsigned char*>(magmaKey);
	for (size_t i = 0; i < sizeof(magmaKey); ++i) p[i] = 0;
}

bool GOSTSymmetric::setKey(const unsigned char* key, size_t keyLen)
{
	if (key == NULL || keyLen != 32) return false;
	if (cipher == KUZNECHIK) expandKuznechikKey(key);
	else expandMagmaKey(key);
	keyed = true;
	return true;
}

size_t GOSTSymmetric::blockSize() const
{
	return cipher == KUZNECHIK ? 16 : 8;
}

void GOSTSymmetric::encryptBlock(const unsigned char* in, unsigned char* out) const
{
	if (!keyed || in == NULL || out == NULL) return;
	if (cipher == KUZNECHIK) encryptKuznechik(in, out);
	else cryptMagma(in, out, false);
}

void GOSTSymmetric::decryptBlock(const unsigned char* in, unsigned char* out) const
{
	if (!keyed || in == NULL || out == NULL) return;
	if (cipher == KUZNECHIK) decryptKuznechik(in, out);
	else cryptMagma(in, out, true);
}

void GOSTSymmetric::expandKuznechikKey(const unsigned char* key)
{
	memcpy(kuzRoundKeys[0], key, 16);
	memcpy(kuzRoundKeys[1], key + 16, 16);
	unsigned char a[16], b[16], c[16], t[16];
	memcpy(a, key, 16);
	memcpy(b, key + 16, 16);
	for (size_t i = 1; i <= 32; ++i)
	{
		memset(c, 0, sizeof(c));
		c[15] = (unsigned char)i;
		kuzLTransform(c);
		memcpy(t, a, sizeof(t));
		xorBlock(t, c, sizeof(t));
		kuzS(t);
		kuzLTransform(t);
		xorBlock(t, b, sizeof(t));
		memcpy(b, a, sizeof(b));
		memcpy(a, t, sizeof(a));
		if ((i % 8) == 0)
		{
			memcpy(kuzRoundKeys[(i / 8) * 2], a, 16);
			memcpy(kuzRoundKeys[(i / 8) * 2 + 1], b, 16);
		}
	}
	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	memset(c, 0, sizeof(c));
	memset(t, 0, sizeof(t));
}

void GOSTSymmetric::encryptKuznechik(const unsigned char* in, unsigned char* out) const
{
	unsigned char x[16];
	memcpy(x, in, sizeof(x));
	for (size_t i = 0; i < 9; ++i)
	{
		xorBlock(x, kuzRoundKeys[i], sizeof(x));
		kuzS(x);
		kuzLTransform(x);
	}
	xorBlock(x, kuzRoundKeys[9], sizeof(x));
	memcpy(out, x, sizeof(x));
	memset(x, 0, sizeof(x));
}

void GOSTSymmetric::decryptKuznechik(const unsigned char* in, unsigned char* out) const
{
	unsigned char x[16];
	memcpy(x, in, sizeof(x));
	xorBlock(x, kuzRoundKeys[9], sizeof(x));
	for (size_t i = 9; i != 0; --i)
	{
		kuzLInv(x);
		kuzSInv(x);
		xorBlock(x, kuzRoundKeys[i - 1], sizeof(x));
	}
	memcpy(out, x, sizeof(x));
	memset(x, 0, sizeof(x));
}

void GOSTSymmetric::expandMagmaKey(const unsigned char* key)
{
	for (size_t i = 0; i < 8; ++i) magmaKey[i] = loadBE32(key + i * 4);
}

void GOSTSymmetric::cryptMagma(const unsigned char* in, unsigned char* out, bool decrypt) const
{
	uint32_t a1 = loadBE32(in);
	uint32_t a0 = loadBE32(in + 4);
	for (size_t round = 0; round < 31; ++round)
	{
		size_t keyIndex;
		if (!decrypt)
			keyIndex = round < 24 ? round % 8 : 7 - (round % 8);
		else
			keyIndex = round < 8 ? round : 7 - (round % 8);
		uint32_t next = a0;
		a0 = a1 ^ magmaG(magmaKey[keyIndex], a0);
		a1 = next;
	}
	size_t lastKey = decrypt ? 0 : 0;
	uint32_t result = a1 ^ magmaG(magmaKey[lastKey], a0);
	storeBE32(out, result);
	storeBE32(out + 4, a0);
}
