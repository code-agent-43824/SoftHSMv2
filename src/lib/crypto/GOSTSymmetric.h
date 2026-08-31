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

#ifndef _SOFTHSM_V2_GOSTSYMMETRIC_H
#define _SOFTHSM_V2_GOSTSYMMETRIC_H

#include <stddef.h>
#include <stdint.h>

// Portable block primitives used by the TC26/Rutoken PKCS #11 mechanisms.
// The byte interfaces use the network-order notation from the standards.
class GOSTSymmetric
{
public:
	enum Cipher
	{
		KUZNECHIK,
		MAGMA
	};

	explicit GOSTSymmetric(Cipher cipher);
	~GOSTSymmetric();

	bool setKey(const unsigned char* key, size_t keyLen);
	void encryptBlock(const unsigned char* in, unsigned char* out) const;
	void decryptBlock(const unsigned char* in, unsigned char* out) const;
	size_t blockSize() const;
	bool ctr(const unsigned char* iv, size_t ivLen, const unsigned char* in,
		unsigned char* out, size_t len) const;
	bool omac(const unsigned char* in, size_t len, unsigned char* out) const;
	bool mgmEncrypt(const unsigned char* icn, const unsigned char* aad, size_t aadLen,
		const unsigned char* plain, size_t plainLen, unsigned char* cipherText,
		unsigned char* tag, size_t tagLen) const;
	bool mgmDecrypt(const unsigned char* icn, const unsigned char* aad, size_t aadLen,
		const unsigned char* cipherText, size_t cipherLen, const unsigned char* tag,
		size_t tagLen, unsigned char* plain) const;

private:
	GOSTSymmetric(const GOSTSymmetric&);
	GOSTSymmetric& operator=(const GOSTSymmetric&);

	void expandKuznechikKey(const unsigned char* key);
	void encryptKuznechik(const unsigned char* in, unsigned char* out) const;
	void decryptKuznechik(const unsigned char* in, unsigned char* out) const;
	void expandMagmaKey(const unsigned char* key);
	void cryptMagma(const unsigned char* in, unsigned char* out, bool decrypt) const;

	Cipher cipher;
	bool keyed;
	unsigned char kuzRoundKeys[10][16];
	uint32_t magmaKey[8];
};

#endif // !_SOFTHSM_V2_GOSTSYMMETRIC_H
