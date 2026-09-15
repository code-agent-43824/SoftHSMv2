/*
 * Copyright (c) 2026 code-agent-43824
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

/*****************************************************************************
 BotanGOSTCurves.cpp

 The one place that turns a GOST R 34.10 curve OID into a curve.
 *****************************************************************************/

#include "BotanGOSTCurves.h"

#include <botan/bigint.h>
#include <botan/point_gfp.h>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace
{
struct Domain
{
	Botan::BigInt p, a, b, x, y, order, cofactor;
};

	// id-tc26-gost-3410-2012-256-paramSetA, RFC 7836 A.2
	static const Domain tc26_256_A = {
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
			Botan::BigInt("0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
			Botan::BigInt("0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
			Botan::BigInt("0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
			Botan::BigInt("0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
			Botan::BigInt("0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
			Botan::BigInt(4)
	};
	// id-GostR3410-2001-CryptoPro-A-ParamSet, RFC 4357 11.4
	static const Domain cryptoPro_A = {
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94"),
			Botan::BigInt("0x00000000000000000000000000000000000000000000000000000000000000A6"),
			Botan::BigInt("0x0000000000000000000000000000000000000000000000000000000000000001"),
			Botan::BigInt("0x8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14"),
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893"),
			Botan::BigInt(1)
	};
	// id-tc26-gost-3410-12-512-paramSetA, RFC 7836 A.1
	static const Domain tc26_512_A = {
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC4"),
			Botan::BigInt("0xE8C2505DEDFC86DDC1BD0B2B6667F1DA34B82574761CB0E879BD081CFD0B6265"
			              "EE3CB090F30D27614CB4574010DA90DD862EF9D4EBEE4761503190785A71C760"),
			Botan::BigInt("0x0000000000000000000000000000000000000000000000000000000000000000"
			              "0000000000000000000000000000000000000000000000000000000000000003"),
			Botan::BigInt("0x7503CFE87A836AE3A61B8816E25450E6CE5E1C93ACF1ABC1778064FDCBEFA921"
			              "DF1626BE4FD036E93D75E6A50E3A41E98028FE5FC235F5B889A589CB5215F2A4"),
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			              "27E69532F48D89116FF22B8D4E0560609B4B38ABFAD2B85DCACDB1411F10B275"),
			Botan::BigInt(1)
	};
	// id-tc26-gost-3410-12-512-paramSetB, RFC 7836 A.1
	static const Domain tc26_512_B = {
			Botan::BigInt("0x8000000000000000000000000000000000000000000000000000000000000000"
			              "000000000000000000000000000000000000000000000000000000000000006F"),
			Botan::BigInt("0x8000000000000000000000000000000000000000000000000000000000000000"
			              "000000000000000000000000000000000000000000000000000000000000006C"),
			Botan::BigInt("0x687D1B459DC841457E3E06CF6F5E2517B97C7D614AF138BCBF85DC806C4B289F"
			              "3E965D2DB1416D217F8B276FAD1AB69C50F78BEE1FA3106EFB8CCBC7C5140116"),
			Botan::BigInt("0x0000000000000000000000000000000000000000000000000000000000000000"
			              "0000000000000000000000000000000000000000000000000000000000000002"),
			Botan::BigInt("0x1A8F7EDA389B094C2C071E3647A8940F3C123B697578C213BE6DD9E6C8EC7335"
			              "DCB228FD1EDF4A39152CBCAAF8C0398828041055F94CEEEC7E21340780FE41BD"),
			Botan::BigInt("0x8000000000000000000000000000000000000000000000000000000000000001"
			              "49A1EC142565A545ACFDB77BD9D40CFA8B996712101BEA0EC6346C54374F25BD"),
			Botan::BigInt(1)
	};
	// id-tc26-gost-3410-2012-512-paramSetC, RFC 7836 A.2
	static const Domain tc26_512_C = {
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			              "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFDC7"),
			Botan::BigInt("0xDC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645"
			              "46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"),
			Botan::BigInt("0xB4C4EE28CEBC6C2C8AC12952CF37F16AC7EFB6A9F69F4B57FFDA2E4F0DE5ADE0"
			              "38CBC2FFF719D2C18DE0284B8BFEF3B52B8CC7A5F5BF0A3C8D2319A5312557E1"),
			Botan::BigInt("0xE2E31EDFC23DE7BDEBE241CE593EF5DE2295B7A9CBAEF021D385F7074CEA043A"
			              "A27272A7AE602BF2A7B9033DB9ED3610C6FB85487EAE97AAC5BC7928C1950148"),
			Botan::BigInt("0xF5CE40D95B5EB899ABBCCFF5911CB8577939804D6527378B8C108C3D2090FF9B"
			              "E18E2D33E3021ED2EF32D85822423B6304F726AA854BAE07D0396E9A9ADDC40F"),
			Botan::BigInt("0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
			              "C98CDBA46506AB004C33A9FF5147502CC8EDA9E7A769A12694623CEF47F023ED"),
			Botan::BigInt(4)
	};

// The encoded OIDs, as they arrive in CKA_GOSTR3410_PARAMS: a DER OBJECT
// IDENTIFIER, tag and length included.
struct Entry
{
	const uint8_t* oid;
	size_t length;
	const Domain* domain;
};

const uint8_t oidTC26_256_A[] = {0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x01};
const uint8_t oidTC26_256_B[] = {0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x02};
const uint8_t oidCryptoProA[] = {0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x01};
const uint8_t oidCryptoProXchA[] = {0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x24,0x00};
const uint8_t oidTC26_512_A[] = {0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x01};
const uint8_t oidTC26_512_B[] = {0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x02};
const uint8_t oidTC26_512_C[] = {0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x03};

// 1.2.643.7.1.2.1.1.2, 1.2.643.2.2.35.1 and 1.2.643.2.2.36.0 are three names
// for one curve, and that is not an approximation made here: RFC 9215
// Appendix C says the TC26 256-bit paramSetB is the curve of
// id-GostR3410-2001-CryptoPro-A-ParamSet, and RFC 4357 gives CryptoPro-XchA
// the same domain as CryptoPro-A. The TC26 256-bit paramSetA above is a
// genuinely different curve that merely shares the prime.
const Entry table[] = {
	{oidTC26_256_A,    sizeof(oidTC26_256_A),    &tc26_256_A},
	{oidTC26_256_B,    sizeof(oidTC26_256_B),    &cryptoPro_A},
	{oidCryptoProA,    sizeof(oidCryptoProA),    &cryptoPro_A},
	{oidCryptoProXchA, sizeof(oidCryptoProXchA), &cryptoPro_A},
	{oidTC26_512_A,    sizeof(oidTC26_512_A),    &tc26_512_A},
	{oidTC26_512_B,    sizeof(oidTC26_512_B),    &tc26_512_B},
	{oidTC26_512_C,    sizeof(oidTC26_512_C),    &tc26_512_C}
};

const Domain* lookup(const ByteString& encodedCurveOID)
{
	for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); ++i)
	{
		if (encodedCurveOID.size() == table[i].length &&
		    std::memcmp(encodedCurveOID.const_byte_str(), table[i].oid, table[i].length) == 0)
			return table[i].domain;
	}
	return NULL;
}
}

bool BotanGOSTCurves::supported(const ByteString& encodedCurveOID)
{
	return lookup(encodedCurveOID) != NULL;
}

Botan::EC_Group BotanGOSTCurves::group(const ByteString& encodedCurveOID)
{
	const Domain* domain = lookup(encodedCurveOID);
	if (domain == NULL)
		throw std::runtime_error("no domain parameters for this GOST curve OID");
	return Botan::EC_Group(domain->p, domain->a, domain->b,
	                       domain->x, domain->y, domain->order, domain->cofactor);
}

size_t BotanGOSTCurves::orderBits(const ByteString& encodedCurveOID)
{
	const Domain* domain = lookup(encodedCurveOID);
	if (domain == NULL) return 0;
	// paramSetC's order is 510 bits inside a 512-bit field, and the 256-bit
	// paramSetA's is 255 bits, so the field is what a caller means by "size".
	return domain->p.bytes() * 8;
}

bool BotanGOSTCurves::pointIsOnCurve(const ByteString& encodedCurveOID,
                                     const ByteString& publicValue)
{
	const Domain* domain = lookup(encodedCurveOID);
	if (domain == NULL) return false;
	const size_t fieldBytes = domain->p.bytes();
	if (publicValue.size() != 2 * fieldBytes) return false;

	try
	{
		// PKCS #11 carries GOST coordinates as little-endian X || Y; Botan's
		// uncompressed encoding is 0x04 || X || Y, big-endian.
		std::vector<uint8_t> encoded(1 + 2 * fieldBytes);
		encoded[0] = 0x04;
		const unsigned char* bytes = publicValue.const_byte_str();
		for (size_t i = 0; i < fieldBytes; ++i)
		{
			encoded[1 + i] = bytes[fieldBytes - 1 - i];
			encoded[1 + fieldBytes + i] = bytes[2 * fieldBytes - 1 - i];
		}
		const Botan::EC_Group curve = group(encodedCurveOID);
		const Botan::PointGFp point = curve.OS2ECP(encoded);
		return curve.verify_public_element(point);
	}
	catch (const std::exception&)
	{
		// OS2ECP throws for a point that is not on the curve, which is the
		// answer being asked for rather than an error.
		return false;
	}
}
