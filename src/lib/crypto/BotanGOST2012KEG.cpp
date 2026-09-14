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

#include "config.h"
#include "BotanGOST2012KEG.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "log.h"

#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <botan/hash.h>
#include <botan/rng.h>
#include <botan/secmem.h>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace
{
class SoftHSMGOST2012KEGRNG : public Botan::RandomNumberGenerator
{
public:
	explicit SoftHSMGOST2012KEGRNG(RNG* source) : source(source) {}

	void randomize(uint8_t output[], size_t length) override
	{
		ByteString random;
		if (source == NULL || !source->generateRandom(random, length))
			throw std::runtime_error("SoftHSM random number generation failed");
		if (length != 0) std::memcpy(output, random.const_byte_str(), length);
	}

	bool accepts_input() const override { return false; }
	void add_entropy(const uint8_t[], size_t) override {}
	std::string name() const override { return "SoftHSM crypto-backend RNG"; }
	void clear() override {}
	bool is_seeded() const override { return source != NULL; }

private:
	RNG* source;
};

bool oidIs(const ByteString& encodedCurveOID, const uint8_t* oid, size_t length)
{
	return encodedCurveOID.size() == length &&
	       std::memcmp(encodedCurveOID.const_byte_str(), oid, length) == 0;
}

// Botan 2.19 knows only some of the curves KEG can be asked for, and for one
// of them it knows the wrong one. Each domain given explicitly below was taken
// from RFC 7836 and checked against it digit by digit; where Botan does have
// the curve and has it right, its named group is used.
//
//   1.2.643.7.1.2.1.1.1  256-bit ParamSet A - Botan resolves this OID to the
//                        older CryptoPro-A curve. Same field size, so a length
//                        check passes, but different points and a different
//                        order: cofactor 4, not 1. Given explicitly.
//   1.2.643.7.1.2.1.2.1  512-bit ParamSet A - Botan's gost_512A, verified
//                        against RFC 7836 (p, a, b, order, cofactor 1). Used
//                        as a named group.
//   1.2.643.7.1.2.1.2.2  512-bit ParamSet B - Botan does not know it.
//   1.2.643.7.1.2.1.2.3  512-bit ParamSet C - Botan does not know it. Cofactor
//                        4; this is the curve the published TC26 KEG example
//                        for 512-bit keys uses, so without it that example
//                        cannot be checked at all.
Botan::EC_Group gostGroup(const ByteString& encodedCurveOID)
{
	static const uint8_t tc26ParamSetA256[] =
		{0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x01, 0x01};
	static const uint8_t tc26ParamSetB512[] =
		{0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x02};
	static const uint8_t tc26ParamSetC512[] =
		{0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x03};

	if (oidIs(encodedCurveOID, tc26ParamSetA256, sizeof(tc26ParamSetA256)))
	{
		return Botan::EC_Group(
			Botan::BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97"),
			Botan::BigInt("0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"),
			Botan::BigInt("0x295F9BAE7428ED9CCC20E7C359A9D41A22FCCD9108E17BF7BA9337A6F8AE9513"),
			Botan::BigInt("0x91E38443A5E82C0D880923425712B2BB658B9196932E02C78B2582FE742DAA28"),
			Botan::BigInt("0x32879423AB1A0375895786C4BB46E9565FDE0B5344766740AF268ADB32322E5C"),
			Botan::BigInt("0x400000000000000000000000000000000FD8CDDFC87B6635C115AF556C360C67"),
			Botan::BigInt(4));
	}
	if (oidIs(encodedCurveOID, tc26ParamSetB512, sizeof(tc26ParamSetB512)))
	{
		return Botan::EC_Group(
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
			Botan::BigInt(1));
	}
	if (oidIs(encodedCurveOID, tc26ParamSetC512, sizeof(tc26ParamSetC512)))
	{
		return Botan::EC_Group(
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
			Botan::BigInt(4));
	}

	std::vector<uint8_t> encodedCurve(encodedCurveOID.size());
	if (!encodedCurve.empty())
		std::memcpy(encodedCurve.data(), encodedCurveOID.const_byte_str(), encodedCurve.size());
	return Botan::EC_Group(encodedCurve);
}

Botan::secure_vector<uint8_t> streebog(const char* algorithm, const uint8_t* data, size_t length)
{
	std::unique_ptr<Botan::HashFunction> hash =
		Botan::HashFunction::create_or_throw(algorithm);
	if (length != 0) hash->update(data, length);
	return hash->final();
}

Botan::secure_vector<uint8_t> hmacStreebog256(
	const Botan::secure_vector<uint8_t>& key, const std::vector<uint8_t>& message)
{
	const size_t blockSize = 64;
	Botan::secure_vector<uint8_t> innerPad(blockSize, 0x36);
	Botan::secure_vector<uint8_t> outerPad(blockSize, 0x5c);
	for (size_t i = 0; i < key.size(); ++i)
	{
		innerPad[i] ^= key[i];
		outerPad[i] ^= key[i];
	}

	std::unique_ptr<Botan::HashFunction> inner =
		Botan::HashFunction::create_or_throw("Streebog-256");
	inner->update(innerPad);
	inner->update(message);
	Botan::secure_vector<uint8_t> innerDigest = inner->final();

	std::unique_ptr<Botan::HashFunction> outer =
		Botan::HashFunction::create_or_throw("Streebog-256");
	outer->update(outerPad);
	outer->update(innerDigest);
	return outer->final();
}
}

bool BotanGOST2012KEG::derive(const ByteString& encodedCurveOID,
	                          const ByteString& privateValue,
	                          const ByteString& publicValue,
	                          const ByteString& ukmSource,
	                          ByteString& twinKey)
{
	twinKey.wipe();
	// Two sizes, told apart by the private key: 32 bytes of scalar with a
	// 64-byte peer point, or 64 with 128. The UKM is 32 bytes either way, and
	// so is the twin key that comes out. A mismatched pair is rejected here
	// rather than somewhere deeper.
	const size_t fieldBytes = privateValue.size();
	if ((fieldBytes != 32 && fieldBytes != 64) ||
	    publicValue.size() != fieldBytes * 2 || ukmSource.size() != 32)
	{
		ERROR_MSG("GOST KEG received invalid private key, public key, or UKM length");
		return false;
	}
	const bool wide = fieldBytes == 64;

	try
	{
		Botan::EC_Group group = gostGroup(encodedCurveOID);
		if (group.get_p().bytes() != fieldBytes)
		{
			ERROR_MSG("GOST KEG curve size does not match the private key length");
			return false;
		}
		if (group.get_cofactor() != Botan::BigInt(1) &&
		    group.get_cofactor() != Botan::BigInt(4))
		{
			ERROR_MSG("GOST KEG requires a cofactor of 1 or 4");
			return false;
		}

		const Botan::BigInt privateScalar(privateValue.const_byte_str(), privateValue.size());
		if (privateScalar.is_zero() || privateScalar >= group.get_order())
		{
			ERROR_MSG("GOST KEG received an invalid private scalar");
			return false;
		}

		// PKCS #11 carries GOST coordinates as little-endian X || Y, while
		// Botan's uncompressed point encoding is 0x04 || X || Y, big-endian.
		std::vector<uint8_t> encodedPoint(1 + 2 * fieldBytes);
		encodedPoint[0] = 0x04;
		const unsigned char* publicBytes = publicValue.const_byte_str();
		for (size_t i = 0; i < fieldBytes; ++i)
		{
			encodedPoint[1 + i] = publicBytes[fieldBytes - 1 - i];
			encodedPoint[1 + fieldBytes + i] = publicBytes[2 * fieldBytes - 1 - i];
		}
		const Botan::PointGFp peer = group.OS2ECP(encodedPoint);
		if (!group.verify_public_element(peer))
		{
			ERROR_MSG("GOST KEG received an invalid peer public point");
			return false;
		}

		// The Rutoken KEG construction derives the VKO UKM from the first
		// half of the 32-byte source. It is interpreted as little-endian.
		std::vector<uint8_t> ukmBigEndian(16);
		const unsigned char* ukmBytes = ukmSource.const_byte_str();
		bool allZero = true;
		for (size_t i = 0; i < 16; ++i) allZero = allZero && ukmBytes[i] == 0;
		if (allZero)
			ukmBigEndian[0] = 1;
		else
			// KEG first reverses these bytes, then VKO interprets that result
			// as little-endian; the two reversals cancel for BigInt input.
			for (size_t i = 0; i < 16; ++i) ukmBigEndian[i] = ukmBytes[i];
		const Botan::BigInt ukm(ukmBigEndian.data(), ukmBigEndian.size());
		const Botan::BigInt scalar =
			group.multiply_mod_order(ukm, group.get_cofactor(), privateScalar);
		if (scalar.is_zero())
		{
			ERROR_MSG("GOST KEG produced a zero VKO scalar");
			return false;
		}

		SoftHSMGOST2012KEGRNG rng(CryptoFactory::i()->getRNG());
		std::vector<Botan::BigInt> workspace;
		const Botan::PointGFp shared =
			group.blinded_var_point_multiply(peer, scalar, rng, workspace);
		const std::vector<uint8_t> sharedPoint =
			shared.encode(Botan::PointGFp::UNCOMPRESSED);
		if (sharedPoint.size() != 1 + 2 * fieldBytes || sharedPoint[0] != 0x04)
		{
			ERROR_MSG("GOST KEG produced an invalid shared point");
			return false;
		}

		Botan::secure_vector<uint8_t> vkoInput(2 * fieldBytes);
		for (size_t i = 0; i < fieldBytes; ++i)
		{
			vkoInput[i] = sharedPoint[fieldBytes - i];
			vkoInput[fieldBytes + i] = sharedPoint[2 * fieldBytes - i];
		}

		// This is where the two sizes part company, and the difference is not
		// an extrapolation from the 256-bit case: both were settled against the
		// worked examples published with the TC26 PKCS #11 extension, whose
		// ETALONs this reproduces byte for byte.
		//
		// 512-bit: VKO on Streebog-512 is the whole of KEG. It already yields
		// the 64 bytes a twin key needs, and no KDF follows.
		//
		// 256-bit: VKO on Streebog-256 yields 32, so KDF_TREE over
		// HMAC-Streebog-256 stretches it to 64 - two blocks, label "kdf tree",
		// seed from UKM bytes 16..23, length field 0x02 0x00.
		if (wide)
		{
			const Botan::secure_vector<uint8_t> vkoKey =
				streebog("Streebog-512", vkoInput.data(), vkoInput.size());
			if (vkoKey.size() != 64)
			{
				ERROR_MSG("GOST KEG produced an unexpected VKO key length");
				return false;
			}
			twinKey.resize(64);
			std::memcpy(twinKey.byte_str(), vkoKey.data(), 64);
			return true;
		}

		const Botan::secure_vector<uint8_t> vkoKey =
			streebog("Streebog-256", vkoInput.data(), vkoInput.size());

		const uint8_t label[] = {'k', 'd', 'f', ' ', 't', 'r', 'e', 'e'};
		twinKey.resize(64);
		for (uint8_t counter = 1; counter <= 2; ++counter)
		{
			std::vector<uint8_t> input;
			input.reserve(20);
			input.push_back(counter);
			input.insert(input.end(), label, label + sizeof(label));
			input.push_back(0x00);
			for (size_t i = 16; i < 24; ++i) input.push_back(ukmBytes[i]);
			input.push_back(0x02);
			input.push_back(0x00);
			const Botan::secure_vector<uint8_t> block = hmacStreebog256(vkoKey, input);
			std::memcpy(twinKey.byte_str() + (counter - 1) * 32, block.data(), 32);
		}
		return true;
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST KEG failed: %s", exception.what());
	}
	catch (...)
	{
		ERROR_MSG("GOST KEG failed");
	}

	twinKey.wipe();
	return false;
}
