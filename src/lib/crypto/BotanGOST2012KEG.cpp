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
#include "BotanGOSTCurves.h"
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
		// One source for the whole module - see BotanGOSTCurves.h. The
		// explicit domains that used to live in this file are there now,
		// which is what stopped generation and signing from meaning a
		// different curve by the same OID.
		if (!BotanGOSTCurves::supported(encodedCurveOID))
		{
			ERROR_MSG("GOST KEG was given a curve with no domain parameters");
			return false;
		}
		Botan::EC_Group group = BotanGOSTCurves::group(encodedCurveOID);
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
