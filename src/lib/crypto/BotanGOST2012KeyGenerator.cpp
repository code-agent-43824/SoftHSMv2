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
#include "BotanGOST2012KeyGenerator.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "log.h"

#include <botan/ec_group.h>
#include <botan/gost_3410.h>
#include <botan/rng.h>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace
{
class SoftHSMBotanRNG : public Botan::RandomNumberGenerator
{
public:
	explicit SoftHSMBotanRNG(RNG* source) : source(source) {}

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
}

bool BotanGOST2012KeyGenerator::generate(const ByteString& encodedCurveOID,
	                                     ByteString& publicValue,
	                                     ByteString& privateValue,
	                                     size_t orderBits)
{
	publicValue.wipe();
	privateValue.wipe();

	if (orderBits != 256 && orderBits != 512)
	{
		ERROR_MSG("GOST R 34.10-2012 supports 256-bit and 512-bit orders only");
		return false;
	}
	const size_t coordinateBytes = orderBits / 8;

	try
	{
		std::vector<uint8_t> encodedCurve(encodedCurveOID.size());
		if (!encodedCurve.empty())
			std::memcpy(encodedCurve.data(), encodedCurveOID.const_byte_str(), encodedCurve.size());
		Botan::EC_Group group(encodedCurve);
		if (group.get_order().bits() != orderBits)
		{
			ERROR_MSG("GOST R 34.10-2012/%zu was asked for a curve of order %zu bits",
			          orderBits, (size_t) group.get_order().bits());
			return false;
		}

		SoftHSMBotanRNG rng(CryptoFactory::i()->getRNG());
		Botan::GOST_3410_PrivateKey key(rng, group);
		const std::vector<uint8_t> point =
			key.public_point().encode(Botan::PointGFp::UNCOMPRESSED);
		if (point.size() != 1 + 2 * coordinateBytes || point[0] != 0x04)
		{
			ERROR_MSG("Botan returned an invalid GOST R 34.10-2012 public point");
			return false;
		}

		// PKCS #11 stores GOST coordinates as little-endian X || Y.
		publicValue.resize(2 * coordinateBytes);
		for (size_t i = 0; i < coordinateBytes; ++i)
		{
			publicValue[i] = point[coordinateBytes - i];
			publicValue[coordinateBytes + i] = point[2 * coordinateBytes - i];
		}

		// Keep the scalar in the representation used by SoftHSM's existing
		// GOST key classes, ready for the later signing implementation.
		privateValue.resize(coordinateBytes);
		key.private_value().binary_encode(privateValue.byte_str(), privateValue.size());
		return true;
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST R 34.10-2012 key generation failed: %s", exception.what());
	}
	catch (...)
	{
		ERROR_MSG("GOST R 34.10-2012 key generation failed");
	}

	publicValue.wipe();
	privateValue.wipe();
	return false;
}
