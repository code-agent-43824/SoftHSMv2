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
#include "BotanGOST2012Signer.h"
#include "CryptoFactory.h"
#include "RNG.h"
#include "log.h"

#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace
{
class SoftHSMGOST2012RNG : public Botan::RandomNumberGenerator
{
public:
	explicit SoftHSMGOST2012RNG(RNG* source) : source(source) {}

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

bool signDigest(BotanGOST2012PrivateKey* privateKey,
	            const ByteString& digest, ByteString& signature)
{
	if (privateKey == NULL || digest.size() != 32 || privateKey->getD().size() != 32)
		return false;

	try
	{
		std::vector<uint8_t> encodedCurve(privateKey->getEC().size());
		if (!encodedCurve.empty())
			std::memcpy(encodedCurve.data(), privateKey->getEC().const_byte_str(), encodedCurve.size());
		Botan::EC_Group group(encodedCurve);
		if (group.get_order().bits() != 256) return false;

		const Botan::BigInt scalar(privateKey->getD().const_byte_str(), privateKey->getD().size());
		if (scalar.is_zero() || scalar >= group.get_order()) return false;
		SoftHSMGOST2012RNG rng(CryptoFactory::i()->getRNG());
		Botan::GOST_3410_PrivateKey botanKey(rng, group, scalar);
		Botan::PK_Signer signer(botanKey, rng, "Raw", Botan::IEEE_1363);
		const std::vector<uint8_t> result =
			signer.sign_message(digest.const_byte_str(), digest.size(), rng);
		if (result.size() != 64) return false;

		signature.resize(result.size());
		std::memcpy(signature.byte_str(), result.data(), result.size());
		return true;
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST R 34.10-2012/256 signing failed: %s", exception.what());
	}
	catch (...)
	{
		ERROR_MSG("GOST R 34.10-2012/256 signing failed");
	}
	return false;
}
}

const char* BotanGOST2012PrivateKey::type = "Botan GOST 2012 Private Key";

bool BotanGOST2012PrivateKey::isOfType(const char* inType)
{
	return inType != NULL && std::strcmp(type, inType) == 0;
}

unsigned long BotanGOST2012PrivateKey::getOutputLength() const
{
	return 64;
}

ByteString BotanGOST2012PrivateKey::serialise() const
{
	return ec.serialise() + d.serialise();
}

bool BotanGOST2012PrivateKey::deserialise(ByteString& serialised)
{
	ByteString decodedEC = ByteString::chainDeserialise(serialised);
	ByteString decodedD = ByteString::chainDeserialise(serialised);
	if (decodedEC.size() == 0 || decodedD.size() == 0) return false;
	setEC(decodedEC);
	setD(decodedD);
	return true;
}

ByteString BotanGOST2012PrivateKey::PKCS8Encode()
{
	return ByteString();
}

bool BotanGOST2012PrivateKey::PKCS8Decode(const ByteString&)
{
	return false;
}

BotanGOST2012Signer::BotanGOST2012Signer()
{
}

BotanGOST2012Signer::~BotanGOST2012Signer()
{
}

bool BotanGOST2012Signer::signInit(PrivateKey* privateKey,
	                               const AsymMech::Type mechanism,
	                               const MechanismParam* mechanismParam)
{
	if (mechanismParam != NULL ||
	    (mechanism != AsymMech::GOST && mechanism != AsymMech::GOST_GOST) ||
	    privateKey == NULL || !privateKey->isOfType(BotanGOST2012PrivateKey::type) ||
	    !AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
		return false;

	rawInput.wipe();
	try
	{
		if (mechanism == AsymMech::GOST_GOST)
			hash = Botan::HashFunction::create_or_throw("Streebog-256");
		else
			hash.reset();
	}
	catch (...)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);
		return false;
	}
	return true;
}

bool BotanGOST2012Signer::signUpdate(const ByteString& dataToSign)
{
	if (!AsymmetricAlgorithm::signUpdate(dataToSign)) return false;
	try
	{
		if (currentMechanism == AsymMech::GOST_GOST)
		{
			if (dataToSign.size() != 0)
				hash->update(dataToSign.const_byte_str(), dataToSign.size());
		}
		else
		{
			rawInput += dataToSign;
			if (rawInput.size() > 32) return false;
		}
		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool BotanGOST2012Signer::signFinal(ByteString& signature)
{
	ByteString digest;
	try
	{
		if (currentMechanism == AsymMech::GOST_GOST)
		{
			digest.resize(32);
			hash->final(digest.byte_str());
		}
		else
		{
			digest = rawInput;
		}
	}
	catch (...)
	{
		ByteString dummy;
		AsymmetricAlgorithm::signFinal(dummy);
		return false;
	}

	BotanGOST2012PrivateKey* privateKey =
		static_cast<BotanGOST2012PrivateKey*>(currentPrivateKey);
	const bool result = signDigest(privateKey, digest, signature);
	ByteString dummy;
	if (!AsymmetricAlgorithm::signFinal(dummy)) return false;
	rawInput.wipe();
	hash.reset();
	return result;
}

bool BotanGOST2012Signer::encrypt(PublicKey*, const ByteString&, ByteString&,
	                              const AsymMech::Type, const MechanismParam*) { return false; }
bool BotanGOST2012Signer::decrypt(PrivateKey*, const ByteString&, ByteString&,
	                              const AsymMech::Type, const MechanismParam*) { return false; }
bool BotanGOST2012Signer::generateKeyPair(AsymmetricKeyPair**, AsymmetricParameters*, RNG*) { return false; }
unsigned long BotanGOST2012Signer::getMinKeySize() { return 256; }
unsigned long BotanGOST2012Signer::getMaxKeySize() { return 256; }
bool BotanGOST2012Signer::reconstructKeyPair(AsymmetricKeyPair**, ByteString&) { return false; }
bool BotanGOST2012Signer::reconstructPublicKey(PublicKey**, ByteString&) { return false; }
bool BotanGOST2012Signer::reconstructPrivateKey(PrivateKey**, ByteString&) { return false; }
PublicKey* BotanGOST2012Signer::newPublicKey() { return NULL; }
PrivateKey* BotanGOST2012Signer::newPrivateKey() { return new BotanGOST2012PrivateKey(); }
