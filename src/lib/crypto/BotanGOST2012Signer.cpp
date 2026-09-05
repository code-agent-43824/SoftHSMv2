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
#include <botan/ber_dec.h>
#include <botan/der_enc.h>
#include <botan/ec_group.h>
#include <botan/gost_3410.h>
#include <botan/pubkey.h>
#include <botan/rng.h>
#include <algorithm>
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

// How many bytes a coordinate, the scalar and half a signature take for a
// mechanism. Zero means the mechanism is not one of ours.
size_t mechanismCoordinateBytes(AsymMech::Type mechanism)
{
	switch (mechanism)
	{
		case AsymMech::GOST:
		case AsymMech::GOST_GOST:
			return 32;
		case AsymMech::GOST_512:
		case AsymMech::GOST_GOST_512:
			return 64;
		default:
			return 0;
	}
}

bool mechanismHashes(AsymMech::Type mechanism)
{
	return mechanism == AsymMech::GOST_GOST || mechanism == AsymMech::GOST_GOST_512;
}

const char* mechanismHashName(AsymMech::Type mechanism)
{
	return mechanism == AsymMech::GOST_GOST_512 ? "Streebog-512" : "Streebog-256";
}

Botan::EC_Group groupOf(const ByteString& ec, size_t coordinateBytes)
{
	std::vector<uint8_t> encodedCurve(ec.size());
	if (!encodedCurve.empty())
		std::memcpy(encodedCurve.data(), ec.const_byte_str(), encodedCurve.size());
	Botan::EC_Group group(encodedCurve);
	if (group.get_order().bits() != coordinateBytes * 8)
		throw std::runtime_error("the curve does not match the mechanism's key size");
	return group;
}

bool signDigest(BotanGOST2012PrivateKey* privateKey, size_t coordinateBytes,
	            const ByteString& digest, ByteString& signature)
{
	if (privateKey == NULL || coordinateBytes == 0 ||
	    digest.size() != coordinateBytes || privateKey->getD().size() != coordinateBytes)
		return false;

	try
	{
		Botan::EC_Group group = groupOf(privateKey->getEC(), coordinateBytes);

		const Botan::BigInt scalar(privateKey->getD().const_byte_str(), privateKey->getD().size());
		if (scalar.is_zero() || scalar >= group.get_order()) return false;
		SoftHSMGOST2012RNG rng(CryptoFactory::i()->getRNG());
		Botan::GOST_3410_PrivateKey botanKey(rng, group, scalar);
		Botan::PK_Signer signer(botanKey, rng, "Raw", Botan::IEEE_1363);
		const std::vector<uint8_t> result =
			signer.sign_message(digest.const_byte_str(), digest.size(), rng);
		if (result.size() != 2 * coordinateBytes) return false;

		signature.resize(result.size());
		std::memcpy(signature.byte_str(), result.data(), result.size());
		return true;
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST R 34.10-2012 signing failed: %s", exception.what());
	}
	catch (...)
	{
		ERROR_MSG("GOST R 34.10-2012 signing failed");
	}
	return false;
}

// PKCS #11 keeps the public point as little-endian X || Y; Botan wants the
// uncompressed big-endian encoding. This is the inverse of what
// BotanGOST2012KeyGenerator does on the way out.
bool verifyDigest(BotanGOST2012PublicKey* publicKey, size_t coordinateBytes,
	              const ByteString& digest, const ByteString& signature)
{
	if (publicKey == NULL || coordinateBytes == 0 ||
	    digest.size() != coordinateBytes ||
	    signature.size() != 2 * coordinateBytes ||
	    publicKey->getQ().size() != 2 * coordinateBytes)
		return false;

	try
	{
		Botan::EC_Group group = groupOf(publicKey->getEC(), coordinateBytes);

		const unsigned char* q = publicKey->getQ().const_byte_str();
		std::vector<uint8_t> point(1 + 2 * coordinateBytes);
		point[0] = 0x04;
		for (size_t i = 0; i < coordinateBytes; ++i)
		{
			point[coordinateBytes - i] = q[i];
			point[2 * coordinateBytes - i] = q[coordinateBytes + i];
		}

		const Botan::PointGFp publicPoint = group.OS2ECP(point.data(), point.size());
		Botan::GOST_3410_PublicKey botanKey(group, publicPoint);
		Botan::PK_Verifier verifier(botanKey, "Raw", Botan::IEEE_1363);
		return verifier.verify_message(digest.const_byte_str(), digest.size(),
		                               signature.const_byte_str(), signature.size());
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST R 34.10-2012 verification failed: %s", exception.what());
	}
	catch (...)
	{
		ERROR_MSG("GOST R 34.10-2012 verification failed");
	}
	return false;
}
}

const char* BotanGOST2012PublicKey::type = "Botan GOST 2012 Public Key";

bool BotanGOST2012PublicKey::isOfType(const char* inType)
{
	return inType != NULL && std::strcmp(type, inType) == 0;
}

unsigned long BotanGOST2012PublicKey::getOutputLength() const
{
	// Twice the coordinate size: the signature is r || s.
	return (unsigned long) q.size();
}

ByteString BotanGOST2012PublicKey::serialise() const
{
	return ec.serialise() + q.serialise();
}

bool BotanGOST2012PublicKey::deserialise(ByteString& serialised)
{
	ByteString decodedEC = ByteString::chainDeserialise(serialised);
	ByteString decodedQ = ByteString::chainDeserialise(serialised);
	if (decodedEC.size() == 0 || decodedQ.size() == 0) return false;
	setEC(decodedEC);
	setQ(decodedQ);
	return true;
}

const char* BotanGOST2012PrivateKey::type = "Botan GOST 2012 Private Key";

bool BotanGOST2012PrivateKey::isOfType(const char* inType)
{
	return inType != NULL && std::strcmp(type, inType) == 0;
}

unsigned long BotanGOST2012PrivateKey::getOutputLength() const
{
	// The signature is r || s, each the size of the scalar.
	return (unsigned long) (2 * d.size());
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
	ByteString result;
	if (ec.size() == 0 || d.size() != 32) return result;
	std::vector<uint8_t> scalar;

	try
	{
		Botan::OID curve;
		Botan::BER_Decoder(ec.const_byte_str(), ec.size()).decode(curve).verify_end();
		Botan::DER_Encoder parameterEncoder;
		parameterEncoder.start_cons(Botan::SEQUENCE).encode(curve);
		const std::string curveName = curve.to_string();
		if (curveName.find("1.2.643.2.2.35.") == 0 ||
		    curveName == "1.2.643.2.2.36.0" ||
		    curveName == "1.2.643.2.2.36.1")
			parameterEncoder.encode(Botan::OID("1.2.643.7.1.1.2.2"));
		const Botan::secure_vector<uint8_t> encodedParameters =
			parameterEncoder.end_cons().get_contents();
		const std::vector<uint8_t> parameters(encodedParameters.begin(), encodedParameters.end());

		scalar.assign(d.const_byte_str(), d.const_byte_str() + d.size());
		std::reverse(scalar.begin(), scalar.end());
		const Botan::AlgorithmIdentifier algorithm(
			Botan::OID("1.2.643.7.1.1.1.1"), parameters);
		const Botan::secure_vector<uint8_t> encoded = Botan::DER_Encoder()
			.start_cons(Botan::SEQUENCE)
				.encode(static_cast<size_t>(0))
				.encode(algorithm)
				.encode(scalar, Botan::OCTET_STRING)
			.end_cons()
			.get_contents();
		result.resize(encoded.size());
		std::memcpy(result.byte_str(), encoded.data(), encoded.size());
	}
	catch (const std::exception& exception)
	{
		ERROR_MSG("GOST R 34.10-2012/256 PKCS #8 encoding failed: %s", exception.what());
		result.wipe();
	}
	std::fill(scalar.begin(), scalar.end(), 0);
	return result;
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
	    mechanismCoordinateBytes(mechanism) == 0 ||
	    privateKey == NULL || !privateKey->isOfType(BotanGOST2012PrivateKey::type) ||
	    !AsymmetricAlgorithm::signInit(privateKey, mechanism, mechanismParam))
		return false;

	rawInput.wipe();
	try
	{
		if (mechanismHashes(mechanism))
			hash = Botan::HashFunction::create_or_throw(mechanismHashName(mechanism));
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
		if (mechanismHashes(currentMechanism))
		{
			if (dataToSign.size() != 0)
				hash->update(dataToSign.const_byte_str(), dataToSign.size());
		}
		else
		{
			rawInput += dataToSign;
			if (rawInput.size() > mechanismCoordinateBytes(currentMechanism)) return false;
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
		if (mechanismHashes(currentMechanism))
		{
			digest.resize(mechanismCoordinateBytes(currentMechanism));
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
	const bool result = signDigest(privateKey,
	                               mechanismCoordinateBytes(currentMechanism),
	                               digest, signature);
	ByteString dummy;
	if (!AsymmetricAlgorithm::signFinal(dummy)) return false;
	rawInput.wipe();
	hash.reset();
	return result;
}

bool BotanGOST2012Signer::verifyInit(PublicKey* publicKey,
	                                 const AsymMech::Type mechanism,
	                                 const MechanismParam* mechanismParam)
{
	if (mechanismParam != NULL ||
	    mechanismCoordinateBytes(mechanism) == 0 ||
	    publicKey == NULL || !publicKey->isOfType(BotanGOST2012PublicKey::type) ||
	    !AsymmetricAlgorithm::verifyInit(publicKey, mechanism, mechanismParam))
		return false;

	rawInput.wipe();
	try
	{
		if (mechanismHashes(mechanism))
			hash = Botan::HashFunction::create_or_throw(mechanismHashName(mechanism));
		else
			hash.reset();
	}
	catch (...)
	{
		AsymmetricAlgorithm::verifyFinal(ByteString());
		return false;
	}
	return true;
}

bool BotanGOST2012Signer::verifyUpdate(const ByteString& originalData)
{
	if (!AsymmetricAlgorithm::verifyUpdate(originalData)) return false;
	try
	{
		if (mechanismHashes(currentMechanism))
		{
			if (originalData.size() != 0)
				hash->update(originalData.const_byte_str(), originalData.size());
		}
		else
		{
			rawInput += originalData;
			if (rawInput.size() > mechanismCoordinateBytes(currentMechanism)) return false;
		}
		return true;
	}
	catch (...)
	{
		return false;
	}
}

bool BotanGOST2012Signer::verifyFinal(const ByteString& signature)
{
	ByteString digest;
	try
	{
		if (mechanismHashes(currentMechanism))
		{
			digest.resize(mechanismCoordinateBytes(currentMechanism));
			hash->final(digest.byte_str());
		}
		else
		{
			digest = rawInput;
		}
	}
	catch (...)
	{
		AsymmetricAlgorithm::verifyFinal(ByteString());
		return false;
	}

	BotanGOST2012PublicKey* publicKey =
		static_cast<BotanGOST2012PublicKey*>(currentPublicKey);
	const size_t coordinateBytes = mechanismCoordinateBytes(currentMechanism);
	const bool result = verifyDigest(publicKey, coordinateBytes, digest, signature);
	// The base class clears the operation; its own return says nothing about
	// whether the signature was good, so it must not overwrite the verdict.
	AsymmetricAlgorithm::verifyFinal(ByteString());
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
unsigned long BotanGOST2012Signer::getMaxKeySize() { return 512; }
bool BotanGOST2012Signer::reconstructKeyPair(AsymmetricKeyPair**, ByteString&) { return false; }
bool BotanGOST2012Signer::reconstructPublicKey(PublicKey**, ByteString&) { return false; }
bool BotanGOST2012Signer::reconstructPrivateKey(PrivateKey**, ByteString&) { return false; }
PublicKey* BotanGOST2012Signer::newPublicKey() { return new BotanGOST2012PublicKey(); }
PrivateKey* BotanGOST2012Signer::newPrivateKey() { return new BotanGOST2012PrivateKey(); }
