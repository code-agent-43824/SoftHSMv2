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

#include "GOST2012Tests.h"

#if defined(WITH_GOST_3411_2012) || defined(WITH_GOST_3411_2012_512) || defined(WITH_GOST_3410_2012_256)
#include "ByteString.h"
CPPUNIT_TEST_SUITE_REGISTRATION(GOST2012Tests);
#endif

#ifdef WITH_GOST_3411_2012
#include "BotanStreebog256.h"

void GOST2012Tests::testStreebog256()
{
	// RFC 6986, sections 10.1.2 and 10.2.2. Its printed octets run in
	// reverse order from the byte API used here.
	const ByteString message1(
		"3031323334353637383930313233343536373839303132333435363738393031"
		"32333435363738393031323334353637383930313233343536373839303132");
	const ByteString digest1("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
	const ByteString message2(
		"d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2"
		"fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efeb"
		"faeafb20c8e3eef0e5e2fb");
	const ByteString digest2("9dd2fe4e90409e5da87f53976d7405b0c0cac628fc669a741d50063c557e8f50");

	BotanStreebog256 hash;
	ByteString result;
	CPPUNIT_ASSERT(hash.getHashSize() == 32);
	CPPUNIT_ASSERT(hash.hashInit());
	CPPUNIT_ASSERT(hash.hashUpdate(message1));
	CPPUNIT_ASSERT(hash.hashFinal(result));
	CPPUNIT_ASSERT(result == digest1);

	// A new operation must reset the same object, even after a full digest.
	CPPUNIT_ASSERT(hash.hashInit());
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(0, 1)));
	CPPUNIT_ASSERT(hash.hashUpdate(ByteString()));
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(1, 13)));
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(14)));
	CPPUNIT_ASSERT(hash.hashFinal(result));
	CPPUNIT_ASSERT(result == digest2);
}
#endif

#ifdef WITH_GOST_3411_2012_512
#include "BotanStreebog512.h"

void GOST2012Tests::testStreebog512()
{
	// RFC 6986, sections 10.1.1 and 10.2.1, in byte-API order.
	const ByteString message1(
		"3031323334353637383930313233343536373839303132333435363738393031"
		"32333435363738393031323334353637383930313233343536373839303132");
	const ByteString digest1(
		"1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa"
		"00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48");
	const ByteString message2(
		"d1e520e2e5f2f0e82c20d1f2f0e8e1eee6e820e2edf3f6e82c20e2e5fef2"
		"fa20f120eceef0ff20f1f2f0e5ebe0ece820ede020f5f0e0e1f0fbff20efeb"
		"faeafb20c8e3eef0e5e2fb");
	const ByteString digest2(
		"1e88e62226bfca6f9994f1f2d51569e0daf8475a3b0fe61a5300eee46d96137"
		"6035fe83549ada2b8620fcd7c496ce5b33f0cb9dddc2b6460143b03dabac9fb28");

	BotanStreebog512 hash;
	ByteString result;
	CPPUNIT_ASSERT(hash.getHashSize() == 64);
	CPPUNIT_ASSERT(hash.hashInit());
	CPPUNIT_ASSERT(hash.hashUpdate(message1));
	CPPUNIT_ASSERT(hash.hashFinal(result));
	CPPUNIT_ASSERT(result == digest1);

	CPPUNIT_ASSERT(hash.hashInit());
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(0, 1)));
	CPPUNIT_ASSERT(hash.hashUpdate(ByteString()));
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(1, 13)));
	CPPUNIT_ASSERT(hash.hashUpdate(message2.substr(14)));
	CPPUNIT_ASSERT(hash.hashFinal(result));
	CPPUNIT_ASSERT(result == digest2);
}
#endif

#ifdef WITH_GOST_3410_2012_256
#include "BotanGOST2012KeyGenerator.h"
#include "BotanGOST2012KEG.h"
#include "BotanGOST2012Signer.h"
#include "BotanGOSTCurves.h"
#include <botan/bigint.h>
#include <botan/ec_group.h>
#include <vector>

namespace
{
ByteString curve256A() { return ByteString("06092a8503070102010101"); }
ByteString curve512C() { return ByteString("06092a8503070102010203"); }

void generateAndCheck(const ByteString& curve, size_t coordinateBytes,
	                  ByteString& publicValue, ByteString& privateValue)
{
	CPPUNIT_ASSERT(BotanGOST2012KeyGenerator::generate(
		curve, publicValue, privateValue, coordinateBytes * 8));
	CPPUNIT_ASSERT(publicValue.size() == 2 * coordinateBytes);
	CPPUNIT_ASSERT(privateValue.size() == coordinateBytes);
	CPPUNIT_ASSERT(BotanGOSTCurves::pointIsOnCurve(curve, publicValue));

	// Check the PKCS #11 little-endian X || Y against d*G, rather than
	// accepting a pair just because its point happens to be on the curve.
	const Botan::EC_Group group = BotanGOSTCurves::group(curve);
	// The named domains are published by TC26. These coefficients distinguish
	// 256 paramSetA from the older CryptoPro-A curve on the same field.
	if (curve == curve256A())
		CPPUNIT_ASSERT(group.get_a() == Botan::BigInt(
			"0xC2173F1513981673AF4892C23035A27CE25E2013BF95AA33B22C656F277E7335"));
	if (curve == curve512C())
		CPPUNIT_ASSERT(group.get_a() == Botan::BigInt(
			"0xDC9203E514A721875485A529D2C722FB187BC8980EB866644DE41C68E1430645"
			"46E861C0E2C9EDD92ADE71F46FCF50FF2AD97F951FDA9F2A2EB6546F39689BD3"));
	CPPUNIT_ASSERT(group.get_cofactor() == Botan::BigInt(4));
	const Botan::BigInt scalar(privateValue.const_byte_str(), privateValue.size());
	CPPUNIT_ASSERT(scalar > Botan::BigInt(0));
	CPPUNIT_ASSERT(scalar < group.get_order());
	const std::vector<uint8_t> point =
		(group.get_base_point() * scalar).encode(Botan::PointGFp::UNCOMPRESSED);
	CPPUNIT_ASSERT(point.size() == 1 + 2 * coordinateBytes);
	CPPUNIT_ASSERT(point[0] == 0x04);
	ByteString expected;
	expected.resize(2 * coordinateBytes);
	for (size_t i = 0; i < coordinateBytes; ++i)
	{
		expected[i] = point[coordinateBytes - i];
		expected[coordinateBytes + i] = point[2 * coordinateBytes - i];
	}
	CPPUNIT_ASSERT(publicValue == expected);

	BotanGOST2012PublicKey publicKey;
	publicKey.setEC(curve);
	publicKey.setQ(publicValue);
	ByteString encodedPublic = publicKey.serialise();
	BotanGOST2012PublicKey decodedPublic;
	CPPUNIT_ASSERT(decodedPublic.deserialise(encodedPublic));
	CPPUNIT_ASSERT(decodedPublic.getEC() == curve);
	CPPUNIT_ASSERT(decodedPublic.getQ() == publicValue);

	BotanGOST2012PrivateKey privateKey;
	privateKey.setEC(curve);
	privateKey.setD(privateValue);
	ByteString encodedPrivate = privateKey.serialise();
	BotanGOST2012PrivateKey decodedPrivate;
	CPPUNIT_ASSERT(decodedPrivate.deserialise(encodedPrivate));
	CPPUNIT_ASSERT(decodedPrivate.getEC() == curve);
	CPPUNIT_ASSERT(decodedPrivate.getD() == privateValue);
}

void signAndCheck(const ByteString& curve, size_t coordinateBytes,
	              AsymMech::Type mechanism, size_t repetitions)
{
	ByteString publicValue, privateValue;
	generateAndCheck(curve, coordinateBytes, publicValue, privateValue);
	BotanGOST2012PublicKey publicKey;
	publicKey.setEC(curve);
	publicKey.setQ(publicValue);
	BotanGOST2012PrivateKey privateKey;
	privateKey.setEC(curve);
	privateKey.setD(privateValue);
	BotanGOST2012Signer signer;
	ByteString digest;
	digest.resize(coordinateBytes);
	for (size_t i = 0; i < coordinateBytes; ++i) digest[i] = (unsigned char)(i + 1);

	for (size_t attempt = 0; attempt < repetitions; ++attempt)
	{
		ByteString signature, signedDigest;
		CPPUNIT_ASSERT(signer.signInit(&privateKey, mechanism));
		CPPUNIT_ASSERT(signer.signUpdate(digest.substr(0, 1)));
		CPPUNIT_ASSERT(signer.signUpdate(digest.substr(1)));
		CPPUNIT_ASSERT(signer.signFinal(signature));
		CPPUNIT_ASSERT(signature.size() == 2 * coordinateBytes);
		CPPUNIT_ASSERT(signer.getSignedDigest(signedDigest));
		CPPUNIT_ASSERT(signedDigest == digest);

		CPPUNIT_ASSERT(signer.verifyInit(&publicKey, mechanism));
		CPPUNIT_ASSERT(signer.verifyUpdate(digest));
		CPPUNIT_ASSERT(signer.verifyFinal(signature));

		ByteString changedDigest = digest;
		changedDigest[0] ^= 1;
		CPPUNIT_ASSERT(signer.verifyInit(&publicKey, mechanism));
		CPPUNIT_ASSERT(signer.verifyUpdate(changedDigest));
		CPPUNIT_ASSERT(!signer.verifyFinal(signature));

		ByteString changedSignature = signature;
		changedSignature[0] ^= 1;
		CPPUNIT_ASSERT(signer.verifyInit(&publicKey, mechanism));
		CPPUNIT_ASSERT(signer.verifyUpdate(digest));
		CPPUNIT_ASSERT(!signer.verifyFinal(changedSignature));
	}

	ByteString shortDigest = digest.substr(0, coordinateBytes - 1);
	ByteString rejectedSignature;
	CPPUNIT_ASSERT(signer.signInit(&privateKey, mechanism));
	CPPUNIT_ASSERT(signer.signUpdate(shortDigest));
	CPPUNIT_ASSERT(!signer.signFinal(rejectedSignature));
}
}

void GOST2012Tests::testKeyGeneration()
{
	ByteString publicValue, privateValue;
	generateAndCheck(curve256A(), 32, publicValue, privateValue);
#ifdef WITH_GOST_3410_2012_512
	generateAndCheck(curve512C(), 64, publicValue, privateValue);
#endif

	// Invalid requests must not leave stale secret material in output buffers.
	const ByteString unknownCurve("06032a0304");
	CPPUNIT_ASSERT(!BotanGOST2012KeyGenerator::generate(
		unknownCurve, publicValue, privateValue, 256));
	CPPUNIT_ASSERT(publicValue.size() == 0 && privateValue.size() == 0);
	CPPUNIT_ASSERT(!BotanGOST2012KeyGenerator::generate(
		curve256A(), publicValue, privateValue, 512));
	CPPUNIT_ASSERT(publicValue.size() == 0 && privateValue.size() == 0);
}

void GOST2012Tests::testSigningAndVerification()
{
	// Both curves have a cofactor of four. Several randomized signatures
	// exercise the required reduction of the verifier's X coordinate mod q.
	signAndCheck(curve256A(), 32, AsymMech::GOST, 8);
#ifdef WITH_GOST_3410_2012_512
	signAndCheck(curve512C(), 64, AsymMech::GOST_512, 8);
#endif

	ByteString publicValue, privateValue;
	generateAndCheck(curve256A(), 32, publicValue, privateValue);
	BotanGOST2012PrivateKey privateKey;
	privateKey.setEC(curve256A());
	privateKey.setD(privateValue);
	BotanGOST2012PublicKey publicKey;
	publicKey.setEC(curve256A());
	publicKey.setQ(publicValue);
	BotanGOST2012Signer signer;
	const ByteString message("3031323334353637383930313233343536373839303132333435363738393031"
	                         "32333435363738393031323334353637383930313233343536373839303132");
	const ByteString expectedDigest("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500");
	ByteString signature, signedDigest;
	CPPUNIT_ASSERT(signer.signInit(&privateKey, AsymMech::GOST_GOST));
	CPPUNIT_ASSERT(signer.signUpdate(message.substr(0, 7)));
	CPPUNIT_ASSERT(signer.signUpdate(message.substr(7)));
	CPPUNIT_ASSERT(signer.signFinal(signature));
	CPPUNIT_ASSERT(signer.getSignedDigest(signedDigest));
	CPPUNIT_ASSERT(signedDigest == expectedDigest);
	CPPUNIT_ASSERT(signer.verifyInit(&publicKey, AsymMech::GOST_GOST));
	CPPUNIT_ASSERT(signer.verifyUpdate(message));
	CPPUNIT_ASSERT(signer.verifyFinal(signature));

	BotanGOST2012PublicKey wrongCurveKey;
	wrongCurveKey.setEC(ByteString("06072a850302022301")); // CryptoPro-A
	wrongCurveKey.setQ(publicValue); // This point belongs to TC26 paramSetA.
	CPPUNIT_ASSERT(signer.verifyInit(&wrongCurveKey, AsymMech::GOST_GOST));
	CPPUNIT_ASSERT(signer.verifyUpdate(message));
	CPPUNIT_ASSERT(!signer.verifyFinal(signature));
}

void GOST2012Tests::testKEG()
{
	// Independent 256-bit known answer from the TC26 KEG sample. The first
	// UKM half drives VKO; bytes 16..23 seed the internal two-block KDF_TREE.
	const ByteString private256(
		"0debb7875a83206ad1b4167c0a3e35c3c3a75b0aefebcc01d81a18ff9f8e7d9f");
	const ByteString public256(
		"c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"
		"8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602");
	const ByteString ukm256(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
	const ByteString expected256(
		"bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900"
		"39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b");
	ByteString result;
	CPPUNIT_ASSERT(BotanGOST2012KEG::isPeerPointValid(curve256A(), public256));
	CPPUNIT_ASSERT(BotanGOST2012KEG::derive(
		curve256A(), private256, public256, ukm256, result));
	CPPUNIT_ASSERT(result == expected256);

	ByteString alteredSeed = ukm256;
	alteredSeed[16] ^= 1;
	CPPUNIT_ASSERT(BotanGOST2012KEG::derive(
		curve256A(), private256, public256, alteredSeed, result));
	CPPUNIT_ASSERT(result.size() == 64 && result != expected256);
	// A failed call must clear the previous derived secret.
	CPPUNIT_ASSERT(!BotanGOST2012KEG::derive(
		curve256A(), private256, public256, ukm256.substr(0, 31), result));
	CPPUNIT_ASSERT(result.size() == 0);
	ByteString zeroScalar;
	zeroScalar.wipe(32);
	CPPUNIT_ASSERT(!BotanGOST2012KEG::derive(
		curve256A(), zeroScalar, public256, ukm256, result));
	CPPUNIT_ASSERT(result.size() == 0);
	ByteString invalidPoint;
	invalidPoint.wipe(64);
	CPPUNIT_ASSERT(!BotanGOST2012KEG::isPeerPointValid(curve256A(), invalidPoint));
	CPPUNIT_ASSERT(!BotanGOST2012KEG::derive(
		curve256A(), private256, invalidPoint, ukm256, result));
	CPPUNIT_ASSERT(result.size() == 0);

#ifdef WITH_GOST_3410_2012_512
	// Published TC26 sample_keg_512 ETALON. 512-bit KEG is VKO-512 without
	// the extra KDF_TREE used by the 256-bit construction.
	const ByteString private512(
		"12fd7a70067479a0f66c59f9a25534adfbc7abfd3cc72d79806f8b402601644b"
		"3005ed365a2d8989a8ccae640d5fc08dd27dfbbfe137cf528e1ac6d445192e01");
	const ByteString public512(
		"c65bd705b6860198bad4a70eb937b6b48084e260adf7b1074a89182862c5bffe"
		"6486283541330b150fe48a737cb3e5bb043e4a1134035a6d479b189351be41c9"
		"be9a7e2afc246276fe4e2356845293b03178e2ec003ca8a814324f16350bc0ab"
		"534187de86c76be29a940a8db2ad71646aa0c952fdf411206548813eb9f754a1");
	const ByteString ukm512(
		"c3ef0428d4b7a1f4c5025f2e65dd2b2ea583aeefdb67c7f4214a6a298e99e325");
	const ByteString expected512(
		"7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"
		"1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24");
	CPPUNIT_ASSERT(BotanGOST2012KEG::isPeerPointValid(curve512C(), public512));
	CPPUNIT_ASSERT(BotanGOST2012KEG::derive(
		curve512C(), private512, public512, ukm512, result));
	CPPUNIT_ASSERT(result == expected512);
	ByteString ignoredTail = ukm512;
	ignoredTail[16] ^= 1;
	CPPUNIT_ASSERT(BotanGOST2012KEG::derive(
		curve512C(), private512, public512, ignoredTail, result));
	CPPUNIT_ASSERT(result == expected512);
	CPPUNIT_ASSERT(!BotanGOST2012KEG::derive(
		curve256A(), private512, public512, ukm512, result));
	CPPUNIT_ASSERT(result.size() == 0);
#endif
}
#endif
