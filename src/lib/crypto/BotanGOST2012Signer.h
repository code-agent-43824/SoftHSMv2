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

#ifndef _SOFTHSM_V2_BOTANGOST2012SIGNER_H
#define _SOFTHSM_V2_BOTANGOST2012SIGNER_H

#include "AsymmetricAlgorithm.h"
#include "GOSTPrivateKey.h"
#include <botan/hash.h>
#include <memory>

class BotanGOST2012PrivateKey : public GOSTPrivateKey
{
public:
	static const char* type;

	virtual bool isOfType(const char* inType);
	virtual unsigned long getOutputLength() const;
	virtual ByteString serialise() const;
	virtual bool deserialise(ByteString& serialised);
	virtual ByteString PKCS8Encode();
	virtual bool PKCS8Decode(const ByteString& ber);
};

class BotanGOST2012Signer : public AsymmetricAlgorithm
{
public:
	BotanGOST2012Signer();
	virtual ~BotanGOST2012Signer();

	virtual bool signInit(PrivateKey* privateKey, const AsymMech::Type mechanism,
	                     const MechanismParam* mechanismParam = NULL);
	virtual bool signUpdate(const ByteString& dataToSign);
	virtual bool signFinal(ByteString& signature);

	virtual bool encrypt(PublicKey*, const ByteString&, ByteString&,
	                     const AsymMech::Type, const MechanismParam* = NULL);
	virtual bool decrypt(PrivateKey*, const ByteString&, ByteString&,
	                     const AsymMech::Type, const MechanismParam* = NULL);
	virtual bool generateKeyPair(AsymmetricKeyPair**, AsymmetricParameters*, RNG* = NULL);
	virtual unsigned long getMinKeySize();
	virtual unsigned long getMaxKeySize();
	virtual bool reconstructKeyPair(AsymmetricKeyPair**, ByteString&);
	virtual bool reconstructPublicKey(PublicKey**, ByteString&);
	virtual bool reconstructPrivateKey(PrivateKey**, ByteString&);
	virtual PublicKey* newPublicKey();
	virtual PrivateKey* newPrivateKey();

private:
	ByteString rawInput;
	std::unique_ptr<Botan::HashFunction> hash;
};

#endif // !_SOFTHSM_V2_BOTANGOST2012SIGNER_H
