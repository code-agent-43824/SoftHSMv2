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
#include "BotanStreebog256.h"

BotanStreebog256::BotanStreebog256()
{
}

BotanStreebog256::~BotanStreebog256()
{
}

bool BotanStreebog256::hashInit()
{
	if (!HashAlgorithm::hashInit()) return false;

	try
	{
		if (!hash)
			hash = Botan::HashFunction::create_or_throw("Streebog-256");
		else
			hash->clear();
	}
	catch (...)
	{
		ERROR_MSG("Failed to initialize Botan Streebog-256");
		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);
		return false;
	}

	return true;
}

bool BotanStreebog256::hashUpdate(const ByteString& data)
{
	if (!HashAlgorithm::hashUpdate(data)) return false;

	try
	{
		if (data.size() != 0) hash->update(data.const_byte_str(), data.size());
	}
	catch (...)
	{
		ERROR_MSG("Failed to update Botan Streebog-256");
		ByteString dummy;
		HashAlgorithm::hashFinal(dummy);
		return false;
	}

	return true;
}

bool BotanStreebog256::hashFinal(ByteString& hashedData)
{
	if (!HashAlgorithm::hashFinal(hashedData)) return false;

	try
	{
		hashedData.resize(hash->output_length());
		hash->final(hashedData.byte_str());
	}
	catch (...)
	{
		ERROR_MSG("Failed to finalize Botan Streebog-256");
		return false;
	}

	return true;
}

int BotanStreebog256::getHashSize()
{
	return 32;
}
