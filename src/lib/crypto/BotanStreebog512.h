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

#ifndef _SOFTHSM_V2_BOTANSTREEBOG512_H
#define _SOFTHSM_V2_BOTANSTREEBOG512_H

#include "HashAlgorithm.h"
#include <botan/hash.h>
#include <memory>

class BotanStreebog512 : public HashAlgorithm
{
public:
	BotanStreebog512();
	virtual ~BotanStreebog512();

	virtual bool hashInit();
	virtual bool hashUpdate(const ByteString& data);
	virtual bool hashFinal(ByteString& hashedData);
	virtual int getHashSize();

private:
	std::unique_ptr<Botan::HashFunction> hash;
};

#endif // !_SOFTHSM_V2_BOTANSTREEBOG512_H
