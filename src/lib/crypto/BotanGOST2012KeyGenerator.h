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

#ifndef _SOFTHSM_V2_BOTANGOST2012KEYGENERATOR_H
#define _SOFTHSM_V2_BOTANGOST2012KEYGENERATOR_H

#include "ByteString.h"

class BotanGOST2012KeyGenerator
{
public:
	// orderBits selects the variant: 256 for GOST R 34.10-2012/256, 512 for
	// the 512-bit one. It is checked against the curve rather than trusted,
	// so a caller that pairs the wrong curve with a size gets a failure and
	// not a key on a curve it did not ask for.
	static bool generate(const ByteString& encodedCurveOID,
	                     ByteString& publicValue,
	                     ByteString& privateValue,
	                     size_t orderBits = 256);
};

#endif // !_SOFTHSM_V2_BOTANGOST2012KEYGENERATOR_H
