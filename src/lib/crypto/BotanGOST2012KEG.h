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

#ifndef _SOFTHSM_V2_BOTANGOST2012KEG_H
#define _SOFTHSM_V2_BOTANGOST2012KEG_H

#include "ByteString.h"

class BotanGOST2012KEG
{
public:
	static bool derive(const ByteString& encodedCurveOID,
	                   const ByteString& privateValue,
	                   const ByteString& publicValue,
	                   const ByteString& ukmSource,
	                   ByteString& twinKey);

	// VKO_GOSTR3410_2012_256 of RFC 7836, 4.3.1: Streebog-256 over the point
	// (cofactor * UKM * d) * Q, with the UKM bytes read as a little-endian
	// integer. This is the whole of CKM_GOSTR3410_12_DERIVE with CKD_NULL;
	// a zero UKM is refused rather than replaced.
	static bool vko256(const ByteString& encodedCurveOID,
	                   const ByteString& privateValue,
	                   const ByteString& publicValue,
	                   const ByteString& ukm,
	                   ByteString& key);
	static bool vko512(const ByteString& encodedCurveOID,
	                   const ByteString& privateValue,
	                   const ByteString& publicValue,
	                   const ByteString& ukm,
	                   ByteString& key);

	// Whether the little-endian X || Y is a valid point of the curve: the
	// VKO derive refuses an invalid one with its own code, as the device does.
	static bool isPeerPointValid(const ByteString& encodedCurveOID,
	                             const ByteString& publicValue);
};

#endif // !_SOFTHSM_V2_BOTANGOST2012KEG_H
