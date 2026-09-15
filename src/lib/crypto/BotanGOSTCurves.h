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

/*****************************************************************************
 BotanGOSTCurves.h

 The one place that turns a GOST R 34.10 curve OID into a curve.
 *****************************************************************************/

#ifndef _SOFTHSM_V2_BOTANGOSTCURVES_H
#define _SOFTHSM_V2_BOTANGOSTCURVES_H

#include "config.h"
#include "ByteString.h"

#include <botan/ec_group.h>

// Every GOST R 34.10-2012 path - key generation, signing, verification and
// KEG - must obtain its curve here and nowhere else, so that one OID means one
// curve across the whole module.
//
// Asking Botan for the group directly is not an equivalent shortcut, and the
// difference is not theoretical: Botan 2.19 resolves the TC26 256-bit
// paramSetA OID to the older CryptoPro-A curve. The two share the same prime,
// so a key generated "on paramSetA" came out on CryptoPro-A, read its own
// attribute back unchanged, signed and verified against itself, and only KEG -
// which already built the domain explicitly - noticed anything was wrong.
// Other TC26 OIDs Botan does not know at all.
//
// The domains below are transcribed from the RFCs that define them and were
// checked against those RFCs field by field, with the base point confirmed to
// satisfy the curve equation and q*G confirmed to be the point at infinity.
namespace BotanGOSTCurves
{
	// Is this encoded curve OID one we carry domain parameters for?
	bool supported(const ByteString& encodedCurveOID);

	// The curve named by this encoded OID. Throws std::runtime_error when the
	// OID is not one of the supported ones - deliberately, rather than falling
	// back to Botan, because a fallback is how the wrong curve got in.
	Botan::EC_Group group(const ByteString& encodedCurveOID);

	// Bit length of the group order for a supported OID, 0 otherwise. Lets a
	// caller reject a curve/mechanism mismatch before building anything.
	size_t orderBits(const ByteString& encodedCurveOID);

	// Does this little-endian X || Y point lie on that curve? Used to refuse a
	// key whose point belongs to a different curve than the one it names.
	bool pointIsOnCurve(const ByteString& encodedCurveOID, const ByteString& publicValue);
}

#endif // !_SOFTHSM_V2_BOTANGOSTCURVES_H
