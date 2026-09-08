/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSAttributes.h

 Specifies vendor defined attributes for use in internal object store files
 *****************************************************************************/

#ifndef _SOFTHSM_V2_OSATTRIBUTES_H
#define _SOFTHSM_V2_OSATTRIBUTES_H

#include "config.h"
#include "cryptoki.h"

// Define vendor tag; presumably the one below is reasonably unique
#define CKA_VENDOR_SOFTHSM	(CKA_VENDOR_DEFINED + 0x5348) // 'SH'

// Vendor defined attribute types for the token file
#define CKA_OS_TOKENLABEL	(CKA_VENDOR_SOFTHSM + 1)
#define CKA_OS_TOKENSERIAL	(CKA_VENDOR_SOFTHSM + 2)
#define CKA_OS_TOKENFLAGS	(CKA_VENDOR_SOFTHSM + 3)
#define CKA_OS_SOPIN		(CKA_VENDOR_SOFTHSM + 4)
#define CKA_OS_USERPIN		(CKA_VENDOR_SOFTHSM + 5)
// When the token object was created: microseconds since the Unix epoch, eight
// bytes big-endian, so it compares as plain bytes and does not depend on the
// width of CK_ULONG. Written once, when the token is created, and never
// updated - re-initialising a token keeps the object, so it keeps its creation
// time. The Rutoken profile orders tokens across its slots by this, so that
// adding a token does not move the ones already placed. Microseconds rather
// than seconds because two tokens made by one script land in the same second,
// and then the order would fall through to the serial, which comes from a
// random UUID - a new token could displace one already placed. Tokens written
// by builds before this attribute existed do not carry it and are not given
// one; they sort as the oldest.
#define CKA_OS_TOKENCREATED	(CKA_VENDOR_SOFTHSM + 6)

#endif // !_SOFTHSM_V2_OSATTRIBUTES_H

