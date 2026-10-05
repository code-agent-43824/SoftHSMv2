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
 Token.h

 This class represents a single PKCS #11 token
 *****************************************************************************/

#ifndef _SOFTHSM_V2_TOKEN_H
#define _SOFTHSM_V2_TOKEN_H

#include "config.h"
#include "ByteString.h"
#include "ObjectStore.h"
#include "ObjectStoreToken.h"
#include "SecureDataManager.h"
#include "cryptoki.h"
#include <string>
#include <vector>

class Token
{
public:
	struct PinPolicy
	{
		unsigned char minLength, minSOLength, maxLength, changeUserPINPolicy;
		unsigned char maxSO, maxUser, leftSO, leftUser;
		PinPolicy() : minLength(6), minSOLength(6), maxLength(32), changeUserPINPolicy(3), maxSO(10), maxUser(10),
		              leftSO(10), leftUser(10) {}
	};
	// Constructor
	Token();
	Token(ObjectStoreToken *inToken);

	// Destructor
	virtual ~Token();

	// Create a new token
	CK_RV createToken(ObjectStore* objectStore, ByteString& soPIN, CK_UTF8CHAR_PTR label);

	// Full-format initialisation for the Rutoken C_EX_InitToken extension: wipe
	// the token and set a fresh SO PIN, user PIN and PIN policy in one step. In
	// repair mode it formats without the old SO PIN, which is the point of the
	// call on a real device; otherwise soPIN is the current SO PIN and is
	// verified first.
	CK_RV initTokenExtended(ObjectStore* objectStore, bool repairMode,
	                        ByteString& soPIN, ByteString& newSOPIN,
	                        ByteString& newUserPIN, const PinPolicy& policy,
	                        CK_UTF8CHAR_PTR label);

	// Is the token valid?
	bool isValid();

	// Is the token initialized?
	bool isInitialized();

	// Is SO or user logged in?
	bool isSOLoggedIn();
	bool isUserLoggedIn();

	// Login
	CK_RV loginSO(ByteString& pin);
	CK_RV loginUser(ByteString& pin);

	// Re-authentication
	CK_RV reAuthenticate(ByteString& pin);

	// Logout any user on this token;
	void logout();

	// Change PIN
	CK_RV setSOPIN(ByteString& oldPIN, ByteString& newPIN);
	CK_RV setUserPIN(ByteString& oldPIN, ByteString& newPIN);
	CK_RV initUserPIN(ByteString& pin);
	CK_RV unblockUserPIN();
	bool getPinPolicy(PinPolicy& policy);
	bool setPinPolicy(const PinPolicy& policy);

	// Retrieve token information for the token
	CK_RV getTokenInfo(CK_TOKEN_INFO_PTR info);

	// How the Rutoken profile orders tokens across its slots: when the token
	// was created, as big-endian microseconds since the Unix epoch, and its
	// serial to break a tie. False from the first when the stored token carries
	// no creation time - written by a build from before the attribute existed.
	bool getCreationTime(ByteString& created);
	bool getSerial(ByteString& serial);
	CK_RV setTokenName(const ByteString& name);
	bool getTokenName(ByteString& name, bool& exists);
	CK_RV setLocalPIN(CK_ULONG id, ByteString& currentPIN, ByteString& newPIN);

	// Create object
	OSObject *createObject();

	// Insert all token objects into the given set.
	void getObjects(std::set<OSObject *> &objects);

	// Decrypt the supplied data
	bool decrypt(const ByteString& encrypted, ByteString& plaintext);

	// Encrypt the supplied data
	bool encrypt(const ByteString& plaintext, ByteString& encrypted);

private:
	CK_RV pinResult(bool so, bool success);
	bool pinLocked(bool so);
	// Token validity
	bool valid;

	// A reference to the object store token
	ObjectStoreToken* token;

	// The secure data manager for this token
	SecureDataManager* sdm;

	Mutex* tokenMutex;
};

#endif // !_SOFTHSM_V2_TOKEN_H
