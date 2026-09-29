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

#include "config.h"
#include "log.h"
#include "ObjectStore.h"
#include "Token.h"
#include "OSAttribute.h"
#include "ByteString.h"
#include "SecureDataManager.h"
#include <cstdio>
#include <cstdlib>

#ifndef _WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif

// Constructor
Token::Token()
{
	tokenMutex = MutexFactory::i()->getMutex();

	token = NULL;
	sdm = NULL;
	valid = false;
}

// Constructor
Token::Token(ObjectStoreToken* inToken)
{
	tokenMutex = MutexFactory::i()->getMutex();

	token = inToken;

	ByteString soPINBlob, userPINBlob;

	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	sdm = new SecureDataManager(soPINBlob, userPINBlob);
}

// Destructor
Token::~Token()
{
	if (sdm != NULL) delete sdm;

	MutexFactory::i()->recycleMutex(tokenMutex);
}

bool Token::getPinPolicy(PinPolicy& policy)
{
	if (token == NULL) return false;
	ByteString bytes;
	bool exists = false;
	if (!token->getPinPolicy(bytes, exists)) return false;
	if (!exists) return true; // Tokens predating this attribute.
	if (bytes.size() != 7 || bytes[0] != 1 || bytes[1] < 6 ||
	    bytes[2] > 32 || bytes[1] > bytes[2] ||
	    bytes[3] < 3 || bytes[3] > 15 || bytes[4] < 3 || bytes[4] > 15 ||
	    bytes[5] > bytes[3] || bytes[6] > bytes[4]) return false;
	policy.minLength = bytes[1]; policy.maxLength = bytes[2];
	policy.maxSO = bytes[3]; policy.maxUser = bytes[4];
	policy.leftSO = bytes[5]; policy.leftUser = bytes[6];
	return true;
}

bool Token::setPinPolicy(const PinPolicy& policy)
{
	if (token == NULL) return false;
	ByteString bytes;
	bytes.resize(7);
	bytes[0] = 1; bytes[1] = policy.minLength; bytes[2] = policy.maxLength;
	bytes[3] = policy.maxSO; bytes[4] = policy.maxUser;
	bytes[5] = policy.leftSO; bytes[6] = policy.leftUser;
	return token->setPinPolicy(bytes);
}

bool Token::pinLocked(bool so)
{
	PinPolicy policy;
	return !getPinPolicy(policy) || (so ? policy.leftSO : policy.leftUser) == 0;
}

CK_RV Token::pinResult(bool so, bool success)
{
	ByteString bytes;
	CK_ULONG flags;
	if (!token->advancePinPolicy(so, success, bytes))
	{
		if (sdm != NULL) sdm->logout();
		return CKR_DEVICE_ERROR;
	}
	const unsigned char left = bytes[so ? 5 : 6];
	const unsigned char maximum = bytes[so ? 3 : 4];
	if (!token->getTokenFlags(flags))
	{
		if (sdm != NULL) sdm->logout();
		return CKR_DEVICE_ERROR;
	}
	const CK_FLAGS low = so ? CKF_SO_PIN_COUNT_LOW : CKF_USER_PIN_COUNT_LOW;
	const CK_FLAGS final = so ? CKF_SO_PIN_FINAL_TRY : CKF_USER_PIN_FINAL_TRY;
	const CK_FLAGS locked = so ? CKF_SO_PIN_LOCKED : CKF_USER_PIN_LOCKED;
	flags &= ~(low | final | locked);
	if (left < maximum) flags |= low;
	if (left == 1) flags |= final;
	if (left == 0) flags |= locked;
	if (!token->setTokenFlags(flags))
	{
		if (sdm != NULL) sdm->logout();
		return CKR_DEVICE_ERROR;
	}
	if (left == 0 && sdm != NULL) sdm->logout();
	return left == 0 ? CKR_PIN_LOCKED : (success ? CKR_OK : CKR_PIN_INCORRECT);
}

// Check if the token is still valid
bool Token::isValid()
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	return (valid && token->isValid());
}

// Check if the token is initialized
bool Token::isInitialized()
{
	if (token == NULL) return false;

	return true;
}

// Check if SO is logged in
bool Token::isSOLoggedIn()
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->isSOLoggedIn();
}

// Check if user is logged in
bool Token::isUserLoggedIn()
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->isUserLoggedIn();
}

// Login SO
CK_RV Token::loginSO(ByteString& pin)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	// User cannot be logged in
	if (sdm->isUserLoggedIn()) return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	// SO cannot be logged in
	if (sdm->isSOLoggedIn()) return CKR_USER_ALREADY_LOGGED_IN;

	if (pinLocked(true)) return CKR_PIN_LOCKED;

	// Login
	if (!sdm->loginSO(pin))
	{
		return pinResult(true, false);
	}
	return pinResult(true, true);
}

// Login user
CK_RV Token::loginUser(ByteString& pin)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	// SO cannot be logged in
	if (sdm->isSOLoggedIn()) return CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

	// User cannot be logged in
	if (sdm->isUserLoggedIn()) return CKR_USER_ALREADY_LOGGED_IN;

	// The user PIN has to be initialized;
	if (sdm->getUserPINBlob().size() == 0) return CKR_USER_PIN_NOT_INITIALIZED;

	if (pinLocked(false)) return CKR_PIN_LOCKED;

	// Login
	if (!sdm->loginUser(pin))
	{
		return pinResult(false, false);
	}
	return pinResult(false, true);
}

CK_RV Token::reAuthenticate(ByteString& pin)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (sdm->isSOLoggedIn())
	{
		if (pinLocked(true)) return CKR_PIN_LOCKED;
		// Login
		if (!sdm->reAuthenticateSO(pin))
		{
			return pinResult(true, false);
		}
		return pinResult(true, true);
	}
	else if (sdm->isUserLoggedIn())
	{
		if (pinLocked(false)) return CKR_PIN_LOCKED;
		// Login
		if (!sdm->reAuthenticateUser(pin))
		{
			return pinResult(false, false);
		}
		return pinResult(false, true);
	}
	else
	{
		return CKR_OPERATION_NOT_INITIALIZED;
	}

}

// Logout any user on this token;
void Token::logout()
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return;

	sdm->logout();
}

// Change SO PIN
CK_RV Token::setSOPIN(ByteString& oldPIN, ByteString& newPIN)
{

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (pinLocked(true)) return CKR_PIN_LOCKED;

	// Verify oldPIN
	SecureDataManager* verifier = new SecureDataManager(sdm->getSOPINBlob(), sdm->getUserPINBlob());
	bool result = verifier->loginSO(oldPIN);
	delete verifier;
	if (result == false)
	{
		return pinResult(true, false);
	}

	if (sdm->setSOPIN(newPIN) == false) return CKR_GENERAL_ERROR;

	// Save PIN to token file
	if (token->setSOPIN(sdm->getSOPINBlob()) == false) return CKR_GENERAL_ERROR;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	return pinResult(true, true);
}

// Change the user PIN
CK_RV Token::setUserPIN(ByteString& oldPIN, ByteString& newPIN)
{

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	// Check if user should stay logged in
	bool stayLoggedIn = sdm->isUserLoggedIn();

	if (pinLocked(false)) return CKR_PIN_LOCKED;

	// Verify oldPIN
	SecureDataManager* newSdm = new SecureDataManager(sdm->getSOPINBlob(), sdm->getUserPINBlob());
	if (newSdm->loginUser(oldPIN) == false)
	{
		delete newSdm;
		return pinResult(false, false);
	}

	// Set the new user PIN
	if (newSdm->setUserPIN(newPIN) == false)
	{
		delete newSdm;
		return CKR_GENERAL_ERROR;
	}

	// Save PIN to token file
	if (token->setUserPIN(newSdm->getUserPINBlob()) == false)
	{
		delete newSdm;
		return CKR_GENERAL_ERROR;
	}

	// Restore previous login state
	if (!stayLoggedIn) newSdm->logout();

	// Switch sdm
	delete sdm;
	sdm = newSdm;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	return pinResult(false, true);
}

// Init the user PIN
CK_RV Token::initUserPIN(ByteString& pin)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return CKR_GENERAL_ERROR;

	if (sdm->setUserPIN(pin) == false) return CKR_GENERAL_ERROR;

	// Save PIN to token file
	if (token->setUserPIN(sdm->getUserPINBlob()) == false) return CKR_GENERAL_ERROR;

	ByteString soPINBlob, userPINBlob;
	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	PinPolicy policy;
	CK_ULONG flags;
	if (!getPinPolicy(policy) || !token->getTokenFlags(flags)) return CKR_DEVICE_ERROR;
	policy.leftUser = policy.maxUser;
	if (!setPinPolicy(policy)) return CKR_DEVICE_ERROR;
	flags &= ~(CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED);
	return token->setTokenFlags(flags) ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV Token::unblockUserPIN()
{
	MutexLocker lock(tokenMutex);
	if (sdm == NULL || !sdm->isSOLoggedIn()) return CKR_USER_NOT_LOGGED_IN;
	PinPolicy policy;
	CK_ULONG flags;
	if (!getPinPolicy(policy) || !token->getTokenFlags(flags)) return CKR_DEVICE_ERROR;
	policy.leftUser = policy.maxUser;
	if (!setPinPolicy(policy)) return CKR_DEVICE_ERROR;
	flags &= ~(CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED);
	return token->setTokenFlags(flags) ? CKR_OK : CKR_DEVICE_ERROR;
}

// Create a new token
CK_RV Token::createToken(ObjectStore* objectStore, ByteString& soPIN, CK_UTF8CHAR_PTR label)
{
	CK_ULONG flags;
	PinPolicy newPolicy;
	const char* requested = getenv("SOFTHSM2_INIT_PIN_POLICY");
	if (requested != NULL && requested[0] != '\0')
	{
		unsigned int so, user, minLen, maxLen;
		char tail;
		if (sscanf(requested, "%u:%u:%u:%u%c", &so, &user, &minLen,
		           &maxLen, &tail) != 4 || so < 3 || so > 15 ||
		    user < 3 || user > 15 || minLen < 6 || maxLen > 32 ||
		    minLen > maxLen) return CKR_ARGUMENTS_BAD;
		newPolicy.maxSO = newPolicy.leftSO = static_cast<unsigned char>(so);
		newPolicy.maxUser = newPolicy.leftUser = static_cast<unsigned char>(user);
		newPolicy.minLength = static_cast<unsigned char>(minLen);
		newPolicy.maxLength = static_cast<unsigned char>(maxLen);
	}
	if (soPIN.size() < newPolicy.minLength ||
	    soPIN.size() > newPolicy.maxLength) return CKR_PIN_LEN_RANGE;

	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (objectStore == NULL) return CKR_GENERAL_ERROR;
	if (label == NULL_PTR) return CKR_ARGUMENTS_BAD;

	// Convert the label
	ByteString labelByteStr((const unsigned char*) label, 32);

	if (token != NULL)
	{
		if (pinLocked(true)) return CKR_PIN_LOCKED;
		// Get token flags
		if (!token->getTokenFlags(flags))
		{
			ERROR_MSG("Could not get the token flags");
			return CKR_GENERAL_ERROR;
		}

		// Verify SO PIN
		if (sdm->getSOPINBlob().size() > 0 && !sdm->loginSO(soPIN))
		{
			ERROR_MSG("Incorrect SO PIN");
			return pinResult(true, false);
		}
		flags &= ~CKF_SO_PIN_COUNT_LOW;
		token->setTokenFlags(flags);

		// Reset the token
		if (!token->resetToken(labelByteStr))
		{
			ERROR_MSG("Could not reset the token");
			return CKR_DEVICE_ERROR;
		}
	}
	else
	{
		// Generate the SO PIN blob
		SecureDataManager soPINBlobGen;

		if (!soPINBlobGen.setSOPIN(soPIN))
		{
			return CKR_GENERAL_ERROR;
		}

		// Create the token
		ObjectStoreToken* newToken = objectStore->newToken(labelByteStr);

		if (newToken == NULL)
		{
			ERROR_MSG("Could not create the token");
			return CKR_DEVICE_ERROR;
		}

		// Set the SO PIN on the token
		if (!newToken->setSOPIN(soPINBlobGen.getSOPINBlob()))
		{
			ERROR_MSG("Failed to set SO PIN on new token");

			if (!objectStore->destroyToken(newToken))
			{
				ERROR_MSG("Failed to destroy incomplete token");
			}

			return CKR_DEVICE_ERROR;
		}

		token = newToken;
	}
	if (!setPinPolicy(newPolicy)) return CKR_DEVICE_ERROR;

	ByteString soPINBlob, userPINBlob;

	valid = token->getSOPIN(soPINBlob) && token->getUserPIN(userPINBlob);

	if (sdm != NULL) delete sdm;
	sdm = new SecureDataManager(soPINBlob, userPINBlob);

	return CKR_OK;
}

// When the token was created, for the Rutoken profile's slot order
bool Token::getCreationTime(ByteString& created)
{
	if (token == NULL) return false;

	return token->getTokenCreationTime(created);
}

// The token serial, the tiebreak of that same order
bool Token::getSerial(ByteString& serial)
{
	if (token == NULL) return false;

	return token->getTokenSerial(serial);
}

// Retrieve token information for the token
CK_RV Token::getTokenInfo(CK_TOKEN_INFO_PTR info)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	ByteString label, serial;

	if (info == NULL)
	{
		return CKR_ARGUMENTS_BAD;
	}

	memset(info->label, ' ', 32);
	memset(info->serialNumber, ' ', 16);

	// Token specific information
	if (token)
	{
		if (!token->getTokenFlags(info->flags))
		{
			ERROR_MSG("Could not get the token flags");
			return CKR_GENERAL_ERROR;
		}
		PinPolicy policy;
		if (!getPinPolicy(policy)) return CKR_DEVICE_ERROR;
		info->flags &= ~(CKF_SO_PIN_COUNT_LOW | CKF_SO_PIN_FINAL_TRY |
		                 CKF_SO_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW |
		                 CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED);
		if (policy.leftSO < policy.maxSO) info->flags |= CKF_SO_PIN_COUNT_LOW;
		if (policy.leftSO == 1) info->flags |= CKF_SO_PIN_FINAL_TRY;
		if (policy.leftSO == 0) info->flags |= CKF_SO_PIN_LOCKED;
		if (policy.leftUser < policy.maxUser) info->flags |= CKF_USER_PIN_COUNT_LOW;
		if (policy.leftUser == 1) info->flags |= CKF_USER_PIN_FINAL_TRY;
		if (policy.leftUser == 0) info->flags |= CKF_USER_PIN_LOCKED;

		if (token->getTokenLabel(label))
		{
			strncpy((char*) info->label, (char*) label.byte_str(), label.size());
		}

		if (token->getTokenSerial(serial))
		{
			strncpy((char*) info->serialNumber, (char*) serial.byte_str(), serial.size());
		}
	}
	else
	{
		info->flags =	CKF_RNG |
				CKF_LOGIN_REQUIRED |
				CKF_RESTORE_KEY_NOT_NEEDED |
				CKF_SO_PIN_LOCKED |
				CKF_SO_PIN_TO_BE_CHANGED;
	}

	// Information shared by all tokens
	char mfgID[33];
	char model[17];

	snprintf(mfgID, 33, "SoftHSM project");
	snprintf(model, 17, "SoftHSM v2");

	memset(info->manufacturerID, ' ', 32);
	memset(info->model, ' ', 16);
	memcpy(info->manufacturerID, mfgID, strlen(mfgID));
	memcpy(info->model, model, strlen(model));

	// TODO: Can we set these?
	info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	info->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	info->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	PinPolicy policy;
	if (token && !getPinPolicy(policy)) return CKR_DEVICE_ERROR;
	info->ulMaxPinLen = policy.maxLength;
	info->ulMinPinLen = policy.minLength;
	info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	info->hardwareVersion.major = VERSION_MAJOR;
	info->hardwareVersion.minor = VERSION_MINOR;
	info->firmwareVersion.major = VERSION_MAJOR;
	info->firmwareVersion.minor = VERSION_MINOR;

	// Current time
	time_t rawtime;
	time(&rawtime);
	char dateTime[17];
	strftime(dateTime, 17, "%Y%m%d%H%M%S00", gmtime(&rawtime));
	memcpy(info->utcTime, dateTime, 16);

		return CKR_OK;
}

// Create an object
OSObject* Token::createObject()
{
	return token->createObject();
}

void Token::getObjects(std::set<OSObject *> &objects)
{
	token->getObjects(objects);
}

bool Token::decrypt(const ByteString &encrypted, ByteString &plaintext)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->decrypt(encrypted,plaintext);
}

bool Token::encrypt(const ByteString &plaintext, ByteString &encrypted)
{
	// Lock access to the token
	MutexLocker lock(tokenMutex);

	if (sdm == NULL) return false;

	return sdm->encrypt(plaintext,encrypted);
}
