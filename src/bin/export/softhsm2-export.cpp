/*
 * Copyright (c) 2026 SoftHSMv2 contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <config.h>
#include "cryptoki.h"
#include "SoftHSM.h"
#include "ByteString.h"
#include "findslot.h"
#include "getpw.h"

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <algorithm>
#include <string>
#include <vector>
#ifndef _WIN32
#include <sys/stat.h>
#endif

CK_FUNCTION_LIST_PTR p11 = NULL_PTR;

static void usage()
{
	printf("Force-export an RSA or EC private key from this SoftHSM fork.\n");
	printf("Usage: softhsm2-export --token <label>|--serial <serial>|--slot <number>\n");
	printf("       --id <hex> --type <rsa|ec> --output <path> [options]\n");
	printf("Options:\n");
	printf("  --label <text>    Also match the private-key label.\n");
	printf("  --id <hex>        Key ID; compact or colon-separated hexadecimal bytes.\n");
	printf("  --pin <PIN>       User PIN; prompt once when omitted.\n");
	printf("  --format <pem|der> Output format; PEM is the default.\n");
	printf("  -v, --version     Show version.\n");
	printf("  -h, --help        Show this help.\n");
}

static bool decodeHex(const char* input, std::vector<CK_BYTE>& output)
{
	if (input == NULL || *input == '\0') return false;
	const size_t length = strlen(input);
	const bool separated = strchr(input, ':') != NULL;
	if ((!separated && length % 2 != 0) || (separated && length % 3 != 2)) return false;
	for (size_t i = 0; i < length; i += separated ? 3 : 2)
	{
		unsigned int value = 0;
		if (sscanf(input + i, "%2x", &value) != 1) return false;
		if (!((input[i] >= '0' && input[i] <= '9') ||
			(input[i] >= 'a' && input[i] <= 'f') ||
			(input[i] >= 'A' && input[i] <= 'F')) ||
			!((input[i + 1] >= '0' && input[i + 1] <= '9') ||
			(input[i + 1] >= 'a' && input[i + 1] <= 'f') ||
			(input[i + 1] >= 'A' && input[i + 1] <= 'F')))
			return false;
		if (separated && i + 2 < length && input[i + 2] != ':') return false;
		output.push_back((CK_BYTE)value);
	}
	return true;
}

static std::string base64Encode(const ByteString& input)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::string output;
	const unsigned char* bytes = input.const_byte_str();
	for (size_t i = 0; i < input.size(); i += 3)
	{
		unsigned int value = ((unsigned int)bytes[i]) << 16;
		if (i + 1 < input.size()) value |= ((unsigned int)bytes[i + 1]) << 8;
		if (i + 2 < input.size()) value |= bytes[i + 2];
		output += alphabet[(value >> 18) & 63];
		output += alphabet[(value >> 12) & 63];
		output += i + 1 < input.size() ? alphabet[(value >> 6) & 63] : '=';
		output += i + 2 < input.size() ? alphabet[value & 63] : '=';
	}
	return output;
}

static bool writeKey(const char* path, const ByteString& keyData, bool pem)
{
	std::ofstream output(path, std::ios::binary | std::ios::trunc);
	if (!output) return false;
#ifndef _WIN32
	chmod(path, S_IRUSR | S_IWUSR);
#endif
	if (pem)
	{
		std::string encoded = base64Encode(keyData);
		output << "-----BEGIN PRIVATE KEY-----\n";
		for (size_t i = 0; i < encoded.size(); i += 64)
		{
			output.write(encoded.data() + i, std::min((size_t)64, encoded.size() - i));
			output.put('\n');
		}
		output << "-----END PRIVATE KEY-----\n";
		std::fill(encoded.begin(), encoded.end(), '\0');
	}
	else
		output.write((const char*)keyData.const_byte_str(), keyData.size());
	output.close();
	return !!output;
}

int main(int argc, char* argv[])
{
	char* slot = NULL;
	char* serial = NULL;
	char* token = NULL;
	char* objectID = NULL;
	char* label = NULL;
	char* pinArgument = NULL;
	char* outputPath = NULL;
	CK_KEY_TYPE keyType = CKK_VENDOR_DEFINED;
	bool pem = true;

	enum { OPT_SLOT = 0x100, OPT_SERIAL, OPT_TOKEN, OPT_ID, OPT_LABEL,
		OPT_PIN, OPT_TYPE, OPT_OUTPUT, OPT_FORMAT, OPT_VERSION };
	static const struct option options[] = {
		{ "slot", 1, NULL, OPT_SLOT }, { "serial", 1, NULL, OPT_SERIAL },
		{ "token", 1, NULL, OPT_TOKEN }, { "id", 1, NULL, OPT_ID },
		{ "label", 1, NULL, OPT_LABEL }, { "pin", 1, NULL, OPT_PIN },
		{ "type", 1, NULL, OPT_TYPE }, { "output", 1, NULL, OPT_OUTPUT },
		{ "format", 1, NULL, OPT_FORMAT }, { "version", 0, NULL, OPT_VERSION },
		{ "help", 0, NULL, 'h' }, { NULL, 0, NULL, 0 }
	};

	int option = 0;
	while ((option = getopt_long(argc, argv, "hv", options, NULL)) != -1)
	{
		switch (option)
		{
			case OPT_SLOT: slot = optarg; break;
			case OPT_SERIAL: serial = optarg; break;
			case OPT_TOKEN: token = optarg; break;
			case OPT_ID: objectID = optarg; break;
			case OPT_LABEL: label = optarg; break;
			case OPT_PIN: pinArgument = optarg; break;
			case OPT_OUTPUT: outputPath = optarg; break;
			case OPT_TYPE:
				if (!strcmp(optarg, "rsa")) keyType = CKK_RSA;
				else if (!strcmp(optarg, "ec") || !strcmp(optarg, "ecdsa")) keyType = CKK_EC;
				else { fprintf(stderr, "ERROR: --type must be rsa or ec.\n"); return 1; }
				break;
			case OPT_FORMAT:
				if (!strcmp(optarg, "pem")) pem = true;
				else if (!strcmp(optarg, "der")) pem = false;
				else { fprintf(stderr, "ERROR: --format must be pem or der.\n"); return 1; }
				break;
			case OPT_VERSION:
			case 'v': printf("%s\n", PACKAGE_VERSION); return 0;
			case 'h': usage(); return 0;
			default: usage(); return 1;
		}
	}

	if ((slot == NULL && serial == NULL && token == NULL) || objectID == NULL ||
		keyType == CKK_VENDOR_DEFINED || outputPath == NULL)
	{
		usage();
		return 1;
	}

	std::vector<CK_BYTE> id;
	if (!decodeHex(objectID, id))
	{
		fprintf(stderr, "ERROR: --id must contain hexadecimal bytes, optionally separated by colons.\n");
		return 1;
	}

	char promptedPIN[MAX_PIN_LEN + 1];
	memset(promptedPIN, 0, sizeof(promptedPIN));
	char* userPIN = pinArgument;
	if (userPIN == NULL)
	{
		if (getpin("Please enter user PIN: ", promptedPIN, sizeof(promptedPIN)) < 0)
		{
			fprintf(stderr, "ERROR: Could not read the user PIN.\n");
			return 1;
		}
		userPIN = promptedPIN;
	}

	CK_RV rv = C_GetFunctionList(&p11);
	if (rv != CKR_OK || p11 == NULL_PTR)
	{
		memset(promptedPIN, 0, sizeof(promptedPIN));
		fprintf(stderr, "ERROR: Could not access the embedded SoftHSM implementation.\n");
		return 1;
	}
	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK)
	{
		memset(promptedPIN, 0, sizeof(promptedPIN));
		fprintf(stderr, "ERROR: Could not initialize SoftHSM (0x%08lx).\n", rv);
		return 1;
	}

	int result = 1;
	CK_SLOT_ID slotID = 0;
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	ByteString keyData;
	CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
	std::vector<CK_ATTRIBUTE> attributes;
	CK_ATTRIBUTE classAttribute = { CKA_CLASS, &keyClass, sizeof(keyClass) };
	CK_ATTRIBUTE typeAttribute = { CKA_KEY_TYPE, &keyType, sizeof(keyType) };
	CK_ATTRIBUTE idAttribute = { CKA_ID, &id[0], (CK_ULONG)id.size() };
	CK_ATTRIBUTE labelAttribute = { CKA_LABEL, label, label ? (CK_ULONG)strlen(label) : 0 };
	CK_OBJECT_HANDLE objects[2] = { CK_INVALID_HANDLE, CK_INVALID_HANDLE };
	CK_ULONG count = 0;
	CK_RV finalRV = CKR_OK;
	if (findSlot(slot, serial, token, slotID) != 0) goto cleanup;
	rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not open a session (0x%08lx).\n", rv);
		goto cleanup;
	}
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, strlen(userPIN));
	memset(promptedPIN, 0, sizeof(promptedPIN));
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not log in (0x%08lx).\n", rv);
		goto cleanup;
	}

	attributes.push_back(classAttribute);
	attributes.push_back(typeAttribute);
	attributes.push_back(idAttribute);
	if (label != NULL) attributes.push_back(labelAttribute);

	rv = p11->C_FindObjectsInit(session, &attributes[0], (CK_ULONG)attributes.size());
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not start the key search (0x%08lx).\n", rv);
		goto cleanup;
	}
	rv = p11->C_FindObjects(session, objects, 2, &count);
	finalRV = p11->C_FindObjectsFinal(session);
	if (rv != CKR_OK || finalRV != CKR_OK || count != 1)
	{
		if (count == 0) fprintf(stderr, "ERROR: No matching private key was found.\n");
		else if (count > 1) fprintf(stderr, "ERROR: More than one matching private key was found; add --label.\n");
		else fprintf(stderr, "ERROR: The key search failed (0x%08lx).\n", rv != CKR_OK ? rv : finalRV);
		goto cleanup;
	}

	rv = SoftHSM::i()->exportPrivateKey(session, objects[0], keyData);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not export the private key (0x%08lx).\n", rv);
		goto cleanup;
	}
	if (!writeKey(outputPath, keyData, pem))
	{
		fprintf(stderr, "ERROR: Could not write '%s'.\n", outputPath);
		goto cleanup;
	}
	printf("The private key was exported to %s.\n", outputPath);
	result = 0;

cleanup:
	keyData.wipe();
	memset(promptedPIN, 0, sizeof(promptedPIN));
	if (session != CK_INVALID_HANDLE) p11->C_CloseSession(session);
	p11->C_Finalize(NULL_PTR);
	return result;
}
