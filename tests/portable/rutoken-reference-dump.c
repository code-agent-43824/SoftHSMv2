/*
 * Read the reference values of a real Rutoken.
 *
 * The compatibility profile can only be as accurate as the device readings it
 * is built from, and most of CK_TOKEN_INFO_EXTENDED describes hardware that
 * cannot be derived from a software token. This tool prints those fields from
 * a physical device so they can be transcribed instead of guessed.
 *
 * It also dumps the vendor hardware-feature object - the CKO_HW_FEATURE whose
 * CKA_HW_FEATURE_TYPE is CKH_VENDOR_TOKEN_INFO - because Rutoken-aware software
 * reads the token's capabilities from there rather than from the extended
 * structure, and those values cannot be guessed either.
 *
 * It talks to the vendor library through PKCS #11 and the extension ABI
 * declared in src/lib/pkcs11/rutoken.h, and never writes to the token: it
 * opens a read-only public session and only reads.
 *
 *   Linux/macOS:
 *     cc -I src/lib/pkcs11 tests/portable/rutoken-reference-dump.c -ldl \
 *        -o rutoken-reference-dump
 *     ./rutoken-reference-dump /usr/lib/librtpkcs11ecp.so
 *
 *   Windows (Developer Command Prompt):
 *     cl /I src\lib\pkcs11 tests\portable\rutoken-reference-dump.c
 *     rutoken-reference-dump.exe C:\Windows\System32\rtPKCS11ECP.dll
 */

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "cryptoki.h"
#include "rutoken.h"

static void printPadded(const char* name, const unsigned char* text, size_t length)
{
	while (length > 0 && (text[length - 1] == ' ' || text[length - 1] == '\0')) --length;
	printf("%-22s '%.*s'\n", name, (int) length, text);
}

static void printFlag(CK_FLAGS flags, CK_FLAGS bit, const char* name)
{
	if ((flags & bit) != 0) printf("                       %s\n", name);
}

/* The capability attributes Rutoken Plugin reads from the hardware-feature
   object, with the buffer size it hands over for each. The plugin asks without
   a preceding size query, so these lengths are what the module must produce. */
static const struct { CK_ATTRIBUTE_TYPE type; CK_ULONG size; const char* name; } kFeatureAttributes[] = {
	{ CKA_VENDOR_SECURE_MESSAGING_AVAILABLE,	1, "SECURE_MESSAGING_AVAILABLE" },
	{ CKA_VENDOR_CURRENT_SECURE_MESSAGING_MODE,	8, "CURRENT_SECURE_MESSAGING_MODE" },
	{ CKA_VENDOR_CURRENT_TOKEN_INTERFACE,		8, "CURRENT_TOKEN_INTERFACE" },
	{ CKA_VENDOR_SUPPORTED_TOKEN_INTERFACE,		8, "SUPPORTED_TOKEN_INTERFACE" },
	{ CKA_VENDOR_EXTERNAL_AUTHENTICATION,		1, "EXTERNAL_AUTHENTICATION" },
	{ CKA_VENDOR_BIOMETRIC_AUTHENTICATION,		8, "BIOMETRIC_AUTHENTICATION" },
	{ CKA_VENDOR_SUPPORT_CUSTOM_PIN,		1, "SUPPORT_CUSTOM_PIN" },
	{ CKA_VENDOR_CUSTOM_ADMIN_PIN,			1, "CUSTOM_ADMIN_PIN" },
	{ CKA_VENDOR_CUSTOM_USER_PIN,			1, "CUSTOM_USER_PIN" },
	{ CKA_VENDOR_SUPPORT_FKC2,			1, "SUPPORT_FKC2" },
	{ CKA_VENDOR_UNDOCUMENTED_800D,			1, "0x8000800D (unnamed)" }
};

static void dumpHardwareFeature(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slot)
{
	const CK_ULONG count = sizeof(kFeatureAttributes) / sizeof(kFeatureAttributes[0]);
	CK_OBJECT_CLASS featureClass = CKO_HW_FEATURE;
	CK_HW_FEATURE_TYPE featureType = CKH_VENDOR_TOKEN_INFO;
	CK_ATTRIBUTE search[2];
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE objects[8];
	CK_ULONG found = 0;
	CK_ATTRIBUTE query[sizeof(kFeatureAttributes) / sizeof(kFeatureAttributes[0])];
	CK_BYTE buffers[sizeof(kFeatureAttributes) / sizeof(kFeatureAttributes[0])][8];
	CK_RV rv;
	CK_ULONG i, j;

	search[0].type = CKA_CLASS;
	search[0].pValue = &featureClass;
	search[0].ulValueLen = sizeof(featureClass);
	search[1].type = CKA_HW_FEATURE_TYPE;
	search[1].pValue = &featureType;
	search[1].ulValueLen = sizeof(featureType);

	printf("\n== CKO_HW_FEATURE / CKH_VENDOR_TOKEN_INFO ==\n");
	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK)
	{
		printf("C_OpenSession returned 0x%lx; cannot look for the object\n", (unsigned long) rv);
		return;
	}

	rv = p11->C_FindObjectsInit(session, search, 2);
	if (rv == CKR_OK)
	{
		rv = p11->C_FindObjects(session, objects, sizeof(objects) / sizeof(objects[0]), &found);
		p11->C_FindObjectsFinal(session);
	}
	if (rv != CKR_OK)
	{
		printf("search returned 0x%lx\n", (unsigned long) rv);
		p11->C_CloseSession(session);
		return;
	}
	printf("%-30s %lu\n", "objects found", (unsigned long) found);
	if (found == 0)
	{
		printf("this library has no vendor hardware-feature object\n");
		p11->C_CloseSession(session);
		return;
	}

	/* Ask exactly the way the plugin does: one call, buffers already sized. */
	for (i = 0; i < count; ++i)
	{
		memset(buffers[i], 0, sizeof(buffers[i]));
		query[i].type = kFeatureAttributes[i].type;
		query[i].pValue = buffers[i];
		query[i].ulValueLen = kFeatureAttributes[i].size;
	}
	rv = p11->C_GetAttributeValue(session, objects[0], query, count);
	printf("%-30s 0x%lx%s\n", "C_GetAttributeValue", (unsigned long) rv,
	       rv == CKR_OK ? "" : " (per-attribute results below)");
	for (i = 0; i < count; ++i)
	{
		printf("  0x%08lx %-30s ", (unsigned long) kFeatureAttributes[i].type,
		       kFeatureAttributes[i].name);
		if (query[i].ulValueLen == (CK_ULONG) -1)
		{
			printf("not available\n");
			continue;
		}
		printf("len %lu, ", (unsigned long) query[i].ulValueLen);
		for (j = 0; j < query[i].ulValueLen && j < sizeof(buffers[i]); ++j)
			printf("%02X", buffers[i][j]);
		printf("\n");
	}

	p11->C_CloseSession(session);
}

int main(int argc, char** argv)
{
	void* handle;
	void* symbol;
	CK_C_GetFunctionList getList;
	CK_C_EX_GetFunctionListExtended getListExtended;
	CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
	CK_FUNCTION_LIST_EXTENDED_PTR ex = NULL_PTR;
	CK_SLOT_ID slots[64];
	CK_ULONG slotCount = sizeof(slots) / sizeof(slots[0]);
	CK_TOKEN_INFO token;
	CK_TOKEN_INFO_EXTENDED extended;
	CK_RV rv;
	CK_ULONG i;

	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <path to the Rutoken PKCS #11 library>\n", argv[0]);
		return 2;
	}

#ifdef _WIN32
	handle = (void*) LoadLibraryA(argv[1]);
	if (handle == NULL) { fprintf(stderr, "LoadLibrary failed\n"); return 1; }
	/* GetProcAddress returns FARPROC, which is a different function type; the
	   round trip through a data pointer is what every PKCS #11 loader does. */
	symbol = (void*) GetProcAddress((HMODULE) handle, "C_GetFunctionList");
	getList = (CK_C_GetFunctionList) symbol;
	symbol = (void*) GetProcAddress((HMODULE) handle, "C_EX_GetFunctionListExtended");
	getListExtended = (CK_C_EX_GetFunctionListExtended) symbol;
#else
	handle = dlopen(argv[1], RTLD_NOW);
	if (handle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
	symbol = dlsym(handle, "C_GetFunctionList");
	getList = (CK_C_GetFunctionList) symbol;
	symbol = dlsym(handle, "C_EX_GetFunctionListExtended");
	getListExtended = (CK_C_EX_GetFunctionListExtended) symbol;
#endif
	if (getList == NULL) { fprintf(stderr, "C_GetFunctionList is not exported\n"); return 1; }
	if (getListExtended == NULL)
	{
		fprintf(stderr, "C_EX_GetFunctionListExtended is not exported: "
				"this library has no Rutoken extension\n");
		return 1;
	}

	if (getList(&p11) != CKR_OK || p11 == NULL_PTR) { fprintf(stderr, "no function list\n"); return 1; }
	rv = getListExtended(&ex);
	if (rv != CKR_OK || ex == NULL_PTR)
	{
		fprintf(stderr, "C_EX_GetFunctionListExtended returned 0x%lx\n", (unsigned long) rv);
		return 1;
	}
	printf("extended table version  %u.%u\n", ex->version.major, ex->version.minor);

	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize returned 0x%lx\n", (unsigned long) rv); return 1; }

	rv = p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK || slotCount == 0)
	{
		fprintf(stderr, "no slot with a token present (0x%lx)\n", (unsigned long) rv);
		p11->C_Finalize(NULL_PTR);
		return 1;
	}
	printf("slot with a token       %lu\n\n", (unsigned long) slots[0]);

	memset(&token, 0, sizeof(token));
	rv = p11->C_GetTokenInfo(slots[0], &token);
	if (rv == CKR_OK)
	{
		printf("== C_GetTokenInfo ==\n");
		printPadded("label", token.label, sizeof(token.label));
		printPadded("manufacturerID", token.manufacturerID, sizeof(token.manufacturerID));
		printPadded("model", (const unsigned char*) token.model, sizeof(token.model));
		printPadded("serialNumber", (const unsigned char*) token.serialNumber,
			    sizeof(token.serialNumber));
		printf("%-22s 0x%08lx\n", "flags", (unsigned long) token.flags);
		printf("%-22s %lu..%lu\n", "PIN length",
		       (unsigned long) token.ulMinPinLen, (unsigned long) token.ulMaxPinLen);
		printf("%-22s %u.%u / %u.%u\n\n", "hardware / firmware",
		       token.hardwareVersion.major, token.hardwareVersion.minor,
		       token.firmwareVersion.major, token.firmwareVersion.minor);
	}

	memset(&extended, 0, sizeof(extended));
	extended.ulSizeofThisStructure = sizeof(extended);
	rv = ex->C_EX_GetTokenInfoExtended(slots[0], &extended);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "C_EX_GetTokenInfoExtended returned 0x%lx\n", (unsigned long) rv);
		p11->C_Finalize(NULL_PTR);
		return 1;
	}

	printf("== C_EX_GetTokenInfoExtended ==\n");
	printf("%-22s %lu (client passed %lu)\n", "ulSizeofThisStructure",
	       (unsigned long) extended.ulSizeofThisStructure, (unsigned long) sizeof(extended));
	printf("%-22s 0x%lx\n", "ulTokenType", (unsigned long) extended.ulTokenType);
	printf("%-22s 0x%lx\n", "ulProtocolNumber", (unsigned long) extended.ulProtocolNumber);
	printf("%-22s 0x%lx\n", "ulMicrocodeNumber", (unsigned long) extended.ulMicrocodeNumber);
	printf("%-22s %lu\n", "ulOrderNumber", (unsigned long) extended.ulOrderNumber);
	printf("%-22s 0x%08lx\n", "flags", (unsigned long) extended.flags);
	printFlag(extended.flags, TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN, "ADMIN_CHANGE_USER_PIN");
	printFlag(extended.flags, TOKEN_FLAGS_USER_CHANGE_USER_PIN, "USER_CHANGE_USER_PIN");
	printFlag(extended.flags, TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT, "ADMIN_PIN_NOT_DEFAULT");
	printFlag(extended.flags, TOKEN_FLAGS_USER_PIN_NOT_DEFAULT, "USER_PIN_NOT_DEFAULT");
	printFlag(extended.flags, TOKEN_FLAGS_SUPPORT_FKN, "SUPPORT_FKN");
	printFlag(extended.flags, TOKEN_FLAGS_SUPPORT_SM, "SUPPORT_SM");
	printFlag(extended.flags, TOKEN_FLAGS_HAS_FLASH_DRIVE, "HAS_FLASH_DRIVE");
	printFlag(extended.flags, TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING, "SUPPORT_SECURE_MESSAGING");
	printFlag(extended.flags, TOKEN_FLAGS_HAS_BUTTON, "HAS_BUTTON");
	printFlag(extended.flags, TOKEN_FLAGS_SUPPORT_JOURNAL, "SUPPORT_JOURNAL");
	printFlag(extended.flags, TOKEN_FLAGS_USER_PIN_UTF8, "USER_PIN_UTF8");
	printFlag(extended.flags, TOKEN_FLAGS_ADMIN_PIN_UTF8, "ADMIN_PIN_UTF8");
	printFlag(extended.flags, TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE, "FW_CHECKSUM_UNAVAILIBLE");
	printFlag(extended.flags, TOKEN_FLAGS_FW_CHECKSUM_INVALID, "FW_CHECKSUM_INVALID");
	printf("%-22s %lu..%lu, retries %lu of %lu\n", "admin PIN",
	       (unsigned long) extended.ulMinAdminPinLen, (unsigned long) extended.ulMaxAdminPinLen,
	       (unsigned long) extended.ulAdminRetryCountLeft,
	       (unsigned long) extended.ulMaxAdminRetryCount);
	printf("%-22s %lu..%lu, retries %lu of %lu\n", "user PIN",
	       (unsigned long) extended.ulMinUserPinLen, (unsigned long) extended.ulMaxUserPinLen,
	       (unsigned long) extended.ulUserRetryCountLeft,
	       (unsigned long) extended.ulMaxUserRetryCount);
	printf("%-22s ", "serialNumber");
	for (i = 0; i < sizeof(extended.serialNumber); ++i) printf("%02X", extended.serialNumber[i]);
	printf("\n%-22s %lu free of %lu\n", "memory",
	       (unsigned long) extended.ulFreeMemory, (unsigned long) extended.ulTotalMemory);
	printf("%-22s %lu bytes: ", "ATR", (unsigned long) extended.ulATRLen);
	for (i = 0; i < extended.ulATRLen && i < sizeof(extended.ATR); ++i)
		printf("%02X", extended.ATR[i]);
	printf("\n%-22s 0x%lx\n", "ulTokenClass", (unsigned long) extended.ulTokenClass);
	printf("%-22s %lu\n", "ulBodyColor", (unsigned long) extended.ulBodyColor);
	printf("%-22s 0x%08lx\n", "ulFirmwareChecksum", (unsigned long) extended.ulFirmwareChecksum);
	printf("%-22s %lu mV, %lu%%, flags 0x%lx\n", "battery",
	       (unsigned long) extended.ulBatteryVoltage,
	       (unsigned long) extended.ulBatteryPercentage,
	       (unsigned long) extended.ulBatteryFlags);

	dumpHardwareFeature(p11, slots[0]);

	p11->C_Finalize(NULL_PTR);
	return 0;
}
