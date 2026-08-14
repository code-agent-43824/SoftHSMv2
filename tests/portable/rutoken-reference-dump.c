/*
 * Read the reference values of a real Rutoken.
 *
 * The compatibility profile can only be as accurate as the device readings it
 * is built from, and most of CK_TOKEN_INFO_EXTENDED describes hardware that
 * cannot be derived from a software token. This tool prints those fields from
 * a physical device so they can be transcribed instead of guessed.
 *
 * It talks to the vendor library through PKCS #11 and the extension ABI
 * declared in src/lib/pkcs11/rutoken.h, and never writes to the token.
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

int main(int argc, char** argv)
{
	void* handle;
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
	getList = (CK_C_GetFunctionList) GetProcAddress((HMODULE) handle, "C_GetFunctionList");
	getListExtended = (CK_C_EX_GetFunctionListExtended)
		GetProcAddress((HMODULE) handle, "C_EX_GetFunctionListExtended");
#else
	handle = dlopen(argv[1], RTLD_NOW);
	if (handle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 1; }
	getList = (CK_C_GetFunctionList) dlsym(handle, "C_GetFunctionList");
	getListExtended = (CK_C_EX_GetFunctionListExtended)
		dlsym(handle, "C_EX_GetFunctionListExtended");
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

	p11->C_Finalize(NULL_PTR);
	return 0;
}
