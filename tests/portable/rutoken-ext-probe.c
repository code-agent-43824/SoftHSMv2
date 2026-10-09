/*
 * One-run probe of the Rutoken ECP extension surface the battery needs to
 * cover, version 2: C_EX_CreateCSR (including the DN, extension and attribute
 * syntax the library accepts), the GOST and RSA C_EX_PKCS7Sign/Verify family,
 * the last-signature journal, the attribute divergences between the real token
 * and this fork (CKA_EXTRACTABLE, reading a private CKA_VALUE, CKA_TRUSTED and
 * CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN), C_EX_UnblockUserPIN,
 * C_EX_TokenManage for the user PIN, C_EX_SetLocalPIN and the local-PIN status,
 * and - with --format - C_EX_InitToken or the restore-factory-defaults call,
 * which leave the token in its factory state.
 *
 * Everything runs non-interactively against a live token through the Aktiv
 * library and prints one text log; every DER the token produces (CSR
 * requests, CMS envelopes, the certificates the probe builds) is also written
 * to the dump directory, and every journal it reads is printed in hex.
 *
 * All keys are generated on the token and all certificates are signed by the
 * token: X.509 structure is assembled here by hand in plain C, so nothing
 * depends on importing a private key (which the device refuses for GOST) and
 * the binary needs nothing but libc. Call semantics for C_EX_TokenManage,
 * C_EX_SetLocalPIN and MODE_RESTORE_FACTORY_DEFAULTS follow the OpenSC fork's
 * pkcs11-tool (code-agent-43824/opensc), which runs them against the device.
 *
 * Building it:
 *
 *   cc -std=c11 -O2 -I src/lib/pkcs11 tests/portable/rutoken-ext-probe.c -ldl \
 *      -o rutoken-ext-probe
 *
 * Running it: see README-ext-probe.txt.
 *
 * Safety: the probe makes no wrong SO PIN attempt at all. It makes one wrong
 * user PIN attempt (cleared by C_EX_UnblockUserPIN under the SO) and one wrong
 * local-PIN attempt. The token-manage section can leave the user PIN changed;
 * --format then reformats the token to the PINs given on the command line.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "cryptoki.h"
#include "rutoken.h"

#define MAX_SLOTS 64
#define MAX_OBJECTS 4096

/* Restore-factory-defaults parameters, with C_EX_SlotManage mode 0x06. The
 * layout is the one the OpenSC fork's pkcs11-tool passes to the device. */
typedef struct PROBE_RESTORE_FACTORY_DEFAULTS_PARAMS {
	CK_ULONG ulSizeofThisStructure;
	CK_BYTE_PTR pAdminPin;
	CK_ULONG ulAdminPinLen;
	CK_RUTOKEN_INIT_PARAM_PTR pInitParam;
	CK_BYTE_PTR pNewEmitentKey;
	CK_ULONG ulNewEmitentKeyLen;
	CK_ULONG ulNewEmitentKeyRetryCount;
	CK_KEY_TYPE newEmitentKeyType;
} PROBE_RESTORE_FACTORY_DEFAULTS_PARAMS;

static const char PROBE_LABEL[] = "CryptoMost ext probe";

static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
static CK_FUNCTION_LIST_EXTENDED_PTR ex = NULL_PTR;
static void* libraryHandle = NULL;
static CK_SLOT_ID theSlot = 0;

static struct {
	const char* module;
	const char* userPin;
	const char* soPin;
	const char* finalUserPin;
	const char* finalSoPin;
	const char* emitentKeyHex;
	const char* dumpDir;
	int write;
	int format;
	int restoreFactory;
	int emitentMagma;
} opt;

/* ---- output helpers ---------------------------------------------------- */

static void line(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf("\n");
	fflush(stdout);
}

static int sectionNumber = 0;
static void section(const char* fmt, ...)
{
	va_list ap;
	printf("\n==== %d. ", ++sectionNumber);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	printf(" ====\n");
	fflush(stdout);
}

static const char* rvName(CK_RV rv)
{
	switch (rv)
	{
	case CKR_OK: return "CKR_OK";
	case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
	case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PIN_INVALID: return "CKR_PIN_INVALID";
	case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_EXPIRED: return "CKR_PIN_EXPIRED";
	case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
	case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
	case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_CERT_CHAIN_NOT_VERIFIED: return "CKR_CERT_CHAIN_NOT_VERIFIED";
	case CKR_LICENSE_READ_ONLY: return "CKR_LICENSE_READ_ONLY";
	case CKR_VENDOR_EMITENT_KEY_BLOCKED: return "CKR_VENDOR_EMITENT_KEY_BLOCKED";
	case CKR_INAPPROPRIATE_PIN: return "CKR_INAPPROPRIATE_PIN";
	case CKR_PIN_IN_HISTORY: return "CKR_PIN_IN_HISTORY";
	default: return "?";
	}
}

static void showRv(const char* what, CK_RV rv)
{
	line("    %-60s rv = %s (0x%lx)", what, rvName(rv), (unsigned long) rv);
}

static void hexAll(const char* name, const unsigned char* data, size_t length)
{
	size_t i;
	printf("    %s (%lu bytes)", name, (unsigned long) length);
	for (i = 0; i < length; i++)
	{
		if (i % 16 == 0) printf("\n        ");
		printf("%02X ", data[i]);
	}
	printf("\n");
	fflush(stdout);
}

static void dumpToFile(const char* name, const unsigned char* data, size_t length)
{
	char path[512];
	FILE* f;
	if (opt.dumpDir == NULL) return;
	snprintf(path, sizeof(path), "%s/%s", opt.dumpDir, name);
	f = fopen(path, "wb");
	if (f == NULL) { line("    (could not write %s)", path); return; }
	fwrite(data, 1, length, f);
	fclose(f);
	line("    wrote %s (%lu bytes)", path, (unsigned long) length);
}

/* ---- a tiny growable byte buffer and DER builder ----------------------- */

typedef struct { unsigned char* p; size_t n; size_t cap; } Buf;

static void bInit(Buf* b) { b->p = NULL; b->n = 0; b->cap = 0; }
static void bFree(Buf* b) { free(b->p); b->p = NULL; b->n = b->cap = 0; }
static void bPut(Buf* b, const unsigned char* d, size_t n)
{
	if (n == 0) return;
	if (b->n + n > b->cap)
	{
		size_t cap = b->cap ? b->cap * 2 : 256;
		unsigned char* grown;
		while (cap < b->n + n) cap *= 2;
		grown = (unsigned char*) realloc(b->p, cap);
		if (grown == NULL) { fprintf(stderr, "out of memory\n"); exit(1); }
		b->p = grown;
		b->cap = cap;
	}
	memcpy(b->p + b->n, d, n);
	b->n += n;
}
static void bByte(Buf* b, unsigned char c) { bPut(b, &c, 1); }

static void derLen(Buf* b, size_t len)
{
	unsigned char tmp[8];
	int i = 0;
	if (len < 128) { bByte(b, (unsigned char) len); return; }
	while (len) { tmp[i++] = (unsigned char) (len & 0xff); len >>= 8; }
	bByte(b, (unsigned char) (0x80 | i));
	while (i) bByte(b, tmp[--i]);
}

static void tlv(Buf* b, unsigned char tag, const unsigned char* content, size_t clen)
{
	bByte(b, tag);
	derLen(b, clen);
	bPut(b, content, clen);
}

static void tlvBuf(Buf* out, unsigned char tag, const Buf* content)
{
	tlv(out, tag, content->p, content->n);
}

static void derInteger(Buf* b, const unsigned char* mag, size_t n)
{
	size_t i = 0;
	Buf v; bInit(&v);
	while (i + 1 < n && mag[i] == 0 && (mag[i + 1] & 0x80) == 0) i++;
	if ((mag[i] & 0x80) != 0) bByte(&v, 0);
	bPut(&v, mag + i, n - i);
	tlvBuf(b, 0x02, &v);
	bFree(&v);
}

static void derIntByte(Buf* b, unsigned char value) { tlv(b, 0x02, &value, 1); }

/* ---- PKCS #11 small helpers -------------------------------------------- */

static CK_ULONG readAttr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
			 CK_ATTRIBUTE_TYPE type, CK_BYTE_PTR buffer, CK_ULONG size)
{
	CK_ATTRIBUTE attr;
	attr.type = type;
	attr.pValue = buffer;
	attr.ulValueLen = size;
	if (p11->C_GetAttributeValue(session, object, &attr, 1) != CKR_OK)
		return (CK_ULONG) -1;
	return attr.ulValueLen;
}

/* The single object of a class with a given CKA_ID, or CK_INVALID_HANDLE. */
static CK_OBJECT_HANDLE findOne(CK_SESSION_HANDLE session, CK_OBJECT_CLASS cls,
				const char* id)
{
	CK_ATTRIBUTE search[2];
	CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
	CK_ULONG count = 0;
	search[0].type = CKA_CLASS;
	search[0].pValue = &cls;
	search[0].ulValueLen = sizeof(cls);
	search[1].type = CKA_ID;
	search[1].pValue = (CK_VOID_PTR) id;
	search[1].ulValueLen = (CK_ULONG) strlen(id);
	if (p11->C_FindObjectsInit(session, search, 2) != CKR_OK) return CK_INVALID_HANDLE;
	if (p11->C_FindObjects(session, &found, 1, &count) != CKR_OK || count == 0)
		found = CK_INVALID_HANDLE;
	p11->C_FindObjectsFinal(session);
	return found;
}

static int countObjects(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR tmpl, CK_ULONG n)
{
	CK_OBJECT_HANDLE objects[256];
	CK_ULONG found = 0;
	int total = 0;
	if (p11->C_FindObjectsInit(session, tmpl, n) != CKR_OK) return -1;
	do
	{
		found = 0;
		if (p11->C_FindObjects(session, objects, 256, &found) != CKR_OK) break;
		total += (int) found;
	} while (found == 256);
	p11->C_FindObjectsFinal(session);
	return total;
}

static void deleteProbeObjects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ATTRIBUTE search[1];
	CK_ULONG found = 0, i;
	search[0].type = CKA_LABEL;
	search[0].pValue = (CK_VOID_PTR) PROBE_LABEL;
	search[0].ulValueLen = sizeof(PROBE_LABEL) - 1;
	if (p11->C_FindObjectsInit(session, search, 1) != CKR_OK) return;
	p11->C_FindObjects(session, objects, MAX_OBJECTS, &found);
	p11->C_FindObjectsFinal(session);
	for (i = 0; i < found; i++) p11->C_DestroyObject(session, objects[i]);
	if (found > 0) line("    cleaned up %lu probe object(s)", (unsigned long) found);
}

static CK_SESSION_HANDLE openUser(void)
{
	CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
	CK_RV rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				      NULL_PTR, NULL_PTR, &s);
	if (rv != CKR_OK) { showRv("C_OpenSession", rv); return CK_INVALID_HANDLE; }
	rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
	{ showRv("C_Login user", rv); p11->C_CloseSession(s); return CK_INVALID_HANDLE; }
	return s;
}

static CK_SESSION_HANDLE openSo(void)
{
	CK_SESSION_HANDLE s = CK_INVALID_HANDLE;
	CK_RV rv;
	p11->C_CloseAllSessions(theSlot);
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				NULL_PTR, NULL_PTR, &s);
	if (rv != CKR_OK) { showRv("C_OpenSession (SO)", rv); return CK_INVALID_HANDLE; }
	rv = p11->C_Login(s, CKU_SO, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin));
	if (rv != CKR_OK)
	{ showRv("C_Login SO", rv); p11->C_CloseSession(s); return CK_INVALID_HANDLE; }
	return s;
}

static void extendedState(const char* when)
{
	CK_TOKEN_INFO_EXTENDED info;
	CK_TOKEN_INFO base;
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	if (ex && ex->C_EX_GetTokenInfoExtended &&
	    ex->C_EX_GetTokenInfoExtended(theSlot, &info) == CKR_OK)
		line("    [%s] ext flags 0x%lx ADMIN_NOT_DEFAULT=%d USER_NOT_DEFAULT=%d "
		     "SO %lu/%lu user %lu/%lu", when, (unsigned long) info.flags,
		     (info.flags & TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT) ? 1 : 0,
		     (info.flags & TOKEN_FLAGS_USER_PIN_NOT_DEFAULT) ? 1 : 0,
		     (unsigned long) info.ulAdminRetryCountLeft, (unsigned long) info.ulMaxAdminRetryCount,
		     (unsigned long) info.ulUserRetryCountLeft, (unsigned long) info.ulMaxUserRetryCount);
	memset(&base, 0, sizeof(base));
	if (p11->C_GetTokenInfo(theSlot, &base) == CKR_OK)
		line("    [%s] token flags 0x%lx USER_PIN_TO_BE_CHANGED=%d label '%.32s'", when,
		     (unsigned long) base.flags,
		     (base.flags & CKF_USER_PIN_TO_BE_CHANGED) ? 1 : 0, base.label);
}

static CK_RV pinToBeChanged(CK_USER_TYPE user)
{
	CK_USER_TYPE value = user;
	if (ex == NULL || ex->C_EX_SlotManage == NULL) return CKR_FUNCTION_NOT_SUPPORTED;
	return ex->C_EX_SlotManage(theSlot, MODE_GET_PIN_SET_TO_BE_CHANGED, &value);
}

/* ---- journal ----------------------------------------------------------- */

static CK_ULONG journalLen = 0;
static CK_BYTE journalBuf[4096];

/* Read the journal into journalBuf; returns 1 if the content differs from
 * the previous read. */
static int readJournal(const char* when)
{
	CK_BYTE previous[4096];
	CK_ULONG previousLen = journalLen;
	CK_ULONG size = 0;
	CK_RV rv;
	memcpy(previous, journalBuf, previousLen);
	if (ex == NULL || ex->C_EX_GetJournal == NULL)
	{ line("    C_EX_GetJournal is not in the table"); return 0; }
	rv = ex->C_EX_GetJournal(theSlot, NULL_PTR, &size);
	if (rv != CKR_OK) { showRv("C_EX_GetJournal (size)", rv); return 0; }
	if (size > sizeof(journalBuf)) size = sizeof(journalBuf);
	journalLen = size;
	if (size > 0)
	{
		rv = ex->C_EX_GetJournal(theSlot, journalBuf, &journalLen);
		if (rv != CKR_OK) { showRv("C_EX_GetJournal (read)", rv); journalLen = 0; return 0; }
	}
	{
		int changed = journalLen != previousLen ||
			      memcmp(previous, journalBuf, journalLen) != 0;
		line("    journal %-34s %lu bytes, %s the previous read", when,
		     (unsigned long) journalLen, changed ? "DIFFERS from" : "same as");
		return changed;
	}
}

/* ---- key generation ---------------------------------------------------- */

static const CK_BYTE CURVE_CP_A[]    = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x01 };
static const CK_BYTE CURVE_TC26_A[]  = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x01 };
static const CK_BYTE CURVE_512_A[]   = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x01 };
static const CK_BYTE DIGEST_256[]    = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x02 };
static const CK_BYTE DIGEST_512[]    = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x03 };

static CK_RV genGostCurve(CK_SESSION_HANDLE session, const char* id, int bits,
			  const CK_BYTE* curve, CK_ULONG curveLen, int sign, int extractable,
			  CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = bits == 512 ? CKK_GOSTR3410_512 : CKK_GOSTR3410;
	CK_MECHANISM mech = { bits == 512 ? CKM_GOSTR3410_512_KEY_PAIR_GEN
					  : CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_BBOOL signFlag = sign ? CK_TRUE : CK_FALSE;
	CK_BBOOL extractFlag = extractable ? CK_TRUE : CK_FALSE;
	const CK_BYTE* digest = bits == 512 ? DIGEST_512 : DIGEST_256;
	CK_ULONG digestLen = bits == 512 ? sizeof(DIGEST_512) : sizeof(DIGEST_256);
	CK_ATTRIBUTE pubT[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, (CK_ULONG) strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) digest, digestLen }
	};
	CK_ATTRIBUTE privT[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &signFlag, sizeof(signFlag) },
		{ CKA_DERIVE, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &extractFlag, sizeof(extractFlag) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, (CK_ULONG) strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) digest, digestLen }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech,
		pubT, sizeof(pubT) / sizeof(pubT[0]),
		privT, sizeof(privT) / sizeof(privT[0]), pub, priv);
}

static CK_RV genGost(CK_SESSION_HANDLE session, const char* id, int sign,
		     CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	return genGostCurve(session, id, 256, CURVE_CP_A, sizeof(CURVE_CP_A), sign, 0, pub, priv);
}

static CK_RV genRsa(CK_SESSION_HANDLE session, const char* id,
		    CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE;
	CK_ULONG bits = 2048;
	CK_BYTE exponent[] = { 0x01, 0x00, 0x01 };
	CK_ATTRIBUTE pubT[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_MODULUS_BITS, &bits, sizeof(bits) },
		{ CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, (CK_ULONG) strlen(id) }
	};
	CK_ATTRIBUTE privT[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, (CK_ULONG) strlen(id) }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech,
		pubT, sizeof(pubT) / sizeof(pubT[0]),
		privT, sizeof(privT) / sizeof(privT[0]), pub, priv);
}

/* ---- X.509 building blocks --------------------------------------------- */

/* A one-RDN Name carrying a commonName. */
static void buildName(Buf* out, const char* cn)
{
	static const unsigned char cnOid[] = { 0x55, 0x04, 0x03 };
	Buf atv, set, rdn;
	bInit(&atv); bInit(&set); bInit(&rdn);
	tlv(&atv, 0x06, cnOid, sizeof(cnOid));
	tlv(&atv, 0x0c, (const unsigned char*) cn, strlen(cn));
	tlvBuf(&set, 0x30, &atv);
	tlvBuf(&rdn, 0x31, &set);
	tlvBuf(out, 0x30, &rdn);
	bFree(&atv); bFree(&set); bFree(&rdn);
}

/* Extensions: basicConstraints (critical) and keyUsage (critical), wrapped
 * as [3] EXPLICIT SEQUENCE OF Extension. */
static void buildExtensions(Buf* out, int isCa)
{
	static const unsigned char bcOid[] = { 0x55, 0x1d, 0x13 };
	static const unsigned char kuOid[] = { 0x55, 0x1d, 0x0f };
	/* keyUsage BIT STRING: CA keyCertSign|cRLSign, leaf digitalSignature. */
	static const unsigned char kuCa[]   = { 0x03, 0x02, 0x01, 0x06 };
	static const unsigned char kuLeaf[] = { 0x03, 0x02, 0x07, 0x80 };
	static const unsigned char yes[] = { 0xff };
	Buf list, ext, value, tagged, inner;
	bInit(&list); bInit(&ext); bInit(&value); bInit(&tagged); bInit(&inner);

	/* basicConstraints */
	if (isCa) tlv(&inner, 0x01, yes, 1);
	tlvBuf(&value, 0x30, &inner);
	tlv(&ext, 0x06, bcOid, sizeof(bcOid));
	tlv(&ext, 0x01, yes, 1);
	tlvBuf(&ext, 0x04, &value);
	tlvBuf(&list, 0x30, &ext);
	bFree(&ext); bFree(&value); bFree(&inner);
	bInit(&ext);

	/* keyUsage */
	tlv(&ext, 0x06, kuOid, sizeof(kuOid));
	tlv(&ext, 0x01, yes, 1);
	if (isCa) tlv(&ext, 0x04, kuCa, sizeof(kuCa));
	else tlv(&ext, 0x04, kuLeaf, sizeof(kuLeaf));
	tlvBuf(&list, 0x30, &ext);

	{
		Buf seq; bInit(&seq);
		tlvBuf(&seq, 0x30, &list);       /* Extensions ::= SEQUENCE OF */
		tlvBuf(&tagged, 0xa3, &seq);     /* [3] EXPLICIT */
		bPut(out, tagged.p, tagged.n);
		bFree(&seq);
	}
	bFree(&list); bFree(&ext); bFree(&tagged);
}

static void buildValidity(Buf* out)
{
	static const unsigned char notBefore[] =
		{'2','6','0','1','0','1','0','0','0','0','0','0','Z'};
	static const unsigned char notAfter[] =
		{'3','6','0','1','0','1','0','0','0','0','0','0','Z'};
	Buf v; bInit(&v);
	tlv(&v, 0x17, notBefore, sizeof(notBefore));
	tlv(&v, 0x17, notAfter, sizeof(notAfter));
	tlvBuf(out, 0x30, &v);
	bFree(&v);
}

/* subjectPublicKeyInfo for a token GOST public key. */
static int gostSpki(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, Buf* out)
{
	static const unsigned char keyAlgOid[] =
		{ 0x2a,0x85,0x03,0x07,0x01,0x01,0x01,0x01 }; /* 1.2.643.7.1.1.1.1 */
	CK_BYTE point[256], curve[64], digest[64];
	CK_ULONG pointLen, curveLen, digestLen;
	Buf params, alg, algSeq, octet, bits, inner;
	pointLen = readAttr(session, pub, CKA_VALUE, point, sizeof(point));
	curveLen = readAttr(session, pub, CKA_GOSTR3410_PARAMS, curve, sizeof(curve));
	digestLen = readAttr(session, pub, CKA_GOSTR3411_PARAMS, digest, sizeof(digest));
	if (pointLen == (CK_ULONG) -1 || curveLen == (CK_ULONG) -1 || digestLen == (CK_ULONG) -1)
		return 0;
	bInit(&params); bInit(&alg); bInit(&algSeq); bInit(&octet); bInit(&bits); bInit(&inner);
	bPut(&params, curve, curveLen);
	bPut(&params, digest, digestLen);
	tlv(&alg, 0x06, keyAlgOid, sizeof(keyAlgOid));
	tlvBuf(&alg, 0x30, &params);
	tlvBuf(&algSeq, 0x30, &alg);
	tlv(&octet, 0x04, point, pointLen);
	bByte(&bits, 0x00);
	bPut(&bits, octet.p, octet.n);
	bPut(&inner, algSeq.p, algSeq.n);
	tlvBuf(&inner, 0x03, &bits);
	tlvBuf(out, 0x30, &inner);
	bFree(&params); bFree(&alg); bFree(&algSeq); bFree(&octet); bFree(&bits); bFree(&inner);
	return 1;
}

/* A GOST R 34.10-2012/256 certificate for subjectPub, signed on the token
 * with issuerPriv: Certificate ::= SEQUENCE { tbs, sigAlg, BIT STRING }. */
static int gostCertificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE subjectPub,
			   CK_OBJECT_HANDLE issuerPriv, const char* issuerCn,
			   const char* subjectCn, unsigned char serial, int isCa,
			   Buf* out)
{
	static const unsigned char sigAlgOid[] =
		{ 0x2a,0x85,0x03,0x07,0x01,0x01,0x03,0x02 }; /* 1.2.643.7.1.1.3.2 */
	Buf tbs, inner, spki, sigAlg, a, version, vi, cert, bits;
	CK_BYTE hash[64], sig[128];
	CK_ULONG hashLen = sizeof(hash), sigLen = sizeof(sig);
	CK_MECHANISM digestMech = { CKM_GOSTR3411_12_256, NULL_PTR, 0 };
	CK_MECHANISM signMech = { CKM_GOSTR3410, NULL_PTR, 0 };
	CK_RV rv;
	int ok = 0;

	bInit(&tbs); bInit(&inner); bInit(&spki); bInit(&sigAlg); bInit(&a);
	bInit(&version); bInit(&vi); bInit(&cert); bInit(&bits);
	if (!gostSpki(session, subjectPub, &spki)) goto done;
	tlv(&a, 0x06, sigAlgOid, sizeof(sigAlgOid));
	tlvBuf(&sigAlg, 0x30, &a);
	derIntByte(&vi, 2);
	tlvBuf(&version, 0xa0, &vi);

	bPut(&inner, version.p, version.n);
	derIntByte(&inner, serial);
	bPut(&inner, sigAlg.p, sigAlg.n);
	buildName(&inner, issuerCn);
	buildValidity(&inner);
	buildName(&inner, subjectCn);
	bPut(&inner, spki.p, spki.n);
	buildExtensions(&inner, isCa);
	tlvBuf(&tbs, 0x30, &inner);

	rv = p11->C_DigestInit(session, &digestMech);
	if (rv == CKR_OK) rv = p11->C_Digest(session, tbs.p, tbs.n, hash, &hashLen);
	if (rv == CKR_OK) rv = p11->C_SignInit(session, &signMech, issuerPriv);
	if (rv == CKR_OK) rv = p11->C_Sign(session, hash, hashLen, sig, &sigLen);
	if (rv != CKR_OK) { showRv("token signature of a GOST certificate", rv); goto done; }

	bPut(&cert, tbs.p, tbs.n);
	bPut(&cert, sigAlg.p, sigAlg.n);
	bByte(&bits, 0x00);
	bPut(&bits, sig, sigLen);
	tlvBuf(&cert, 0x03, &bits);
	tlvBuf(out, 0x30, &cert);
	ok = 1;
done:
	bFree(&tbs); bFree(&inner); bFree(&spki); bFree(&sigAlg); bFree(&a);
	bFree(&version); bFree(&vi); bFree(&cert); bFree(&bits);
	return ok;
}

/* An RSA certificate (self-signed, sha256WithRSAEncryption). */
static int rsaCertificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
			  CK_OBJECT_HANDLE priv, const char* cn, Buf* out)
{
	static const unsigned char rsaSha256[] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
	static const unsigned char rsaEnc[]    = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };
	CK_BYTE modulus[512], exponent[8], sig[512];
	CK_ULONG modLen, expLen, sigLen = sizeof(sig);
	CK_MECHANISM signMech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
	Buf tbs, inner, sigAlg, a, version, vi, spki, algId, modExp, rsaKey, keyBits, spkiInner, cert, bits;
	CK_RV rv;
	int ok = 0;
	modLen = readAttr(session, pub, CKA_MODULUS, modulus, sizeof(modulus));
	expLen = readAttr(session, pub, CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent));
	if (modLen == (CK_ULONG) -1 || expLen == (CK_ULONG) -1) return 0;
	bInit(&tbs); bInit(&inner); bInit(&sigAlg); bInit(&a); bInit(&version); bInit(&vi);
	bInit(&spki); bInit(&algId); bInit(&modExp); bInit(&rsaKey); bInit(&keyBits);
	bInit(&spkiInner); bInit(&cert); bInit(&bits);

	tlv(&a, 0x06, rsaSha256, sizeof(rsaSha256));
	tlv(&a, 0x05, NULL, 0);
	tlvBuf(&sigAlg, 0x30, &a);
	derIntByte(&vi, 2);
	tlvBuf(&version, 0xa0, &vi);

	tlv(&algId, 0x06, rsaEnc, sizeof(rsaEnc));
	tlv(&algId, 0x05, NULL, 0);
	derInteger(&modExp, modulus, modLen);
	derInteger(&modExp, exponent, expLen);
	tlvBuf(&rsaKey, 0x30, &modExp);
	bByte(&keyBits, 0x00);
	bPut(&keyBits, rsaKey.p, rsaKey.n);
	tlvBuf(&spkiInner, 0x30, &algId);
	tlvBuf(&spkiInner, 0x03, &keyBits);
	tlvBuf(&spki, 0x30, &spkiInner);

	bPut(&inner, version.p, version.n);
	derIntByte(&inner, 1);
	bPut(&inner, sigAlg.p, sigAlg.n);
	buildName(&inner, cn);
	buildValidity(&inner);
	buildName(&inner, cn);
	bPut(&inner, spki.p, spki.n);
	buildExtensions(&inner, 0);
	tlvBuf(&tbs, 0x30, &inner);

	rv = p11->C_SignInit(session, &signMech, priv);
	if (rv == CKR_OK) rv = p11->C_Sign(session, tbs.p, tbs.n, sig, &sigLen);
	if (rv != CKR_OK) { showRv("token signature of an RSA certificate", rv); goto done; }
	bPut(&cert, tbs.p, tbs.n);
	bPut(&cert, sigAlg.p, sigAlg.n);
	bByte(&bits, 0x00);
	bPut(&bits, sig, sigLen);
	tlvBuf(&cert, 0x03, &bits);
	tlvBuf(out, 0x30, &cert);
	ok = 1;
done:
	bFree(&tbs); bFree(&inner); bFree(&sigAlg); bFree(&a); bFree(&version); bFree(&vi);
	bFree(&spki); bFree(&algId); bFree(&modExp); bFree(&rsaKey); bFree(&keyBits);
	bFree(&spkiInner); bFree(&cert); bFree(&bits);
	return ok;
}

static CK_RV importCert(CK_SESSION_HANDLE session, const char* id, const char* subjectCn,
			const Buf* der, CK_OBJECT_HANDLE* out)
{
	CK_OBJECT_CLASS objectClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL yes = CK_TRUE;
	Buf subject;
	CK_RV rv;
	bInit(&subject);
	buildName(&subject, subjectCn);
	{
		CK_ATTRIBUTE attrs[] = {
			{ CKA_CLASS, &objectClass, sizeof(objectClass) },
			{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
			{ CKA_TOKEN, &yes, sizeof(yes) },
			{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
			{ CKA_SUBJECT, subject.p, (CK_ULONG) subject.n },
			{ CKA_ID, (CK_VOID_PTR) id, (CK_ULONG) strlen(id) },
			{ CKA_VALUE, der->p, (CK_ULONG) der->n }
		};
		*out = CK_INVALID_HANDLE;
		rv = p11->C_CreateObject(session, attrs, sizeof(attrs) / sizeof(attrs[0]), out);
	}
	bFree(&subject);
	return rv;
}

/* ---- 1. identity ------------------------------------------------------- */

static void probeIdentity(void)
{
	CK_INFO info;
	CK_TOKEN_INFO token;
	section("Library and token identity");
	memset(&info, 0, sizeof(info));
	if (p11->C_GetInfo(&info) == CKR_OK)
	{
		line("    manufacturer '%.32s'", info.manufacturerID);
		line("    library      '%.32s' version %u.%u", info.libraryDescription,
		     info.libraryVersion.major, info.libraryVersion.minor);
	}
	if (ex) line("    extended table version %u.%u", ex->version.major, ex->version.minor);
	memset(&token, 0, sizeof(token));
	if (p11->C_GetTokenInfo(theSlot, &token) == CKR_OK)
	{
		line("    model        '%.16s'", token.model);
		line("    serialNumber '%.16s'", token.serialNumber);
		line("    firmware     %u.%u", token.firmwareVersion.major, token.firmwareVersion.minor);
	}
	extendedState("start");
	line("    PIN to be changed: user %s, SO %s",
	     rvName(pinToBeChanged(CKU_USER)), rvName(pinToBeChanged(CKU_SO)));
}

/* ---- 2. C_EX_CreateCSR ------------------------------------------------- */

static CK_RV csrCall(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv,
		     const char** dn, CK_ULONG dnCount, const char** attrs, CK_ULONG attrCount,
		     const char** exts, CK_ULONG extCount, const char* what, const char* dumpName)
{
	CK_BYTE_PTR csr = NULL_PTR;
	CK_ULONG csrLen = 0;
	CK_RV rv;
	if (ex == NULL || ex->C_EX_CreateCSR == NULL)
	{ line("    C_EX_CreateCSR is not in the table"); return CKR_FUNCTION_NOT_SUPPORTED; }
	rv = ex->C_EX_CreateCSR(session, pub, (CK_CHAR_PTR*) dn, dnCount, &csr, &csrLen, priv,
				(CK_CHAR_PTR*) attrs, attrCount, (CK_CHAR_PTR*) exts, extCount);
	showRv(what, rv);
	if (rv == CKR_OK && csr != NULL_PTR)
	{
		if (dumpName) dumpToFile(dumpName, csr, csrLen);
		else line("    CSR %lu bytes", (unsigned long) csrLen);
	}
	if (csr != NULL_PTR && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(csr);
	return rv;
}

static void probeCsr(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE aPub, aPriv, tPub, tPriv, gPub, gPriv, rPub, rPriv, nPub, nPriv;
	CK_RV rv;
	static const char* dnBasic[] = { "CN", "CryptoMost Probe", "O", "CryptoMost", "C", "RU" };
	static const char* dnCnOnly[] = { "CN", "CryptoMost Probe" };
	section("C_EX_CreateCSR: key types, DN/extension/attribute syntax, negatives");
	readJournal("before the CSR section");

	rv = genGostCurve(session, "csr-cpA", 256, CURVE_CP_A, sizeof(CURVE_CP_A), 1, 0, &aPub, &aPriv);
	showRv("generate GOST-256 CryptoPro-A", rv);
	rv = genGostCurve(session, "csr-tc26A", 256, CURVE_TC26_A, sizeof(CURVE_TC26_A), 1, 0, &tPub, &tPriv);
	showRv("generate GOST-256 TC26-A", rv);
	rv = genGostCurve(session, "csr-512A", 512, CURVE_512_A, sizeof(CURVE_512_A), 1, 0, &gPub, &gPriv);
	showRv("generate GOST-512 TC26-A", rv);
	rv = genRsa(session, "csr-rsa", &rPub, &rPriv);
	showRv("generate RSA-2048", rv);
	rv = genGostCurve(session, "csr-nosign", 256, CURVE_CP_A, sizeof(CURVE_CP_A), 0, 0, &nPub, &nPriv);
	showRv("generate GOST-256 key with CKA_SIGN=false", rv);

	line("  basic DN {CN, O, C} on every key type:");
	csrCall(session, aPub, aPriv, dnBasic, 6, NULL, 0, NULL, 0, "GOST-256 CryptoPro-A", "csr-gost256-cpA.der");
	csrCall(session, tPub, tPriv, dnBasic, 6, NULL, 0, NULL, 0, "GOST-256 TC26-A", "csr-gost256-tc26A.der");
	csrCall(session, gPub, gPriv, dnBasic, 6, NULL, 0, NULL, 0, "GOST-512 TC26-A", "csr-gost512-tc26A.der");
	csrCall(session, rPub, rPriv, dnBasic, 6, NULL, 0, NULL, 0, "RSA-2048", "csr-rsa2048.der");
	readJournal("after the GOST CSRs");

	line("  DN syntax (GOST-256 CryptoPro-A key):");
	{
		static const char* dnFull[] = {
			"CN", "CryptoMost Probe", "SN", "Probe", "GN", "Crypto", "title", "Tester",
			"O", "CryptoMost", "OU", "QA", "L", "Moscow", "ST", "Moscow",
			"street", "Main 1", "C", "RU", "emailAddress", "probe@example.com" };
		static const char* dnRussian[] = {
			"CN", "CryptoMost Probe",
			"1.2.643.3.131.1.1", "123456789012",   /* INN */
			"1.2.643.100.1", "1234567890123",      /* OGRN */
			"1.2.643.100.3", "12345678901",        /* SNILS */
			"1.2.643.100.4", "1234567890" };       /* INNLE */
		static const char* dnOid[] = { "2.5.4.3", "CryptoMost Probe", "2.5.4.6", "RU" };
		static const char* dnCyrillic[] = { "CN", "\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82 "
						      "\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82\xd0\xbe\xd0\xb2" };
		static const char* dnLongNames[] = { "commonName", "CryptoMost Probe",
						     "countryName", "RU" };
		static const char* dnEmail[] = { "CN", "CryptoMost Probe", "E", "probe@example.com" };
		csrCall(session, aPub, aPriv, dnFull, 22, NULL, 0, NULL, 0, "DN full set (short names)", "csr-dn-full.der");
		csrCall(session, aPub, aPriv, dnRussian, 10, NULL, 0, NULL, 0, "DN INN/OGRN/SNILS/INNLE OIDs", "csr-dn-russian.der");
		csrCall(session, aPub, aPriv, dnOid, 4, NULL, 0, NULL, 0, "DN by dotted OIDs", "csr-dn-oid.der");
		csrCall(session, aPub, aPriv, dnCyrillic, 2, NULL, 0, NULL, 0, "DN Cyrillic UTF-8 CN", "csr-dn-cyrillic.der");
		csrCall(session, aPub, aPriv, dnLongNames, 4, NULL, 0, NULL, 0, "DN long names (commonName)", "csr-dn-longnames.der");
		csrCall(session, aPub, aPriv, dnEmail, 4, NULL, 0, NULL, 0, "DN 'E' for email", "csr-dn-E.der");
	}

	line("  extension syntax (DN = CN only):");
	{
		static const char* extKu[] = { "keyUsage", "digitalSignature,nonRepudiation" };
		static const char* extKuOid[] = { "2.5.29.15", "digitalSignature" };
		static const char* extEku[] = { "extendedKeyUsage", "1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4" };
		static const char* extBc[] = { "basicConstraints", "CA:FALSE" };
		static const char* extPol[] = { "certificatePolicies", "1.2.643.100.113.1" };
		static const char* extSst[] = { "1.2.643.100.111", "ASN1:UTF8String:CryptoMost probe tool" };
		static const char* extSstName[] = { "subjectSignTool", "CryptoMost probe tool" };
		static const char* extTwo[] = { "keyUsage", "digitalSignature",
						"extendedKeyUsage", "1.3.6.1.5.5.7.3.4" };
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extKu, 2, "keyUsage by name", "csr-ext-ku.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extKuOid, 2, "keyUsage by OID 2.5.29.15", "csr-ext-ku-oid.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extEku, 2, "extendedKeyUsage OID list", "csr-ext-eku.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extBc, 2, "basicConstraints CA:FALSE", "csr-ext-bc.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extPol, 2, "certificatePolicies OID", "csr-ext-pol.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extSst, 2, "subjectSignTool OID, ASN1:UTF8String:", "csr-ext-sst.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extSstName, 2, "subjectSignTool by name", "csr-ext-sst-name.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, NULL, 0, extTwo, 4, "keyUsage + extendedKeyUsage", "csr-ext-two.der");
	}

	line("  attribute syntax (DN = CN only):");
	{
		static const char* attrCp[] = { "challengePassword", "probe-secret" };
		static const char* attrCpOid[] = { "1.2.840.113549.1.9.7", "probe-secret" };
		static const char* attrUn[] = { "unstructuredName", "probe" };
		csrCall(session, aPub, aPriv, dnCnOnly, 2, attrCp, 2, NULL, 0, "challengePassword by name", "csr-attr-cp.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, attrCpOid, 2, NULL, 0, "challengePassword by OID", "csr-attr-cp-oid.der");
		csrCall(session, aPub, aPriv, dnCnOnly, 2, attrUn, 2, NULL, 0, "unstructuredName by name", "csr-attr-un.der");
	}

	line("  negatives:");
	{
		static const char* dnOdd[] = { "CN", "CryptoMost Probe", "O" };
		static const char* dnUnknown[] = { "XYZ", "value" };
		csrCall(session, nPub, nPriv, dnBasic, 6, NULL, 0, NULL, 0, "private key has CKA_SIGN=false", NULL);
		csrCall(session, aPub, aPriv, dnOdd, 3, NULL, 0, NULL, 0, "odd number of DN strings", NULL);
		csrCall(session, aPub, aPriv, NULL, 0, NULL, 0, NULL, 0, "empty DN (NULL, 0)", "csr-dn-empty.der");
		csrCall(session, aPub, aPriv, dnUnknown, 2, NULL, 0, NULL, 0, "unknown DN type 'XYZ'", NULL);
		csrCall(session, aPriv, aPriv, dnBasic, 6, NULL, 0, NULL, 0, "private key handle as hPublicKey", NULL);
		csrCall(session, aPub, tPriv, dnBasic, 6, NULL, 0, NULL, 0, "public and private keys from different pairs", "csr-mismatch.der");
	}

	line("  negative: no login (the application is logged out, then back in):");
	rv = p11->C_Logout(session);
	showRv("C_Logout", rv);
	csrCall(session, aPub, aPriv, dnBasic, 6, NULL, 0, NULL, 0, "C_EX_CreateCSR while logged out", NULL);
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
	showRv("C_Login user again", rv);
}

/* ---- 3. GOST CMS ------------------------------------------------------- */

static int verifyCount = 0;

static void freeSigners(CK_VENDOR_BUFFER_PTR signers, CK_ULONG count)
{
	CK_ULONG i;
	if (signers == NULL_PTR || ex == NULL || ex->C_EX_FreeBuffer == NULL) return;
	for (i = 0; i < count; i++) ex->C_EX_FreeBuffer(signers[i].pData);
	ex->C_EX_FreeBuffer((CK_BYTE_PTR) signers);
}

/* Verify an envelope. trusted/untrusted may be NULL. */
static void verifyEnvelope(CK_SESSION_HANDLE session, const unsigned char* envelope,
			   CK_ULONG envelopeLen, const Buf* trusted, const Buf* extra,
			   CK_FLAGS flags, int useStore, const unsigned char* original,
			   CK_ULONG originalLen, int detached, const char* what)
{
	CK_VENDOR_X509_STORE store;
	CK_VENDOR_BUFFER trustedBuf[1], extraBuf[1];
	CK_BYTE_PTR data = NULL_PTR;
	CK_ULONG dataLen = 0;
	CK_VENDOR_BUFFER_PTR signers = NULL_PTR;
	CK_ULONG signerCount = 0;
	char label[160];
	CK_RV rv;
	if (ex == NULL || ex->C_EX_PKCS7VerifyInit == NULL || ex->C_EX_PKCS7Verify == NULL)
	{ line("    verify functions are not in the table"); return; }
	memset(&store, 0, sizeof(store));
	if (trusted)
	{
		trustedBuf[0].pData = trusted->p;
		trustedBuf[0].ulSize = (CK_ULONG) trusted->n;
		store.pTrustedCertificates = trustedBuf;
		store.ulTrustedCertificateCount = 1;
	}
	if (extra)
	{
		extraBuf[0].pData = extra->p;
		extraBuf[0].ulSize = (CK_ULONG) extra->n;
		store.pCertificates = extraBuf;
		store.ulCertificateCount = 1;
	}
	snprintf(label, sizeof(label), "#%d %s: VerifyInit", ++verifyCount, what);
	rv = ex->C_EX_PKCS7VerifyInit(session, (CK_BYTE_PTR) envelope, envelopeLen,
				      useStore ? &store : NULL_PTR, OPTIONAL_CRL_CHECK, flags);
	showRv(label, rv);
	if (rv != CKR_OK) return;
	if (detached)
	{
		if (ex->C_EX_PKCS7VerifyUpdate)
		{
			rv = ex->C_EX_PKCS7VerifyUpdate(session, (CK_BYTE_PTR) original, originalLen);
			showRv("    VerifyUpdate", rv);
		}
		if (ex->C_EX_PKCS7VerifyFinal)
		{
			rv = ex->C_EX_PKCS7VerifyFinal(session, &signers, &signerCount);
			showRv("    VerifyFinal", rv);
		}
		line("      signer count = %lu, signers %s", (unsigned long) signerCount,
		     signers ? "returned" : "NULL");
	}
	else
	{
		rv = ex->C_EX_PKCS7Verify(session, &data, &dataLen, &signers, &signerCount);
		showRv("    Verify", rv);
		line("      signer count = %lu, signers %s", (unsigned long) signerCount,
		     signers ? "returned" : "NULL");
		if (data != NULL_PTR)
		{
			int match = dataLen == originalLen &&
				    (originalLen == 0 || memcmp(data, original, originalLen) == 0);
			line("      extracted %lu bytes, byte-for-byte equal to the input: %s",
			     (unsigned long) dataLen, match ? "YES" : "NO");
			if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(data);
		}
		else line("      no data returned");
	}
	freeSigners(signers, signerCount);
}

/* Sign; on success write the envelope and return it in *out (caller frees
 * with C_EX_FreeBuffer). */
static CK_RV signCms(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE certObj,
		     CK_OBJECT_HANDLE privKey, CK_OBJECT_HANDLE* chain, CK_ULONG chainLen,
		     const unsigned char* data, CK_ULONG dataLen, CK_ULONG flags,
		     const char* what, const char* dumpName, CK_BYTE_PTR* out, CK_ULONG* outLen)
{
	CK_RV rv;
	*out = NULL_PTR;
	*outLen = 0;
	if (ex == NULL || ex->C_EX_PKCS7Sign == NULL)
	{ line("    C_EX_PKCS7Sign is not in the table"); return CKR_FUNCTION_NOT_SUPPORTED; }
	rv = ex->C_EX_PKCS7Sign(session, (CK_BYTE_PTR) data, dataLen, certObj, out, outLen,
				privKey, chain, chainLen, flags);
	showRv(what, rv);
	if (rv == CKR_OK && *out != NULL_PTR && dumpName) dumpToFile(dumpName, *out, *outLen);
	return rv;
}

static void probeGostCms(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE rootPub, rootPriv, leafPub, leafPriv, otherPub, otherPriv;
	CK_OBJECT_HANDLE rootCert = CK_INVALID_HANDLE, leafCert = CK_INVALID_HANDLE, otherCert = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE chain[1];
	Buf rootDer, leafDer, otherDer;
	static const unsigned char payload[] = "CryptoMost GOST CMS parity payload";
	const CK_ULONG payloadLen = sizeof(payload) - 1;
	CK_BYTE_PTR env = NULL_PTR;
	CK_ULONG envLen = 0;
	CK_RV rv;
	section("GOST C_EX_PKCS7Sign / C_EX_PKCS7Verify");
	bInit(&rootDer); bInit(&leafDer); bInit(&otherDer);

	if (genGost(session, "cms-ca", 1, &rootPub, &rootPriv) != CKR_OK ||
	    genGost(session, "cms-leaf", 1, &leafPub, &leafPriv) != CKR_OK ||
	    genGost(session, "cms-other", 1, &otherPub, &otherPriv) != CKR_OK)
	{ line("    could not generate the GOST keys"); goto done; }
	if (!gostCertificate(session, rootPub, rootPriv, "CryptoMost CA", "CryptoMost CA", 1, 1, &rootDer) ||
	    !gostCertificate(session, leafPub, rootPriv, "CryptoMost CA", "CryptoMost Signer", 2, 0, &leafDer) ||
	    !gostCertificate(session, otherPub, otherPriv, "Unrelated CA", "Unrelated CA", 3, 1, &otherDer))
	{ line("    could not build the GOST certificates"); goto done; }
	dumpToFile("gost-root.der", rootDer.p, rootDer.n);
	dumpToFile("gost-leaf.der", leafDer.p, leafDer.n);
	dumpToFile("gost-other.der", otherDer.p, otherDer.n);
	showRv("import leaf certificate", importCert(session, "cms-leaf", "CryptoMost Signer", &leafDer, &leafCert));
	showRv("import root certificate", importCert(session, "cms-ca", "CryptoMost CA", &rootDer, &rootCert));
	showRv("import unrelated certificate", importCert(session, "cms-other", "Unrelated CA", &otherDer, &otherCert));
	if (leafCert == CK_INVALID_HANDLE) goto done;
	chain[0] = rootCert;
	readJournal("before CMS signing");

	line("  signing variants:");
	rv = signCms(session, leafCert, leafPriv, chain, 1, payload, payloadLen, 0,
		     "attached, explicit key, chain [root]", "cms-gost-attached.der", &env, &envLen);
	if (rv == CKR_OK)
	{
		readJournal("after attached PKCS7Sign");
		verifyEnvelope(session, env, envLen, &rootDer, NULL, 0, 1, payload, payloadLen, 0,
			       "attached, trusted root");
		/* tamper the signature: the signerInfo signature is the last field */
		{
			CK_BYTE* copy = (CK_BYTE*) malloc(envLen);
			if (copy)
			{
				memcpy(copy, env, envLen);
				copy[envLen - 3] ^= 0xff;
				verifyEnvelope(session, copy, envLen, &rootDer, NULL, 0, 1, payload,
					       payloadLen, 0, "tampered signature");
				free(copy);
			}
		}
		verifyEnvelope(session, env, envLen, &otherDer, NULL, 0, 1, payload, payloadLen, 0,
			       "foreign CA trusted only");
		verifyEnvelope(session, env, envLen, NULL, NULL, CKF_VENDOR_CHECK_SIGNATURE_ONLY, 0,
			       payload, payloadLen, 0, "CHECK_SIGNATURE_ONLY, no store");
		verifyEnvelope(session, env, envLen, NULL, NULL, 0, 0, payload, payloadLen, 0,
			       "no store, no flags");
		verifyEnvelope(session, env, envLen, &leafDer, NULL, CKF_VENDOR_ALLOW_PARTIAL_CHAINS, 1,
			       payload, payloadLen, 0, "ALLOW_PARTIAL_CHAINS, leaf trusted");
		verifyEnvelope(session, env, envLen, &rootDer, NULL, CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS, 1,
			       payload, payloadLen, 0, "DO_NOT_USE_INTERNAL_CMS_CERTS, root trusted");
		verifyEnvelope(session, env, envLen, &rootDer, &leafDer, CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS, 1,
			       payload, payloadLen, 0, "DO_NOT_USE_INTERNAL, leaf given in store");
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	}

	rv = signCms(session, leafCert, CK_INVALID_HANDLE, chain, 1, payload, payloadLen, 0,
		     "attached, hPrivKey = CK_INVALID_HANDLE", "cms-gost-nokey.der", &env, &envLen);
	if (rv == CKR_OK && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);

	rv = signCms(session, leafCert, leafPriv, NULL_PTR, 0, payload, payloadLen, 0,
		     "attached, no chain", "cms-gost-nochain.der", &env, &envLen);
	if (rv == CKR_OK)
	{
		verifyEnvelope(session, env, envLen, &rootDer, NULL, 0, 1, payload, payloadLen, 0,
			       "no chain in envelope, root trusted");
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	}

	rv = signCms(session, leafCert, leafPriv, chain, 1, payload, payloadLen,
		     PKCS7_DETACHED_SIGNATURE, "detached", "cms-gost-detached.der", &env, &envLen);
	if (rv == CKR_OK)
	{
		verifyEnvelope(session, env, envLen, &rootDer, NULL, 0, 1, payload, payloadLen, 1,
			       "detached, trusted root");
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	}

	rv = signCms(session, leafCert, leafPriv, chain, 1, payload, payloadLen,
		     USE_HARDWARE_HASH, "hardware hash", "cms-gost-hwhash.der", &env, &envLen);
	if (rv == CKR_OK)
	{
		verifyEnvelope(session, env, envLen, &rootDer, NULL, 0, 1, payload, payloadLen, 0,
			       "hardware hash, trusted root");
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	}

	rv = signCms(session, leafCert, leafPriv, chain, 1, payload, payloadLen,
		     PKCS7_DETACHED_SIGNATURE | USE_HARDWARE_HASH, "detached + hardware hash",
		     "cms-gost-detached-hwhash.der", &env, &envLen);
	if (rv == CKR_OK && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);

	rv = signCms(session, leafCert, rootPriv, NULL_PTR, 0, payload, payloadLen, 0,
		     "mismatched: leaf certificate, root key", "cms-gost-mismatch.der", &env, &envLen);
	if (rv == CKR_OK)
	{
		verifyEnvelope(session, env, envLen, &rootDer, NULL, 0, 1, payload, payloadLen, 0,
			       "mismatched envelope, root trusted");
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	}

	rv = signCms(session, leafCert, leafPub, NULL_PTR, 0, payload, payloadLen, 0,
		     "public key handle as hPrivKey", NULL, &env, &envLen);
	if (rv == CKR_OK && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	readJournal("after the CMS section");
done:
	bFree(&rootDer); bFree(&leafDer); bFree(&otherDer);
}

/* ---- 4. RSA CMS -------------------------------------------------------- */

static void probeRsaCms(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE pub, priv, certObj = CK_INVALID_HANDLE;
	static const unsigned char payload[] = "CryptoMost RSA CMS payload";
	CK_BYTE_PTR env = NULL_PTR;
	CK_ULONG envLen = 0;
	Buf der;
	CK_RV rv;
	section("RSA C_EX_PKCS7Sign");
	bInit(&der);
	rv = genRsa(session, "rsa-cms", &pub, &priv);
	if (rv != CKR_OK) { showRv("generate RSA key", rv); return; }
	if (!rsaCertificate(session, pub, priv, "CryptoMost RSA", &der)) { bFree(&der); return; }
	dumpToFile("rsa-cert.der", der.p, der.n);
	showRv("import RSA certificate", importCert(session, "rsa-cms", "CryptoMost RSA", &der, &certObj));
	if (certObj != CK_INVALID_HANDLE)
	{
		rv = signCms(session, certObj, priv, NULL_PTR, 0, payload, sizeof(payload) - 1, 0,
			     "RSA attached", "cms-rsa-attached.der", &env, &envLen);
		if (rv == CKR_OK)
		{
			verifyEnvelope(session, env, envLen, &der, NULL, 0, 1, payload, sizeof(payload) - 1, 0,
				       "RSA attached, self-signed trusted");
			if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
		}
	}
	bFree(&der);
}

/* ---- 5. journal -------------------------------------------------------- */

static void probeJournal(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE g1Pub, g1Priv, g5Pub, g5Priv, rPub, rPriv;
	CK_BYTE hash[64], sig[512];
	CK_ULONG hashLen, sigLen;
	CK_RV rv;
	section("C_EX_GetJournal: GOST-256 twice, GOST-512, RSA");
	readJournal("before");
	if (readJournal("re-read, nothing in between")) line("    (journal changed without an operation)");
	if (journalLen) hexAll("journal now", journalBuf, journalLen);

	if (genGost(session, "jrn-256", 1, &g1Pub, &g1Priv) == CKR_OK)
	{
		int run;
		for (run = 1; run <= 2; run++)
		{
			CK_MECHANISM dm = { CKM_GOSTR3411_12_256, NULL_PTR, 0 };
			CK_MECHANISM sm = { CKM_GOSTR3410, NULL_PTR, 0 };
			hashLen = 32;
			sigLen = sizeof(sig);
			rv = p11->C_DigestInit(session, &dm);
			if (rv == CKR_OK) rv = p11->C_Digest(session, (CK_BYTE_PTR) "journal", 7, hash, &hashLen);
			if (rv == CKR_OK) rv = p11->C_SignInit(session, &sm, g1Priv);
			if (rv == CKR_OK) rv = p11->C_Sign(session, hash, hashLen, sig, &sigLen);
			showRv(run == 1 ? "GOST-256 CKM_GOSTR3410 sign #1" : "GOST-256 CKM_GOSTR3410 sign #2", rv);
			readJournal(run == 1 ? "after GOST-256 sign #1" : "after GOST-256 sign #2");
			if (journalLen) hexAll("journal", journalBuf, journalLen);
		}
		{
			CK_MECHANISM sm = { CKM_GOSTR3410_WITH_GOSTR3411_12_256, NULL_PTR, 0 };
			sigLen = sizeof(sig);
			rv = p11->C_SignInit(session, &sm, g1Priv);
			if (rv == CKR_OK) rv = p11->C_Sign(session, (CK_BYTE_PTR) "journal data", 12, sig, &sigLen);
			showRv("GOST-256 sign with on-token hashing", rv);
			readJournal("after sign with on-token hash");
			if (journalLen) hexAll("journal", journalBuf, journalLen);
		}
	}
	if (genGostCurve(session, "jrn-512", 512, CURVE_512_A, sizeof(CURVE_512_A), 1, 0, &g5Pub, &g5Priv) == CKR_OK)
	{
		CK_MECHANISM dm = { CKM_GOSTR3411_12_512, NULL_PTR, 0 };
		CK_MECHANISM sm = { CKM_GOSTR3410_512, NULL_PTR, 0 };
		hashLen = 64;
		sigLen = sizeof(sig);
		rv = p11->C_DigestInit(session, &dm);
		if (rv == CKR_OK) rv = p11->C_Digest(session, (CK_BYTE_PTR) "journal", 7, hash, &hashLen);
		if (rv == CKR_OK) rv = p11->C_SignInit(session, &sm, g5Priv);
		if (rv == CKR_OK) rv = p11->C_Sign(session, hash, hashLen, sig, &sigLen);
		showRv("GOST-512 sign", rv);
		readJournal("after GOST-512 sign");
		if (journalLen) hexAll("journal", journalBuf, journalLen);
	}
	if (genRsa(session, "jrn-rsa", &rPub, &rPriv) == CKR_OK)
	{
		CK_MECHANISM sm = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
		sigLen = sizeof(sig);
		rv = p11->C_SignInit(session, &sm, rPriv);
		if (rv == CKR_OK) rv = p11->C_Sign(session, (CK_BYTE_PTR) "journal", 7, sig, &sigLen);
		showRv("RSA sign", rv);
		readJournal("after RSA sign (expect same)");
	}
}

/* ---- 6. attribute divergences and the trusted store -------------------- */

static void probeDivergences(CK_SESSION_HANDLE* sessionPtr)
{
	CK_SESSION_HANDLE session = *sessionPtr;
	CK_OBJECT_HANDLE pub, priv, caPub, caPriv, lPub, lPriv;
	CK_OBJECT_HANDLE caCert = CK_INVALID_HANDLE, leafCert = CK_INVALID_HANDLE;
	Buf caDer, leafDer;
	static const unsigned char payload[] = "CryptoMost trusted-store payload";
	CK_BYTE_PTR env = NULL_PTR;
	CK_ULONG envLen = 0;
	CK_RV rv;
	section("Attribute divergences; CKA_TRUSTED and the token's trusted store");
	bInit(&caDer); bInit(&leafDer);

	rv = genGostCurve(session, "div-key", 256, CURVE_CP_A, sizeof(CURVE_CP_A), 1, 0, &pub, &priv);
	if (rv == CKR_OK)
	{
		CK_BBOOL yes = CK_TRUE, value = CK_FALSE;
		CK_ATTRIBUTE set = { CKA_EXTRACTABLE, &yes, sizeof(yes) };
		CK_ATTRIBUTE q = { CKA_VALUE, NULL_PTR, 0 };
		rv = p11->C_SetAttributeValue(session, priv, &set, 1);
		showRv("CKA_EXTRACTABLE false->true (owner: hw 0x0, fork 0x10)", rv);
		readAttr(session, priv, CKA_EXTRACTABLE, &value, sizeof(value));
		line("      CKA_EXTRACTABLE now reads %s", value ? "TRUE" : "FALSE");
		rv = p11->C_GetAttributeValue(session, priv, &q, 1);
		showRv("read private CKA_VALUE (owner: hw 0x12, fork 0x11)", rv);
	}
	else showRv("generate divergence key", rv);

	if (genGost(session, "trust-ca", 1, &caPub, &caPriv) != CKR_OK ||
	    genGost(session, "trust-leaf", 1, &lPub, &lPriv) != CKR_OK ||
	    !gostCertificate(session, caPub, caPriv, "Trust CA", "Trust CA", 11, 1, &caDer) ||
	    !gostCertificate(session, lPub, caPriv, "Trust CA", "Trust Signer", 12, 0, &leafDer))
	{ line("    could not prepare the trusted-store certificates"); goto done; }
	showRv("import trust CA certificate", importCert(session, "trust-ca", "Trust CA", &caDer, &caCert));
	showRv("import trust leaf certificate", importCert(session, "trust-leaf", "Trust Signer", &leafDer, &leafCert));
	if (caCert == CK_INVALID_HANDLE || leafCert == CK_INVALID_HANDLE) goto done;

	/* the envelope to verify against the trusted store */
	rv = signCms(session, leafCert, lPriv, NULL_PTR, 0, payload, sizeof(payload) - 1, 0,
		     "sign for the trusted-store checks", "cms-trust.der", &env, &envLen);
	if (rv == CKR_OK)
		verifyEnvelope(session, env, envLen, NULL, NULL, CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN, 0,
			       payload, sizeof(payload) - 1, 0, "USE_TRUSTED_CERTS_FROM_TOKEN, CA not yet trusted");

	if (!opt.write) { line("    CKA_TRUSTED part skipped (needs --write)"); goto done; }

	/* SO marks the CA trusted. */
	{
		CK_SESSION_HANDLE so = openSo();
		if (so != CK_INVALID_HANDLE)
		{
			CK_OBJECT_HANDLE c = findOne(so, CKO_CERTIFICATE, "trust-ca");
			CK_BBOOL yes = CK_TRUE, value = CK_FALSE;
			CK_ATTRIBUTE set = { CKA_TRUSTED, &yes, sizeof(yes) };
			rv = c == CK_INVALID_HANDLE ? CKR_OBJECT_HANDLE_INVALID
						    : p11->C_SetAttributeValue(so, c, &set, 1);
			showRv("SO: CKA_TRUSTED false->true on the CA", rv);
			if (c != CK_INVALID_HANDLE) readAttr(so, c, CKA_TRUSTED, &value, sizeof(value));
			line("      CKA_TRUSTED reads %s in the same SO session", value ? "TRUE" : "FALSE");
			p11->C_Logout(so);
			p11->C_CloseSession(so);
		}
	}
	session = openUser();
	*sessionPtr = session;
	if (session == CK_INVALID_HANDLE) goto done;
	if (env)
		verifyEnvelope(session, env, envLen, NULL, NULL, CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN, 0,
			       payload, sizeof(payload) - 1, 0, "USE_TRUSTED_CERTS_FROM_TOKEN, CA trusted");

	/* Reopen the library and look again. */
	p11->C_CloseAllSessions(theSlot);
	p11->C_Finalize(NULL_PTR);
	rv = p11->C_Initialize(NULL_PTR);
	showRv("C_Finalize + C_Initialize (reopen)", rv);
	session = openUser();
	*sessionPtr = session;
	if (session == CK_INVALID_HANDLE) goto done;
	{
		CK_OBJECT_HANDLE c = findOne(session, CKO_CERTIFICATE, "trust-ca");
		CK_BBOOL value = CK_FALSE, yes = CK_TRUE;
		CK_ATTRIBUTE set = { CKA_TRUSTED, &yes, sizeof(yes) };
		if (c == CK_INVALID_HANDLE) { line("    trust CA certificate not found after reopen"); goto done; }
		readAttr(session, c, CKA_TRUSTED, &value, sizeof(value));
		line("    after reopen CKA_TRUSTED reads %s (owner: hw FALSE)", value ? "TRUE" : "FALSE");
		showRv("USER: set CKA_TRUSTED again (owner: hw 0x10)", p11->C_SetAttributeValue(session, c, &set, 1));
	}
	if (env)
		verifyEnvelope(session, env, envLen, NULL, NULL, CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN, 0,
			       payload, sizeof(payload) - 1, 0, "USE_TRUSTED_CERTS_FROM_TOKEN after reopen");
	{
		CK_SESSION_HANDLE so = openSo();
		if (so != CK_INVALID_HANDLE)
		{
			CK_OBJECT_HANDLE c = findOne(so, CKO_CERTIFICATE, "trust-ca");
			CK_BBOOL yes = CK_TRUE;
			CK_ATTRIBUTE set = { CKA_TRUSTED, &yes, sizeof(yes) };
			showRv("SO: set CKA_TRUSTED again after reopen",
			       c == CK_INVALID_HANDLE ? CKR_OBJECT_HANDLE_INVALID
						      : p11->C_SetAttributeValue(so, c, &set, 1));
			p11->C_Logout(so);
			p11->C_CloseSession(so);
		}
	}
	session = openUser();
	*sessionPtr = session;
done:
	if (env && ex && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(env);
	bFree(&caDer); bFree(&leafDer);
}

/* ---- 7. unblock and token-manage (user PIN) --------------------------- */

static CK_RV userLogin(const char* pin)
{
	CK_SESSION_HANDLE s;
	CK_RV rv;
	p11->C_CloseAllSessions(theSlot);
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &s);
	if (rv != CKR_OK) return rv;
	rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) pin, strlen(pin));
	if (rv == CKR_OK) p11->C_Logout(s);
	p11->C_CloseSession(s);
	return rv;
}

static CK_RV userSetPin(const char* oldPin, const char* newPin)
{
	CK_SESSION_HANDLE s;
	CK_RV rv;
	p11->C_CloseAllSessions(theSlot);
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &s);
	if (rv != CKR_OK) return rv;
	rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) oldPin, strlen(oldPin));
	if (rv == CKR_OK || rv == CKR_PIN_EXPIRED)
	{
		rv = p11->C_SetPIN(s, (CK_UTF8CHAR_PTR) oldPin, strlen(oldPin),
				   (CK_UTF8CHAR_PTR) newPin, strlen(newPin));
		p11->C_Logout(s);
	}
	p11->C_CloseSession(s);
	return rv;
}

static CK_RV tokenManage(CK_ULONG mode, CK_USER_TYPE user)
{
	CK_SESSION_HANDLE so = openSo();
	CK_USER_TYPE value = user;
	CK_RV rv;
	if (so == CK_INVALID_HANDLE) return CKR_GENERAL_ERROR;
	rv = ex && ex->C_EX_TokenManage ? ex->C_EX_TokenManage(so, mode, &value)
					: CKR_FUNCTION_NOT_SUPPORTED;
	p11->C_Logout(so);
	p11->C_CloseSession(so);
	return rv;
}

static const char* userPinNow = NULL;

static void probeTokenManage(void)
{
	static const char tempPin[] = "13572468";
	CK_RV rv;
	section("C_EX_UnblockUserPIN and C_EX_TokenManage (user PIN)");
	userPinNow = opt.userPin;
	if (!opt.write) { line("    skipped (needs --write)"); return; }

	line("  unblock under SO after one wrong user attempt:");
	showRv("user login with a wrong PIN", userLogin("00000000"));
	extendedState("after one wrong attempt");
	{
		CK_SESSION_HANDLE so = openSo();
		if (so != CK_INVALID_HANDLE)
		{
			rv = ex && ex->C_EX_UnblockUserPIN ? ex->C_EX_UnblockUserPIN(so)
							   : CKR_FUNCTION_NOT_SUPPORTED;
			showRv("C_EX_UnblockUserPIN (SO)", rv);
			p11->C_Logout(so);
			p11->C_CloseSession(so);
		}
	}
	extendedState("after unblock");

	line("  force-user-pin-change (MODE_FORCE_USER_TO_CHANGE_PIN, CKU_USER):");
	showRv("C_EX_TokenManage force user to change PIN", tokenManage(MODE_FORCE_USER_TO_CHANGE_PIN, CKU_USER));
	showRv("MODE_GET_PIN_SET_TO_BE_CHANGED user (expect CKR_PIN_EXPIRED)", pinToBeChanged(CKU_USER));
	extendedState("after force");
	showRv("user login with the current PIN", userLogin(userPinNow));
	rv = userSetPin(userPinNow, tempPin);
	showRv("user C_SetPIN current -> temporary", rv);
	if (rv == CKR_OK) userPinNow = tempPin;
	showRv("MODE_GET_PIN_SET_TO_BE_CHANGED user after the change", pinToBeChanged(CKU_USER));
	extendedState("after the user changed the PIN");
	if (userPinNow == tempPin)
	{
		rv = userSetPin(tempPin, opt.userPin);
		showRv("user C_SetPIN temporary -> original (history?)", rv);
		if (rv == CKR_OK) userPinNow = opt.userPin;
	}

	line("  standard-default-user-pin (MODE_RESET_CUSTOM_PIN_TO_STANDARD, CKU_USER):");
	showRv("C_EX_TokenManage reset custom default PIN to standard",
	       tokenManage(MODE_RESET_CUSTOM_PIN_TO_STANDARD, CKU_USER));
	extendedState("after standard-default");
	showRv("user login with the PIN now in force", userLogin(userPinNow));
	if (userPinNow != opt.userPin)
		line("    WARNING: the user PIN is now '%s', not the one given; --format restores it", userPinNow);
}

/* ---- 8. local PIN ------------------------------------------------------ */

static void localPinInfo(CK_ULONG id, int quiet)
{
	CK_LOCAL_PIN_INFO info;
	CK_RV rv;
	memset(&info, 0, sizeof(info));
	info.ulPinID = id;
	rv = ex && ex->C_EX_SlotManage ? ex->C_EX_SlotManage(theSlot, MODE_GET_LOCAL_PIN_INFO, &info)
				       : CKR_FUNCTION_NOT_SUPPORTED;
	if (rv == CKR_OK || !quiet)
		line("    local PIN %2lu: rv=%s min=%lu max=%lu maxRetry=%lu left=%lu flags=0x%lx",
		     (unsigned long) id, rvName(rv), (unsigned long) info.ulMinSize,
		     (unsigned long) info.ulMaxSize, (unsigned long) info.ulMaxRetryCount,
		     (unsigned long) info.ulCurrentRetryCount, (unsigned long) info.flags);
}

static void probeLocalPin(void)
{
	CK_ULONG id;
	int notReported = 0;
	CK_RV rv;
	section("C_EX_SetLocalPIN (ID 3) and local-PIN status");
	if (!opt.write) { line("    skipped (needs --write)"); return; }
	if (ex == NULL || ex->C_EX_SetLocalPIN == NULL)
	{ line("    C_EX_SetLocalPIN is not in the table"); return; }
	p11->C_CloseAllSessions(theSlot);

	rv = ex->C_EX_SetLocalPIN(theSlot, (CK_UTF8CHAR_PTR) userPinNow, strlen(userPinNow),
				  (CK_UTF8CHAR_PTR) "135790", 6, 3);
	showRv("create local PIN 3 = 135790, authorised by the user PIN", rv);
	localPinInfo(3, 0);
	rv = ex->C_EX_SetLocalPIN(theSlot, (CK_UTF8CHAR_PTR) "135790", 6,
				  (CK_UTF8CHAR_PTR) "246802", 6, 3);
	showRv("change local PIN 3 -> 246802, authorised by its value", rv);
	localPinInfo(3, 0);
	rv = ex->C_EX_SetLocalPIN(theSlot, (CK_UTF8CHAR_PTR) userPinNow, strlen(userPinNow),
				  (CK_UTF8CHAR_PTR) "112233", 6, 3);
	showRv("change existing local PIN 3 with the user PIN (hint: refused)", rv);
	localPinInfo(3, 0);
	rv = ex->C_EX_SetLocalPIN(theSlot, (CK_UTF8CHAR_PTR) "000000", 6,
				  (CK_UTF8CHAR_PTR) "112233", 6, 3);
	showRv("change local PIN 3 with a wrong current value", rv);
	localPinInfo(3, 0);
	rv = ex->C_EX_SetLocalPIN(theSlot, (CK_UTF8CHAR_PTR) "246802", 6,
				  (CK_UTF8CHAR_PTR) "135790", 6, 3);
	showRv("change local PIN 3 back -> 135790 by its value", rv);
	localPinInfo(3, 0);
	for (id = 3; id <= 31; id++)
	{
		CK_LOCAL_PIN_INFO info;
		memset(&info, 0, sizeof(info));
		info.ulPinID = id;
		if (ex->C_EX_SlotManage == NULL ||
		    ex->C_EX_SlotManage(theSlot, MODE_GET_LOCAL_PIN_INFO, &info) != CKR_OK)
			notReported++;
	}
	line("    IDs 3..31: %d not reported (owner: only the set one is readable)", notReported);
	{
		CK_SESSION_HANDLE s;
		if (p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				       NULL_PTR, NULL_PTR, &s) == CKR_OK)
		{
			showRv("C_Login(userType=3, local PIN)",
			       p11->C_Login(s, 3, (CK_UTF8CHAR_PTR) "135790", 6));
			p11->C_CloseSession(s);
		}
	}
}

/* ---- 9. format / restore factory defaults ------------------------------ */

static int hexKey(const char* hex, CK_BYTE* out, CK_ULONG outMax, CK_ULONG* outLen)
{
	CK_ULONG n = 0;
	while (hex && *hex)
	{
		unsigned int v;
		if (hex[0] == ' ' || hex[0] == ':') { hex++; continue; }
		if (!hex[1] || sscanf(hex, "%2x", &v) != 1 || n >= outMax) return 0;
		out[n++] = (CK_BYTE) v;
		hex += 2;
	}
	*outLen = n;
	return 1;
}

static void fillInit(CK_RUTOKEN_INIT_PARAM* init, CK_ULONG repair, CK_FLAGS policy)
{
	static CK_BYTE noLabel[1];
	memset(init, 0, sizeof(*init));
	init->ulSizeofThisStructure = sizeof(*init);
	init->UseRepairMode = repair;
	init->pNewAdminPin = (CK_BYTE_PTR) opt.finalSoPin;
	init->ulNewAdminPinLen = strlen(opt.finalSoPin);
	init->pNewUserPin = (CK_BYTE_PTR) opt.finalUserPin;
	init->ulNewUserPinLen = strlen(opt.finalUserPin);
	init->ChangeUserPINPolicy = policy;
	init->ulMinAdminPinLen = 6;
	init->ulMinUserPinLen = 6;
	init->ulMaxAdminRetryCount = 10;
	init->ulMaxUserRetryCount = 10;
	init->pTokenLabel = noLabel;
	init->ulLabelLen = 0;
	init->ulSmMode = 0;
}

static void postFormatState(void)
{
	CK_SESSION_HANDLE s;
	extendedState("after format");
	line("    PIN to be changed: user %s, SO %s",
	     rvName(pinToBeChanged(CKU_USER)), rvName(pinToBeChanged(CKU_SO)));
	readJournal("after format");
	if (journalLen) hexAll("journal", journalBuf, journalLen);
	localPinInfo(3, 0);
	if (p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &s) == CKR_OK)
	{
		CK_OBJECT_CLASS hw = CKO_HW_FEATURE;
		CK_ATTRIBUTE none[1];
		CK_ATTRIBUTE hwOnly = { CKA_CLASS, &hw, sizeof(hw) };
		int all = countObjects(s, none, 0), features = countObjects(s, &hwOnly, 1);
		CK_RV rv;
		line("    public objects visible: %d (of them hardware features: %d)", all, features);
		rv = p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) opt.finalUserPin, strlen(opt.finalUserPin));
		showRv("user login with the final PIN", rv);
		if (rv == CKR_OK)
		{
			line("    objects visible as user: %d", countObjects(s, none, 0));
			p11->C_Logout(s);
		}
		p11->C_CloseSession(s);
	}
	p11->C_CloseAllSessions(theSlot);
	{
		CK_SESSION_HANDLE so;
		if (p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &so) == CKR_OK)
		{
			CK_RV rv = p11->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR) opt.finalSoPin, strlen(opt.finalSoPin));
			showRv("SO login with the final SO PIN", rv);
			if (rv == CKR_OK) p11->C_Logout(so);
			p11->C_CloseSession(so);
		}
	}
}

static void probeFormat(void)
{
	CK_RUTOKEN_INIT_PARAM init;
	CK_SESSION_HANDLE held;
	CK_RV rv;
	section("C_EX_InitToken checks and the final format");
	if (!opt.format) { line("    skipped (needs --format)"); return; }
	if (ex == NULL || ex->C_EX_InitToken == NULL) { line("    C_EX_InitToken is not in the table"); return; }
	p11->C_CloseAllSessions(theSlot);

	fillInit(&init, 0, 0);
	showRv("C_EX_InitToken with ChangeUserPINPolicy=0 (03.10 rejected)",
	       ex->C_EX_InitToken(theSlot, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin), &init));
	if (p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &held) == CKR_OK)
	{
		fillInit(&init, 0, TOKEN_FLAGS_USER_CHANGE_USER_PIN);
		showRv("C_EX_InitToken with a session open",
		       ex->C_EX_InitToken(theSlot, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin), &init));
		p11->C_CloseSession(held);
	}

	if (opt.restoreFactory)
	{
		PROBE_RESTORE_FACTORY_DEFAULTS_PARAMS params;
		CK_BYTE key[64];
		CK_ULONG keyLen = 0;
		if (opt.emitentKeyHex == NULL || !hexKey(opt.emitentKeyHex, key, sizeof(key), &keyLen) ||
		    keyLen != 32)
		{
			line("    restore-factory: the emitent key must be 32 bytes of hex in the "
			     "environment variable named by --emitent-key-env; not attempted");
		}
		else
		{
			fillInit(&init, 0, TOKEN_FLAGS_USER_CHANGE_USER_PIN);
			memset(&params, 0, sizeof(params));
			params.ulSizeofThisStructure = sizeof(params);
			params.pAdminPin = (CK_BYTE_PTR) opt.soPin;
			params.ulAdminPinLen = strlen(opt.soPin);
			params.pInitParam = &init;
			params.pNewEmitentKey = key;
			params.ulNewEmitentKeyLen = keyLen;
			params.ulNewEmitentKeyRetryCount = 10;
			params.newEmitentKeyType = opt.emitentMagma ? CKK_MAGMA : CKK_KUZNECHIK;
			rv = ex->C_EX_SlotManage ? ex->C_EX_SlotManage(theSlot, MODE_RESTORE_FACTORY_DEFAULTS, &params)
						 : CKR_FUNCTION_NOT_SUPPORTED;
			showRv(opt.emitentMagma ? "C_EX_SlotManage restore-factory (Magma key)"
						: "C_EX_SlotManage restore-factory (Kuznyechik key)", rv);
			memset(key, 0, sizeof(key));
			if (rv == CKR_OK) { postFormatState(); return; }
			line("    restore-factory failed; falling back to C_EX_InitToken");
		}
	}

	fillInit(&init, 0, TOKEN_FLAGS_USER_CHANGE_USER_PIN);
	rv = ex->C_EX_InitToken(theSlot, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin), &init);
	showRv("C_EX_InitToken: rtadmin-equivalent format (policy user, 6/6, 10/10)", rv);
	if (rv == CKR_OK) postFormatState();
	else line("    format failed: format the token with rtAdmin to return it to factory state");
}

/* ---- loader and main --------------------------------------------------- */

static int loadLibrary(void)
{
	CK_C_GetFunctionList getList;
	CK_C_EX_GetFunctionListExtended getListExtended;
	CK_RV rv;
	libraryHandle = dlopen(opt.module, RTLD_NOW);
	if (libraryHandle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 0; }
	getList = (CK_C_GetFunctionList) dlsym(libraryHandle, "C_GetFunctionList");
	if (getList == NULL || getList(&p11) != CKR_OK || p11 == NULL_PTR)
	{ fprintf(stderr, "C_GetFunctionList missing or failed\n"); return 0; }
	getListExtended = (CK_C_EX_GetFunctionListExtended)
		dlsym(libraryHandle, "C_EX_GetFunctionListExtended");
	if (getListExtended != NULL)
	{
		rv = getListExtended(&ex);
		if (rv != CKR_OK || ex == NULL_PTR)
		{ fprintf(stderr, "C_EX_GetFunctionListExtended returned 0x%lx\n", (unsigned long) rv); ex = NULL_PTR; }
	}
	else fprintf(stderr, "warning: C_EX_GetFunctionListExtended is not exported\n");
	return 1;
}

static const char* argValue(int argc, char** argv, int* i)
{
	if (*i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", argv[*i]); exit(2); }
	return argv[++(*i)];
}

int main(int argc, char** argv)
{
	CK_SLOT_ID slots[MAX_SLOTS];
	CK_ULONG slotCount = MAX_SLOTS;
	CK_SESSION_HANDLE session;
	CK_RV rv;
	int i;

	opt.userPin = "12345678";
	opt.soPin = "87654321";

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] != '-' && opt.module == NULL) opt.module = argv[i];
		else if (strcmp(argv[i], "--user-pin") == 0) opt.userPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--so-pin") == 0) opt.soPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--user-pin-env") == 0) opt.userPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--so-pin-env") == 0) opt.soPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--final-user-pin") == 0) opt.finalUserPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--final-so-pin") == 0) opt.finalSoPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--emitent-key-env") == 0) opt.emitentKeyHex = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--emitent-magma") == 0) opt.emitentMagma = 1;
		else if (strcmp(argv[i], "--dump-dir") == 0) opt.dumpDir = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--write") == 0) opt.write = 1;
		else if (strcmp(argv[i], "--format") == 0) { opt.write = 1; opt.format = 1; }
		else if (strcmp(argv[i], "--restore-factory") == 0) opt.restoreFactory = 1;
		else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
	}

	if (opt.module == NULL)
	{
		fprintf(stderr,
			"usage: %s <path to librtpkcs11ecp.so> [options]\n"
			"  --user-pin PIN / --so-pin PIN         current PINs (default 12345678 / 87654321)\n"
			"  --user-pin-env NAME / --so-pin-env NAME take a PIN from the environment\n"
			"  --dump-dir DIR                        write every DER the token produces into DIR\n"
			"  --write                               local PIN, token-manage, CKA_TRUSTED changes\n"
			"  --format                              finish with C_EX_InitToken to factory state\n"
			"  --final-user-pin PIN / --final-so-pin PIN  PINs after the format (default: current)\n"
			"  --restore-factory                     format via restore-factory-defaults instead\n"
			"  --emitent-key-env NAME                hex 32-byte emitent key for --restore-factory\n"
			"  --emitent-magma                       the emitent key is Magma, not Kuznyechik\n",
			argv[0]);
		return 2;
	}
	if (opt.userPin == NULL || opt.soPin == NULL)
	{ fprintf(stderr, "a PIN resolved to NULL (bad --*-pin-env?)\n"); return 2; }
	if (opt.finalUserPin == NULL) opt.finalUserPin = opt.userPin;
	if (opt.finalSoPin == NULL) opt.finalSoPin = opt.soPin;
	if (opt.dumpDir) mkdir(opt.dumpDir, 0700);

	if (!loadLibrary()) return 1;

	line("Rutoken extension probe v2");
	line("  module  %s", opt.module);
	line("  mode    read + crypto%s%s%s", opt.write ? " + write" : "",
	     opt.format ? " + format" : "", opt.restoreFactory ? " (restore-factory)" : "");

	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize 0x%lx\n", (unsigned long) rv); return 1; }
	rv = p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK || slotCount == 0)
	{ fprintf(stderr, "no token (0x%lx)\n", (unsigned long) rv); p11->C_Finalize(NULL_PTR); return 1; }
	theSlot = slots[0];
	line("  token on slot %lu", (unsigned long) theSlot);

	probeIdentity();

	session = openUser();
	if (session == CK_INVALID_HANDLE) { p11->C_Finalize(NULL_PTR); return 1; }
	deleteProbeObjects(session);
	probeCsr(session);
	probeGostCms(session);
	probeRsaCms(session);
	probeJournal(session);
	probeDivergences(&session);

	p11->C_CloseAllSessions(theSlot);
	session = openUser();
	if (session != CK_INVALID_HANDLE)
	{
		deleteProbeObjects(session);
		p11->C_Logout(session);
		p11->C_CloseSession(session);
	}

	probeTokenManage();
	probeLocalPin();
	probeFormat();

	line("\nDone.");
	if (!opt.format)
		line("No format was requested: objects the probe created were deleted; local PIN 3 "
		     "and any PIN changes from the token-manage section remain. Format with rtAdmin "
		     "or run again with --format to return the token to factory state.");
	p11->C_Finalize(NULL_PTR);
	if (libraryHandle) dlclose(libraryHandle);
	return 0;
}
