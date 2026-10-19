/*
 * One-run probe of CKM_GOSTR3410_12_DERIVE (0xD4321007) on a real Rutoken.
 * The original measurements informed release .84; this version also measures
 * the VKO variants that the first run left unknown. It prints one text log;
 * answers for unknown variants are not assumed before a hardware run.
 *
 * What it reads:
 *   1. identity and the mechanism information of the GOST derive mechanisms;
 *   2. the plugin's exact call - flat 84-byte parameter, CKD_NULL, 8-byte UKM,
 *      template CKO_SECRET_KEY / CKK_GOST28147 / CKA_TOKEN = FALSE - and every
 *      attribute of the key it makes. The peer point is the public half of the
 *      TC26 256-bit sample key already used by the fork's tests, so the value
 *      can be recomputed offline from the published private half; the token's
 *      own public point is printed for that;
 *   3. agreement from both sides on CryptoPro-A/B/C and TC26-A, and whether
 *      the token accepts the sample private key for import;
 *   4. other KDF values, UKM lengths and a zero UKM;
 *   5. unmeasured UKM lengths, diversification, S-box and result attributes;
 *   6. the parameter as a CK_GOSTR3410_DERIVE_PARAMS structure instead of the
 *      flat buffer, and malformed buffers;
 *   7. other result key types, CKA_VALUE_LEN, token, sensitive and
 *      non-extractable results, explicit CKA_GOST28147_PARAMS;
 *   8. 512-bit keys (TC26 paramSetC, the curve of the 512-bit TC26 sample);
 *   9. a base key without CKA_DERIVE, a public key as the base key, and the
 *      same parameter under CKM_GOSTR3410_DERIVE (0x1204);
 *  10. test the SDK's VKO KDF selector and compare HMAC/KDF key types;
 *  11. clean-up.
 *
 * It needs only the user PIN. It does not format the token, uses no SO PIN,
 * makes no wrong PIN attempt, and destroys every object it created (they all
 * carry the label below) - also the ones left by an earlier interrupted run.
 *
 * Building it:
 *
 *   cc -std=c11 -O2 -Wall -Wextra -I src/lib/pkcs11 \
 *      tests/portable/rutoken-derive-probe.c -ldl -o rutoken-derive-probe
 *
 * Running it: see README-derive-probe.txt.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cryptoki.h"

#define MAX_SLOTS 64
#define MAX_OBJECTS 1024

#define MECH_GOSTR3410_12_DERIVE 0xD4321007UL
#define MECH_GOSTR3410_DERIVE    0x00001204UL
#define MECH_GOST_KEG            0xD4321039UL
#define MECH_KDF_GOST_256        0xD4321026UL
#define MECH_KDF_HMAC_256        0xD4321028UL
#define MECH_KDF_TREE_256        0xD432102AUL
#define MECH_VKO_512             0xD4321038UL
#define MECH_VENDOR_CBC_FSS      0x8000000BUL
#define MECH_VENDOR_SECURE_IMPORT 0x80000003UL

static const char PROBE_LABEL[] = "CryptoMost derive probe";

static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
static void* libraryHandle = NULL;
static CK_SLOT_ID theSlot = 0;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

static struct {
	const char* module;
	const char* userPin;
	int slotGiven;
	CK_SLOT_ID slot;
} opt;

/* Curves and digest parameters, DER-encoded OIDs. */
static const CK_BYTE CURVE_CP_A[]    = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x01 };
static const CK_BYTE CURVE_CP_B[]    = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x02 };
static const CK_BYTE CURVE_CP_C[]    = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x03 };
static const CK_BYTE CURVE_TC26_A[]  = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x01 };
static const CK_BYTE CURVE_512_C[]   = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x03 };
static const CK_BYTE DIGEST_256[]    = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x02 };
static const CK_BYTE DIGEST_512[]    = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x03 };
/* id-Gost28147-89-CryptoPro-A-ParamSet, 1.2.643.2.2.31.1 */
static const CK_BYTE GOST28147_CP_A[] = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1f,0x01 };
static const CK_BYTE GOST28147_CP_B[] = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1f,0x02 };
static const CK_BYTE GOST28147_TC26_Z[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x05,0x01,0x01 };

/* Public halves of the TC26 sample keys the fork's tests use (verifyGOSTKEG,
 * verifyGOSTKEG512), as little-endian X || Y. The private halves are public
 * too, so whatever the token derives against these points can be recomputed
 * offline. Each point was computed from its private key by gost-engine. */
static const CK_BYTE SAMPLE_256_POINT[64] = {
	0xa5, 0x3d, 0x0c, 0x90, 0x4d, 0x0c, 0x13, 0x83, 0x5c, 0x5e, 0xbd, 0x3e, 0x35, 0x41, 0x4e, 0x51,
	0x82, 0xf3, 0xa9, 0x32, 0x0f, 0x91, 0xcc, 0xec, 0x17, 0x7b, 0x28, 0x4e, 0xb4, 0x07, 0xaf, 0x2c,
	0x6b, 0x81, 0x9e, 0xc4, 0x62, 0xeb, 0xf9, 0x33, 0xda, 0xbb, 0xa2, 0x4f, 0xb3, 0xc7, 0x41, 0xeb,
	0xe4, 0x98, 0xfa, 0xf2, 0xb8, 0xf4, 0xea, 0xa2, 0x1b, 0x09, 0x1d, 0x6a, 0xb5, 0x2c, 0xd3, 0xc4
};
static const CK_BYTE SAMPLE_512_POINT[128] = {
	0x3a, 0x83, 0xeb, 0x1d, 0xf1, 0xb8, 0x39, 0xfd, 0xe4, 0xd2, 0x5b, 0xb3, 0x52, 0x27, 0x2d, 0xc2,
	0x10, 0x33, 0x7e, 0x7c, 0x0d, 0x9f, 0x23, 0x4e, 0x9b, 0x3c, 0x70, 0x67, 0xb2, 0x06, 0x97, 0x7a,
	0x24, 0x97, 0x3e, 0x13, 0xc3, 0xf6, 0x9f, 0xcd, 0x47, 0xf4, 0x8b, 0x28, 0x0a, 0xa3, 0xe6, 0x92,
	0x80, 0xf5, 0x3f, 0x9b, 0x66, 0x63, 0x65, 0xc6, 0x72, 0xd9, 0x9a, 0x47, 0xda, 0x89, 0x45, 0xf1,
	0xea, 0xf4, 0x11, 0x7a, 0x58, 0xbe, 0x6a, 0xb1, 0xeb, 0x67, 0xd5, 0xb3, 0xe3, 0xe1, 0x78, 0xbd,
	0xe6, 0x2b, 0x61, 0x1d, 0xa0, 0xa7, 0x01, 0x41, 0xcb, 0x1c, 0x5e, 0x6a, 0xe6, 0xdf, 0xf2, 0x99,
	0xf2, 0x13, 0x04, 0x3b, 0xb5, 0xdd, 0xdf, 0xb1, 0x04, 0x2c, 0x3a, 0x7f, 0x72, 0x95, 0x7c, 0xfc,
	0x0b, 0xb3, 0x0a, 0xb2, 0x9f, 0x05, 0xa1, 0x60, 0x4e, 0x2d, 0x50, 0x36, 0x5b, 0xe9, 0x05, 0xf3
};
/* The TC26 256-bit sample private key in the little-endian CKA_VALUE order
 * the TC26 extension and Rutoken use; only for the import attempt. */
static const CK_BYTE SAMPLE_256_PRIVATE_LE[32] = {
	0x9f, 0x7d, 0x8e, 0x9f, 0xff, 0x18, 0x1a, 0xd8, 0x01, 0xcc, 0xeb, 0xef, 0x0a, 0x5b, 0xa7, 0xc3,
	0xc3, 0x35, 0x3e, 0x0a, 0x7c, 0x16, 0xb4, 0xd1, 0x6a, 0x20, 0x83, 0x5a, 0x87, 0xb7, 0xeb, 0x0d
};
/* gost-engine's VKO_GOSTR3410_2012_256 of that key with its own point and
 * UKM 01 02 03 04 05 06 07 08: what an imported sample key should give. */
static const CK_BYTE SAMPLE_256_SELF_VKO[32] = {
	0xc4, 0x93, 0xf2, 0x68, 0x7c, 0xe1, 0x5c, 0xad, 0x68, 0x02, 0x07, 0x2b, 0xad, 0x8a, 0x9d, 0x55,
	0x0d, 0xe3, 0xd0, 0x65, 0xd5, 0x4f, 0xcc, 0xf9, 0x97, 0xa2, 0xd3, 0xa6, 0x7e, 0x23, 0x9f, 0xae
};

static const CK_BYTE UKM_1[8] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
static const CK_BYTE UKM_1_REVERSED[8] = { 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };

/* ---- output ------------------------------------------------------------ */

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
static void section(const char* title)
{
	printf("\n==== %d. %s ====\n", ++sectionNumber, title);
	fflush(stdout);
}

static const char* rvName(CK_RV rv)
{
	switch (rv)
	{
	case CKR_OK: return "CKR_OK";
	case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
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
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_BUFFER_TOO_SMALL: return "CKR_BUFFER_TOO_SMALL";
	case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
	default: return "CKR_?";
	}
}

static void showRv(const char* what, CK_RV rv)
{
	line("    %-62s rv = %s (0x%lx)", what, rvName(rv), (unsigned long)rv);
}

static void hexLine(const char* what, const CK_BYTE* data, CK_ULONG length)
{
	CK_ULONG i;
	printf("      %s (%lu bytes): ", what, (unsigned long)length);
	for (i = 0; i < length; ++i) printf("%02x", data[i]);
	printf("\n");
	fflush(stdout);
}

/* ---- objects ----------------------------------------------------------- */

static CK_RV genPair(const char* id, int bits, const CK_BYTE* curve, CK_ULONG curveLen,
		     CK_BBOOL derive, CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = bits == 512 ? CKK_GOSTR3410_512 : CKK_GOSTR3410;
	CK_MECHANISM mech = { bits == 512 ? CKM_GOSTR3410_512_KEY_PAIR_GEN
					  : CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE;
	const CK_BYTE* digest = bits == 512 ? DIGEST_512 : DIGEST_256;
	CK_ULONG digestLen = bits == 512 ? sizeof(DIGEST_512) : sizeof(DIGEST_256);
	CK_ATTRIBUTE pubT[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)digest, digestLen }
	};
	CK_ATTRIBUTE privT[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_DERIVE, &derive, sizeof(derive) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)digest, digestLen }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech,
		pubT, sizeof(pubT) / sizeof(pubT[0]),
		privT, sizeof(privT) / sizeof(privT[0]), pub, priv);
}

/* Read an attribute into buf; returns its length, or -1 with rv set. */
static long readAttr(CK_OBJECT_HANDLE object, CK_ATTRIBUTE_TYPE type,
		     CK_BYTE* buf, CK_ULONG size, CK_RV* rvOut)
{
	CK_ATTRIBUTE a = { type, NULL_PTR, 0 };
	CK_RV rv = p11->C_GetAttributeValue(session, object, &a, 1);
	if (rv == CKR_OK && a.ulValueLen != (CK_ULONG)-1 && a.ulValueLen <= size)
	{
		a.pValue = buf;
		rv = p11->C_GetAttributeValue(session, object, &a, 1);
	}
	else if (rv == CKR_OK)
		rv = CKR_BUFFER_TOO_SMALL;
	if (rvOut) *rvOut = rv;
	return rv == CKR_OK ? (long)a.ulValueLen : -1;
}

static long publicPoint(CK_OBJECT_HANDLE pub, CK_BYTE* point, CK_ULONG size)
{
	CK_RV rv;
	long length = readAttr(pub, CKA_VALUE, point, size, &rv);
	if (length < 0) showRv("read the public point", rv);
	return length;
}

static void describeKey(CK_OBJECT_HANDLE key)
{
	static const struct { CK_ATTRIBUTE_TYPE type; const char* name; int boolean; } attrs[] = {
		{ CKA_KEY_TYPE, "CKA_KEY_TYPE", 0 },
		{ CKA_VALUE_LEN, "CKA_VALUE_LEN", 0 },
		{ CKA_TOKEN, "CKA_TOKEN", 1 },
		{ CKA_PRIVATE, "CKA_PRIVATE", 1 },
		{ CKA_SENSITIVE, "CKA_SENSITIVE", 1 },
		{ CKA_EXTRACTABLE, "CKA_EXTRACTABLE", 1 },
		{ CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE", 1 },
		{ CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE", 1 },
		{ CKA_LOCAL, "CKA_LOCAL", 1 },
		{ CKA_MODIFIABLE, "CKA_MODIFIABLE", 1 },
		{ CKA_ENCRYPT, "CKA_ENCRYPT", 1 },
		{ CKA_DECRYPT, "CKA_DECRYPT", 1 },
		{ CKA_WRAP, "CKA_WRAP", 1 },
		{ CKA_UNWRAP, "CKA_UNWRAP", 1 },
		{ CKA_SIGN, "CKA_SIGN", 1 },
		{ CKA_VERIFY, "CKA_VERIFY", 1 },
		{ CKA_DERIVE, "CKA_DERIVE", 1 },
	};
	CK_BYTE buf[256];
	CK_RV rv;
	size_t i;
	for (i = 0; i < sizeof(attrs) / sizeof(attrs[0]); ++i)
	{
		long length = readAttr(key, attrs[i].type, buf, sizeof(buf), &rv);
		if (length < 0)
			line("      %-22s %s", attrs[i].name, rvName(rv));
		else if (attrs[i].boolean && length == 1)
			line("      %-22s %s", attrs[i].name, buf[0] ? "TRUE" : "FALSE");
		else
		{
			CK_ULONG value = 0;
			if (length == (long)sizeof(CK_ULONG)) memcpy(&value, buf, sizeof(value));
			line("      %-22s 0x%lx", attrs[i].name, (unsigned long)value);
		}
	}
	{
		long length = readAttr(key, CKA_GOST28147_PARAMS, buf, sizeof(buf), &rv);
		if (length < 0) line("      %-22s %s", "CKA_GOST28147_PARAMS", rvName(rv));
		else hexLine("CKA_GOST28147_PARAMS", buf, (CK_ULONG)length);
	}
	{
		long length = readAttr(key, CKA_VALUE, buf, sizeof(buf), &rv);
		if (length < 0) line("      %-22s %s", "CKA_VALUE", rvName(rv));
		else hexLine("CKA_VALUE", buf, (CK_ULONG)length);
	}
}

static void destroy(CK_OBJECT_HANDLE object)
{
	if (object != CK_INVALID_HANDLE) p11->C_DestroyObject(session, object);
}

static void deleteProbeObjects(void)
{
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	CK_ATTRIBUTE search = { CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 };
	CK_ULONG found = 0, i;
	if (p11->C_FindObjectsInit(session, &search, 1) != CKR_OK) return;
	p11->C_FindObjects(session, objects, MAX_OBJECTS, &found);
	p11->C_FindObjectsFinal(session);
	for (i = 0; i < found; i++) p11->C_DestroyObject(session, objects[i]);
	line("    removed %lu probe object(s)", (unsigned long)found);
}

/* ---- the derive call ---------------------------------------------------- */

/* The flat parameter of the plugin's trace: little-endian 32-bit KDF,
 * public-key length, the point, UKM length, the UKM. */
static CK_ULONG flatParameter(CK_BYTE* out, CK_ULONG kdf, const CK_BYTE* point, CK_ULONG pointLen,
			      const CK_BYTE* ukm, CK_ULONG ukmLen)
{
	CK_ULONG n = 0, i;
	for (i = 0; i < 4; ++i) out[n++] = (CK_BYTE)(kdf >> (8 * i));
	for (i = 0; i < 4; ++i) out[n++] = (CK_BYTE)(pointLen >> (8 * i));
	memcpy(out + n, point, pointLen); n += pointLen;
	for (i = 0; i < 4; ++i) out[n++] = (CK_BYTE)(ukmLen >> (8 * i));
	if (ukmLen) memcpy(out + n, ukm, ukmLen);
	n += ukmLen;
	return n;
}

typedef struct {
	CK_KEY_TYPE keyType;
	int valueLen;		/* -1: no CKA_VALUE_LEN */
	CK_BBOOL token;
	int sensitive;		/* -1: not given */
	int extractable;	/* -1: not given */
	int gostParams;		/* 1: CryptoPro-A, 2: CryptoPro-B, 3: TC26-Z */
	int deriveAttribute;	/* 0: omitted, -1: FALSE, 1: TRUE */
} Result;

static const Result PLUGIN_RESULT = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 0 };

static CK_RV derive(CK_MECHANISM_TYPE mechanism, CK_OBJECT_HANDLE base, const void* param,
		    CK_ULONG paramLen, const Result* result, CK_OBJECT_HANDLE* key)
{
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = result->keyType;
	CK_ULONG valueLen = result->valueLen < 0 ? 0 : (CK_ULONG)result->valueLen;
	CK_BBOOL token = result->token;
	CK_BBOOL sensitive = result->sensitive > 0 ? CK_TRUE : CK_FALSE;
	CK_BBOOL extractable = result->extractable > 0 ? CK_TRUE : CK_FALSE;
	CK_BBOOL deriveValue = result->deriveAttribute > 0 ? CK_TRUE : CK_FALSE;
	CK_ATTRIBUTE t[9];
	CK_ULONG n = 0;
	CK_MECHANISM mech = { mechanism, (CK_VOID_PTR)param, paramLen };
	t[n].type = CKA_CLASS; t[n].pValue = &secret; t[n++].ulValueLen = sizeof(secret);
	t[n].type = CKA_KEY_TYPE; t[n].pValue = &keyType; t[n++].ulValueLen = sizeof(keyType);
	t[n].type = CKA_TOKEN; t[n].pValue = &token; t[n++].ulValueLen = sizeof(token);
	if (result->valueLen >= 0) { t[n].type = CKA_VALUE_LEN; t[n].pValue = &valueLen; t[n++].ulValueLen = sizeof(valueLen); }
	if (result->sensitive >= 0) { t[n].type = CKA_SENSITIVE; t[n].pValue = &sensitive; t[n++].ulValueLen = sizeof(sensitive); }
	if (result->extractable >= 0) { t[n].type = CKA_EXTRACTABLE; t[n].pValue = &extractable; t[n++].ulValueLen = sizeof(extractable); }
	if (result->gostParams)
	{
		const CK_BYTE* params = result->gostParams == 2 ? GOST28147_CP_B :
			result->gostParams == 3 ? GOST28147_TC26_Z : GOST28147_CP_A;
		CK_ULONG len = result->gostParams == 3 ? sizeof(GOST28147_TC26_Z) : sizeof(GOST28147_CP_A);
		t[n].type = CKA_GOST28147_PARAMS; t[n].pValue = (CK_VOID_PTR)params; t[n++].ulValueLen = len;
	}
	if (result->deriveAttribute)
	{
		t[n].type = CKA_DERIVE; t[n].pValue = &deriveValue; t[n++].ulValueLen = sizeof(deriveValue);
	}
	if (result->token) { t[n].type = CKA_LABEL; t[n].pValue = (CK_VOID_PTR)PROBE_LABEL; t[n++].ulValueLen = sizeof(PROBE_LABEL) - 1; }
	*key = CK_INVALID_HANDLE;
	return p11->C_DeriveKey(session, &mech, base, t, n, key);
}

/* One derive: show the code, and the value (or all attributes) if a key came
 * back. Returns the value length read, or -1. */
static long tryDerive(const char* what, CK_MECHANISM_TYPE mechanism, CK_OBJECT_HANDLE base,
		      const void* param, CK_ULONG paramLen, const Result* result,
		      int full, CK_BYTE* value, CK_ULONG valueSize)
{
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_BYTE buf[256];
	CK_RV rv = derive(mechanism, base, param, paramLen, result, &key);
	long length = -1;
	showRv(what, rv);
	if (rv != CKR_OK) return -1;
	if (key == CK_INVALID_HANDLE) { line("      (CKR_OK without a key handle)"); return -1; }
	if (full) describeKey(key);
	else
	{
		CK_RV readRv;
		length = readAttr(key, CKA_VALUE, buf, sizeof(buf), &readRv);
		if (length < 0) line("      CKA_VALUE: %s", rvName(readRv));
		else hexLine("CKA_VALUE", buf, (CK_ULONG)length);
	}
	if (value && length < 0)
	{
		CK_RV readRv;
		length = readAttr(key, CKA_VALUE, buf, sizeof(buf), &readRv);
	}
	if (value && length > 0 && (CK_ULONG)length <= valueSize) memcpy(value, buf, (size_t)length);
	destroy(key);
	return length;
}

/* Both SDK VKO-2012-256 samples put 0xD4321026 into the first four bytes of
 * CKM_GOSTR3410_12_DERIVE's flat parameter, including the sample with a
 * 512-bit base key. This is a KDF selector inside that mechanism, not a call
 * to C_DeriveKey with CKM_KDF_GOSTR3411_2012_256 as the mechanism. The
 * template below follows the samples' CKO_SECRET_KEY result attributes. */
static void trySdkVko(const char* what, CK_OBJECT_HANDLE base,
		      const CK_BYTE* peer, CK_ULONG peerLen)
{
	CK_BYTE param[256];
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_KEY_TYPE gost = CKK_GOST28147;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ATTRIBUTE attributes[] = {
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &gost, sizeof(gost) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_MODIFIABLE, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
		{ CKA_SENSITIVE, &no, sizeof(no) }
	};
	CK_MECHANISM mechanism = { MECH_GOSTR3410_12_DERIVE, param, 0 };
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_RV rv;
	mechanism.ulParameterLen = flatParameter(param, MECH_KDF_GOST_256,
		peer, peerLen, UKM_1, sizeof(UKM_1));
	rv = p11->C_DeriveKey(session, &mechanism, base, attributes,
		(CK_ULONG)(sizeof(attributes) / sizeof(attributes[0])), &key);
	showRv(what, rv);
	if (rv == CKR_OK && key != CK_INVALID_HANDLE) describeKey(key);
	destroy(key);
}

/* ---- sections ------------------------------------------------------------ */

static void probeMechanisms(void)
{
	static const struct { CK_MECHANISM_TYPE m; const char* name; } mechs[] = {
		{ MECH_GOSTR3410_12_DERIVE, "CKM_GOSTR3410_12_DERIVE 0xD4321007" },
		{ MECH_GOSTR3410_DERIVE, "CKM_GOSTR3410_DERIVE 0x1204" },
		{ MECH_GOST_KEG, "CKM_GOST_KEG 0xD4321039" },
		{ MECH_KDF_GOST_256, "CKM_KDF_GOSTR3411_2012_256 0xD4321026" },
		{ MECH_KDF_HMAC_256, "CKM_KDF_HMAC3411_2012_256 0xD4321028" },
		{ MECH_KDF_TREE_256, "CKM_KDF_TREE_GOSTR3411_2012_256 0xD432102A" },
		{ MECH_VKO_512, "CKM_VKO_GOSTR3410_2012_512 0xD4321038" },
		{ MECH_VENDOR_CBC_FSS, "CKM_VENDOR_GOST28147_CBC_FSS 0x8000000B" },
		{ MECH_VENDOR_SECURE_IMPORT, "CKM_VENDOR_SECURE_IMPORT 0x80000003" },
		{ 0xD4321014UL, "CKM_GOSTR3411_12_256_HMAC 0xD4321014" },
		{ 0xD4321015UL, "CKM_GOSTR3411_12_512_HMAC 0xD4321015" },
	};
	CK_TOKEN_INFO token;
	CK_INFO info;
	size_t i;
	section("Library, token and the GOST derive mechanisms");
	if (p11->C_GetInfo(&info) == CKR_OK)
		line("    library      '%.32s' version %d.%d", info.libraryDescription,
		     info.libraryVersion.major, info.libraryVersion.minor);
	if (p11->C_GetTokenInfo(theSlot, &token) == CKR_OK)
		line("    token        '%.16s' serial '%.16s' firmware %d.%d", token.model,
		     token.serialNumber, token.firmwareVersion.major, token.firmwareVersion.minor);
	for (i = 0; i < sizeof(mechs) / sizeof(mechs[0]); ++i)
	{
		CK_MECHANISM_INFO mi;
		CK_RV rv = p11->C_GetMechanismInfo(theSlot, mechs[i].m, &mi);
		if (rv == CKR_OK)
			line("    %-36s min %lu max %lu flags 0x%lx", mechs[i].name,
			     (unsigned long)mi.ulMinKeySize, (unsigned long)mi.ulMaxKeySize,
			     (unsigned long)mi.flags);
		else
			showRv(mechs[i].name, rv);
	}
}

static CK_OBJECT_HANDLE basePub = CK_INVALID_HANDLE, basePriv = CK_INVALID_HANDLE;

static void probePluginCall(void)
{
	CK_BYTE param[256], point[128];
	CK_ULONG paramLen;
	long pointLen;
	section("The plugin's call: TC26-A key, flat parameter, CKD_NULL, 8-byte UKM, CKK_GOST28147");
	showRv("generate the base key pair (TC26-A, token, CKA_DERIVE)",
	       genPair("drv-base", 256, CURVE_TC26_A, sizeof(CURVE_TC26_A), CK_TRUE, &basePub, &basePriv));
	if (basePriv == CK_INVALID_HANDLE) return;
	pointLen = publicPoint(basePub, point, sizeof(point));
	if (pointLen > 0) hexLine("the token's public point, little-endian X || Y", point, (CK_ULONG)pointLen);
	line("      peer: the TC26 256-bit sample key's point (see the probe source)");
	paramLen = flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8);
	hexLine("parameter", param, paramLen);
	tryDerive("derive, UKM 01..08, the plugin's template", MECH_GOSTR3410_12_DERIVE, basePriv,
		  param, paramLen, &PLUGIN_RESULT, 1, NULL, 0);
	paramLen = flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1_REVERSED, 8);
	tryDerive("derive, UKM 08..01 (the same bytes reversed)", MECH_GOSTR3410_12_DERIVE, basePriv,
		  param, paramLen, &PLUGIN_RESULT, 0, NULL, 0);
}

static void probeCurves(void)
{
	static const struct { const char* name; const CK_BYTE* curve; CK_ULONG len; } curves[] = {
		{ "CryptoPro-A", CURVE_CP_A, sizeof(CURVE_CP_A) },
		{ "CryptoPro-B", CURVE_CP_B, sizeof(CURVE_CP_B) },
		{ "CryptoPro-C", CURVE_CP_C, sizeof(CURVE_CP_C) },
		{ "TC26-A", CURVE_TC26_A, sizeof(CURVE_TC26_A) },
	};
	size_t i;
	section("Both sides agree, per curve; importing the sample private key");
	for (i = 0; i < sizeof(curves) / sizeof(curves[0]); ++i)
	{
		CK_OBJECT_HANDLE pa, ka, pb, kb;
		CK_BYTE pointA[128], pointB[128], vab[64], vba[64], param[256];
		long la, lb, xab, xba;
		char what[96];
		snprintf(what, sizeof(what), "%s: generate pairs A and B", curves[i].name);
		CK_RV rv = genPair("drv-curve-a", 256, curves[i].curve, curves[i].len, CK_TRUE, &pa, &ka);
		if (rv == CKR_OK) rv = genPair("drv-curve-b", 256, curves[i].curve, curves[i].len, CK_TRUE, &pb, &kb);
		showRv(what, rv);
		if (rv != CKR_OK) continue;
		la = publicPoint(pa, pointA, sizeof(pointA));
		lb = publicPoint(pb, pointB, sizeof(pointB));
		if (la == 64 && lb == 64)
		{
			snprintf(what, sizeof(what), "%s: A with B's point", curves[i].name);
			xab = tryDerive(what, MECH_GOSTR3410_12_DERIVE, ka, param,
					flatParameter(param, CKD_NULL, pointB, 64, UKM_1, 8),
					&PLUGIN_RESULT, 0, vab, sizeof(vab));
			snprintf(what, sizeof(what), "%s: B with A's point", curves[i].name);
			xba = tryDerive(what, MECH_GOSTR3410_12_DERIVE, kb, param,
					flatParameter(param, CKD_NULL, pointA, 64, UKM_1, 8),
					&PLUGIN_RESULT, 0, vba, sizeof(vba));
			if (xab > 0 && xab == xba)
				line("      both sides equal: %s", memcmp(vab, vba, (size_t)xab) == 0 ? "YES" : "NO");
		}
		destroy(pa); destroy(ka); destroy(pb); destroy(kb);
	}
	{
		CK_OBJECT_CLASS privClass = CKO_PRIVATE_KEY;
		CK_KEY_TYPE keyType = CKK_GOSTR3410;
		CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
		CK_OBJECT_HANDLE imported = CK_INVALID_HANDLE;
		CK_ATTRIBUTE t[] = {
			{ CKA_CLASS, &privClass, sizeof(privClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &no, sizeof(no) },
			{ CKA_PRIVATE, &yes, sizeof(yes) },
			{ CKA_DERIVE, &yes, sizeof(yes) },
			{ CKA_VALUE, (CK_VOID_PTR)SAMPLE_256_PRIVATE_LE, sizeof(SAMPLE_256_PRIVATE_LE) },
			{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)CURVE_TC26_A, sizeof(CURVE_TC26_A) },
			{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)DIGEST_256, sizeof(DIGEST_256) },
		};
		CK_RV rv = p11->C_CreateObject(session, t, sizeof(t) / sizeof(t[0]), &imported);
		showRv("import the TC26 sample private key (session object)", rv);
		if (rv == CKR_OK)
		{
			CK_BYTE param[256], value[64];
			long length = tryDerive("the sample key with its own point, UKM 01..08",
						MECH_GOSTR3410_12_DERIVE, imported, param,
						flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8),
						&PLUGIN_RESULT, 0, value, sizeof(value));
			if (length == 32)
				line("      equal to gost-engine's VKO: %s",
				     memcmp(value, SAMPLE_256_SELF_VKO, 32) == 0 ? "YES" : "NO");
			destroy(imported);
		}
	}
}

static void probeParameterValues(void)
{
	static const CK_ULONG kdfs[] = { 0, CKD_SHA1_KDF, CKD_CPDIVERSIFY_KDF,
		MECH_KDF_GOST_256, MECH_KDF_HMAC_256, MECH_KDF_TREE_256 };
	static const CK_BYTE ukm16[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	static const CK_BYTE ukm32[32] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
					   17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 };
	static const CK_BYTE zero8[8] = { 0 };
	CK_BYTE param[256];
	size_t i;
	char what[96];
	section("Other KDF values, UKM lengths and a zero UKM (TC26-A base key)");
	if (basePriv == CK_INVALID_HANDLE) { line("    no base key"); return; }
	for (i = 0; i < sizeof(kdfs) / sizeof(kdfs[0]); ++i)
	{
		snprintf(what, sizeof(what), "kdf = 0x%lx", (unsigned long)kdfs[i]);
		tryDerive(what, MECH_GOSTR3410_12_DERIVE, basePriv, param,
			  flatParameter(param, kdfs[i], SAMPLE_256_POINT, 64, UKM_1, 8), &PLUGIN_RESULT, 0, NULL, 0);
	}
	trySdkVko("SDK 256-bit VKO sample: KDF 0xD4321026 and full result template",
		basePriv, SAMPLE_256_POINT, sizeof(SAMPLE_256_POINT));
	tryDerive("UKM length 0", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, NULL, 0), &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("UKM 4 bytes 01..04", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 4), &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("UKM 16 bytes 01..10", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, ukm16, 16), &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("UKM 32 bytes 01..20", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, ukm32, 32), &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("UKM 8 zero bytes", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, zero8, 8), &PLUGIN_RESULT, 0, NULL, 0);
}

static void probeUnmeasuredVko(void)
{
	static const CK_ULONG lengths[] = { 1, 2, 3, 5, 6, 7, 9, 15, 17, 24, 31, 33, 64 };
	static const CK_ULONG diversifyLengths[] = { 1, 4, 16, 32, 33 };
	static const Result cpB = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 2, 0 };
	static const Result tc26Z = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 3, 0 };
	static const Result explicitDeriveFalse = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, -1 };
	static const Result explicitDeriveTrue = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 1 };
	static const Result resultLen16 = { CKK_GOST28147, 16, CK_FALSE, -1, -1, 0, 0 };
	static const Result resultLen64 = { CKK_GOST28147, 64, CK_FALSE, -1, -1, 0, 0 };
	CK_BYTE ukm[64], padded[32] = { 1 }, param[256];
	size_t i;
	char name[96];
	section("Unmeasured VKO variants: UKM, diversification, result template (256-bit key)");
	if (basePriv == CK_INVALID_HANDLE) { line("    no base key"); return; }
	for (i = 0; i < sizeof(ukm); ++i) ukm[i] = (CK_BYTE)(i + 1);
	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
	{
		CK_ULONG len = lengths[i];
		snprintf(name, sizeof(name), "CKD_NULL, UKM %lu bytes, 01..%02lx", (unsigned long)len,
			 (unsigned long)len);
		tryDerive(name, MECH_GOSTR3410_12_DERIVE, basePriv, param,
			flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, ukm, len),
			&PLUGIN_RESULT, 0, NULL, 0);
	}
	for (i = 0; i < 5; ++i)
	{
		static const CK_ULONG paddedLengths[] = { 1, 4, 8, 16, 32 };
		CK_ULONG len = paddedLengths[i];
		snprintf(name, sizeof(name), "CKD_NULL, padded UKM 01 + zeros, %lu bytes", (unsigned long)len);
		tryDerive(name, MECH_GOSTR3410_12_DERIVE, basePriv, param,
			flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, padded, len),
			&PLUGIN_RESULT, 0, NULL, 0);
	}
	for (i = 0; i < sizeof(diversifyLengths) / sizeof(diversifyLengths[0]); ++i)
	{
		CK_ULONG len = diversifyLengths[i];
		snprintf(name, sizeof(name), "CKD_CPDIVERSIFY_KDF, UKM %lu bytes", (unsigned long)len);
		tryDerive(name, MECH_GOSTR3410_12_DERIVE, basePriv, param,
			flatParameter(param, CKD_CPDIVERSIFY_KDF, SAMPLE_256_POINT, 64, ukm, len),
			&PLUGIN_RESULT, 0, NULL, 0);
	}
	tryDerive("CKD_CPDIVERSIFY_KDF, explicit CryptoPro-B", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_CPDIVERSIFY_KDF, SAMPLE_256_POINT, 64,
		UKM_1, 8), &cpB, 1, NULL, 0);
	tryDerive("CKD_CPDIVERSIFY_KDF, explicit TC26-Z", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_CPDIVERSIFY_KDF, SAMPLE_256_POINT, 64,
		UKM_1, 8), &tc26Z, 1, NULL, 0);
	tryDerive("CKD_NULL, explicit CryptoPro-B", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &cpB, 1, NULL, 0);
	tryDerive("CKD_NULL, explicit TC26-Z", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &tc26Z, 1, NULL, 0);
	tryDerive("CKD_NULL, explicit CKA_DERIVE FALSE", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &explicitDeriveFalse, 1, NULL, 0);
	tryDerive("CKD_NULL, explicit CKA_DERIVE TRUE", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &explicitDeriveTrue, 1, NULL, 0);
	tryDerive("CKD_NULL, CKK_GOST28147 CKA_VALUE_LEN 16", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &resultLen16, 0, NULL, 0);
	tryDerive("CKD_NULL, CKK_GOST28147 CKA_VALUE_LEN 64", MECH_GOSTR3410_12_DERIVE,
		basePriv, param, flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64,
		UKM_1, 8), &resultLen64, 0, NULL, 0);
}

static void probeParameterForms(void)
{
	CK_GOSTR3410_DERIVE_PARAMS structured;
	CK_BYTE param[256], wrongPoint[64];
	CK_ULONG paramLen;
	section("The parameter as a structure, and malformed buffers (TC26-A base key)");
	if (basePriv == CK_INVALID_HANDLE) { line("    no base key"); return; }
	line("    sizeof(CK_GOSTR3410_DERIVE_PARAMS) = %lu", (unsigned long)sizeof(structured));
	structured.kdf = CKD_NULL;
	structured.pPublicData = (CK_BYTE_PTR)SAMPLE_256_POINT;
	structured.ulPublicDataLen = 64;
	structured.pUKM = (CK_BYTE_PTR)UKM_1;
	structured.ulUKMLen = 8;
	tryDerive("CK_GOSTR3410_DERIVE_PARAMS {CKD_NULL, point, UKM 01..08}", MECH_GOSTR3410_12_DERIVE,
		  basePriv, &structured, sizeof(structured), &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("no parameter (NULL, 0)", MECH_GOSTR3410_12_DERIVE, basePriv, NULL, 0,
		  &PLUGIN_RESULT, 0, NULL, 0);
	paramLen = flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8);
	tryDerive("flat buffer one byte short", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  paramLen - 1, &PLUGIN_RESULT, 0, NULL, 0);
	param[paramLen] = 0;
	tryDerive("flat buffer with one extra byte", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  paramLen + 1, &PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("128-byte point with the 256-bit key", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, SAMPLE_512_POINT, 128, UKM_1, 8), &PLUGIN_RESULT, 0, NULL, 0);
	memcpy(wrongPoint, SAMPLE_256_POINT, sizeof(wrongPoint));
	wrongPoint[0] ^= 1;
	tryDerive("a point not on the curve", MECH_GOSTR3410_12_DERIVE, basePriv, param,
		  flatParameter(param, CKD_NULL, wrongPoint, 64, UKM_1, 8), &PLUGIN_RESULT, 0, NULL, 0);
}

static void probeResults(void)
{
	static const struct { const char* name; Result r; int full; } results[] = {
		{ "CKK_GOST28147, CKA_VALUE_LEN 32", { CKK_GOST28147, 32, CK_FALSE, -1, -1, 0, 0 }, 0 },
		{ "CKK_GOST28147, CKA_GOST28147_PARAMS CryptoPro-A", { CKK_GOST28147, -1, CK_FALSE, -1, -1, 1, 0 }, 1 },
		{ "CKK_GOST28147, CKA_SENSITIVE TRUE", { CKK_GOST28147, -1, CK_FALSE, 1, -1, 0, 0 }, 1 },
		{ "CKK_GOST28147, CKA_EXTRACTABLE FALSE", { CKK_GOST28147, -1, CK_FALSE, -1, 0, 0, 0 }, 1 },
		{ "CKK_GOST28147, CKA_TOKEN TRUE", { CKK_GOST28147, -1, CK_TRUE, -1, -1, 0, 0 }, 0 },
		{ "CKK_GENERIC_SECRET, no CKA_VALUE_LEN", { CKK_GENERIC_SECRET, -1, CK_FALSE, -1, -1, 0, 0 }, 0 },
		{ "CKK_GENERIC_SECRET, CKA_VALUE_LEN 32", { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 }, 0 },
		{ "CKK_GENERIC_SECRET, CKA_VALUE_LEN 64", { CKK_GENERIC_SECRET, 64, CK_FALSE, -1, -1, 0, 0 }, 0 },
		{ "CKK_MAGMA (0xD4321005)", { 0xD4321005UL, -1, CK_FALSE, -1, -1, 0, 0 }, 0 },
		{ "CKK_KUZNECHIK (0xD4321004)", { 0xD4321004UL, -1, CK_FALSE, -1, -1, 0, 0 }, 0 },
	};
	CK_BYTE param[256];
	CK_ULONG paramLen;
	size_t i;
	section("Other result templates (TC26-A base key, the plugin's parameter)");
	if (basePriv == CK_INVALID_HANDLE) { line("    no base key"); return; }
	paramLen = flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8);
	for (i = 0; i < sizeof(results) / sizeof(results[0]); ++i)
		tryDerive(results[i].name, MECH_GOSTR3410_12_DERIVE, basePriv, param, paramLen,
			  &results[i].r, results[i].full, NULL, 0);
}

static void probe512(void)
{
	static const Result generic64 = { CKK_GENERIC_SECRET, 64, CK_FALSE, -1, -1, 0, 0 };
	CK_OBJECT_HANDLE pa, ka, pb, kb;
	CK_BYTE pointA[160], pointB[160], param[320], vab[64], vba[64];
	long la, lb, xab, xba;
	CK_RV rv;
	section("512-bit keys (TC26 512 paramSetC)");
	rv = genPair("drv-512-a", 512, CURVE_512_C, sizeof(CURVE_512_C), CK_TRUE, &pa, &ka);
	if (rv == CKR_OK) rv = genPair("drv-512-b", 512, CURVE_512_C, sizeof(CURVE_512_C), CK_TRUE, &pb, &kb);
	showRv("generate pairs A and B", rv);
	if (rv != CKR_OK) return;
	la = publicPoint(pa, pointA, sizeof(pointA));
	lb = publicPoint(pb, pointB, sizeof(pointB));
	if (la > 0) hexLine("A's public point, little-endian X || Y", pointA, (CK_ULONG)la);
	line("      peer: the TC26 512-bit sample key's point (see the probe source)");
	tryDerive("A with the sample point (128 bytes), CKK_GOST28147", MECH_GOSTR3410_12_DERIVE, ka, param,
		  flatParameter(param, CKD_NULL, SAMPLE_512_POINT, 128, UKM_1, 8), &PLUGIN_RESULT, 1, NULL, 0);
	trySdkVko("SDK 512-bit base-key sample: KDF 0xD4321026 and full result template",
		ka, SAMPLE_512_POINT, sizeof(SAMPLE_512_POINT));
	tryDerive("standalone CKM_VKO_GOSTR3410_2012_512: flat CKD_NULL (format hypothesis)",
		MECH_VKO_512, ka, param,
		flatParameter(param, CKD_NULL, SAMPLE_512_POINT, 128, UKM_1, 8),
		&PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("standalone CKM_VKO_GOSTR3410_2012_512: flat SDK KDF 0xD4321026 (hypothesis)",
		MECH_VKO_512, ka, param,
		flatParameter(param, MECH_KDF_GOST_256, SAMPLE_512_POINT, 128, UKM_1, 8),
		&PLUGIN_RESULT, 0, NULL, 0);
	tryDerive("A with the sample point, CKK_GENERIC_SECRET CKA_VALUE_LEN 64", MECH_GOSTR3410_12_DERIVE,
		  ka, param, flatParameter(param, CKD_NULL, SAMPLE_512_POINT, 128, UKM_1, 8), &generic64, 0, NULL, 0);
	tryDerive("A with a 64-byte point", MECH_GOSTR3410_12_DERIVE, ka, param,
		  flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8), &PLUGIN_RESULT, 0, NULL, 0);
	{
		CK_BYTE ukm[32];
		static const CK_ULONG lengths[] = { 4, 16, 32 };
		size_t i;
		char name[96];
		for (i = 0; i < sizeof(ukm); ++i) ukm[i] = (CK_BYTE)(i + 1);
		for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
		{
			CK_ULONG len = lengths[i];
			snprintf(name, sizeof(name), "512-bit key, CKD_NULL, UKM %lu bytes", (unsigned long)len);
			tryDerive(name, MECH_GOSTR3410_12_DERIVE, ka, param,
				flatParameter(param, CKD_NULL, SAMPLE_512_POINT, 128, ukm, len),
				&PLUGIN_RESULT, 0, NULL, 0);
		}
		tryDerive("512-bit key, CKD_CPDIVERSIFY_KDF, UKM 8 bytes",
			MECH_GOSTR3410_12_DERIVE, ka, param,
			flatParameter(param, CKD_CPDIVERSIFY_KDF, SAMPLE_512_POINT, 128,
			UKM_1, 8), &PLUGIN_RESULT, 0, NULL, 0);
		tryDerive("512-bit key, CKD_CPDIVERSIFY_KDF, UKM 16 bytes",
			MECH_GOSTR3410_12_DERIVE, ka, param,
			flatParameter(param, CKD_CPDIVERSIFY_KDF, SAMPLE_512_POINT, 128,
			ukm, 16), &PLUGIN_RESULT, 0, NULL, 0);
	}
	if (la == 128 && lb == 128)
	{
		xab = tryDerive("A with B's point", MECH_GOSTR3410_12_DERIVE, ka, param,
				flatParameter(param, CKD_NULL, pointB, 128, UKM_1, 8), &PLUGIN_RESULT, 0, vab, sizeof(vab));
		xba = tryDerive("B with A's point", MECH_GOSTR3410_12_DERIVE, kb, param,
				flatParameter(param, CKD_NULL, pointA, 128, UKM_1, 8), &PLUGIN_RESULT, 0, vba, sizeof(vba));
		if (xab > 0 && xab == xba)
			line("      both sides equal: %s", memcmp(vab, vba, (size_t)xab) == 0 ? "YES" : "NO");
	}
	destroy(pa); destroy(ka); destroy(pb); destroy(kb);
}

static void probeBaseKeys(void)
{
	CK_OBJECT_HANDLE pub, priv;
	CK_BYTE param[256];
	CK_ULONG paramLen = flatParameter(param, CKD_NULL, SAMPLE_256_POINT, 64, UKM_1, 8);
	section("Base keys: no CKA_DERIVE, a public key, and CKM_GOSTR3410_DERIVE (0x1204)");
	showRv("generate a TC26-A pair with CKA_DERIVE FALSE",
	       genPair("drv-noderive", 256, CURVE_TC26_A, sizeof(CURVE_TC26_A), CK_FALSE, &pub, &priv));
	if (priv != CK_INVALID_HANDLE)
	{
		tryDerive("derive with the CKA_DERIVE FALSE key", MECH_GOSTR3410_12_DERIVE, priv, param, paramLen,
			  &PLUGIN_RESULT, 0, NULL, 0);
		destroy(pub); destroy(priv);
	}
	if (basePub != CK_INVALID_HANDLE)
		tryDerive("the public key as the base key", MECH_GOSTR3410_12_DERIVE, basePub, param, paramLen,
			  &PLUGIN_RESULT, 0, NULL, 0);
	if (basePriv != CK_INVALID_HANDLE)
	{
		CK_GOSTR3410_DERIVE_PARAMS structured;
		tryDerive("CKM_GOSTR3410_DERIVE, the flat parameter", MECH_GOSTR3410_DERIVE, basePriv, param,
			  paramLen, &PLUGIN_RESULT, 0, NULL, 0);
		structured.kdf = CKD_NULL;
		structured.pPublicData = (CK_BYTE_PTR)SAMPLE_256_POINT;
		structured.ulPublicDataLen = 64;
		structured.pUKM = (CK_BYTE_PTR)UKM_1;
		structured.ulUKMLen = 8;
		tryDerive("CKM_GOSTR3410_DERIVE, CK_GOSTR3410_DERIVE_PARAMS", MECH_GOSTR3410_DERIVE, basePriv,
			  &structured, sizeof(structured), &PLUGIN_RESULT, 0, NULL, 0);
	}
}

/* This layout is CK_KDF_TREE_GOST_PARAMS from Rutoken SDK pkcs11tc26_18.h. */
typedef struct {
	CK_ULONG ulLabelLength;
	CK_BYTE_PTR pLabel;
	CK_ULONG ulSeedLength;
	CK_BYTE_PTR pSeed;
	CK_ULONG ulR;
	CK_ULONG ulL;
	CK_ULONG ulOffset;
} ProbeKdfTreeParams;

static CK_OBJECT_HANDLE createProbeSecret(const char* what, CK_KEY_TYPE type,
					  const CK_BYTE* bytes, CK_ULONG length)
{
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE attrs[12] = {
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_SENSITIVE, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
		{ CKA_DERIVE, &yes, sizeof(yes) },
		{ CKA_SIGN, &yes, sizeof(yes) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_VALUE, (CK_VOID_PTR)bytes, length },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 }
	};
	CK_ULONG count = 11;
	CK_RV rv;
	if (type == CKK_GOST28147)
	{
		attrs[count].type = CKA_GOST28147_PARAMS;
		attrs[count].pValue = (CK_VOID_PTR)GOST28147_CP_A;
		attrs[count++].ulValueLen = sizeof(GOST28147_CP_A);
	}
	rv = p11->C_CreateObject(session, attrs, count, &key);
	showRv(what, rv);
	return rv == CKR_OK ? key : CK_INVALID_HANDLE;
}

/* The two SDK SigVerGOST34.11-2012-{256,512}-HMAC.c samples generate a
 * session CKK_GOST28147 key with these attributes; CKA_SIGN/CKA_VERIFY are
 * omitted there, making their device defaults part of this measurement. */
static CK_OBJECT_HANDLE generateSdkHmacKey(void)
{
	static const CK_BYTE id[] = { 'h','m','a','c','-','s','d','k' };
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_KEY_TYPE gost = CKK_GOST28147;
	CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
	CK_MECHANISM mechanism = { CKM_GOST28147_KEY_GEN, NULL_PTR, 0 };
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, sizeof(id) },
		{ CKA_KEY_TYPE, &gost, sizeof(gost) },
		{ CKA_ENCRYPT, &yes, sizeof(yes) },
		{ CKA_DECRYPT, &yes, sizeof(yes) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_GOST28147_PARAMS, (CK_VOID_PTR)GOST28147_CP_A, sizeof(GOST28147_CP_A) }
	};
	CK_RV rv = p11->C_GenerateKey(session, &mechanism, attrs,
		(CK_ULONG)(sizeof(attrs) / sizeof(attrs[0])), &key);
	showRv("generate CKK_GOST28147 by the SDK HMAC sample template", rv);
	return rv == CKR_OK ? key : CK_INVALID_HANDLE;
}

static void probeHmacOnKey(const char* keyName, CK_OBJECT_HANDLE base,
			   const CK_BYTE* message, CK_ULONG messageLen)
{
	static const struct { CK_MECHANISM_TYPE mechanism; const char* name; } hmacs[] = {
		{ 0xD4321014UL, "HMAC-Streebog-256" },
		{ 0xD4321015UL, "HMAC-Streebog-512" }
	};
	CK_BYTE mac[64];
	CK_RV rv;
	size_t i;
	line("    HMAC key profile: %s", keyName);
	for (i = 0; i < sizeof(hmacs) / sizeof(hmacs[0]); ++i)
	{
		CK_MECHANISM mech = { hmacs[i].mechanism, NULL_PTR, 0 };
		CK_ULONG macLen = sizeof(mac);
		rv = p11->C_SignInit(session, &mech, base);
		showRv(hmacs[i].name, rv);
		if (rv != CKR_OK) continue;
		rv = p11->C_Sign(session, (CK_BYTE_PTR)message, messageLen, mac, &macLen);
		showRv("C_Sign RFC 7836 sample message", rv);
		if (rv == CKR_OK && macLen <= sizeof(mac))
		{
			hexLine("HMAC", mac, macLen);
			rv = p11->C_VerifyInit(session, &mech, base);
			showRv("C_VerifyInit with the same key", rv);
			if (rv == CKR_OK)
				showRv("C_Verify with the produced HMAC",
					p11->C_Verify(session, (CK_BYTE_PTR)message, messageLen, mac, macLen));
		}
	}
}

static void probeDocumentedKdfsAndHmac(void)
{
	static const Result generic16 = { CKK_GENERIC_SECRET, 16, CK_FALSE, -1, -1, 0, 0 };
	static const Result generic32 = { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 };
	static const Result generic64 = { CKK_GENERIC_SECRET, 64, CK_FALSE, -1, -1, 0, 0 };
	CK_BYTE keyBytes[64], seed[8] = { 1,2,3,4,5,6,7,8 };
	CK_BYTE label[] = { 'k', 'd', 'f' };
	CK_BYTE message[] = { 0x01,0x26,0xbd,0xb8,0x78,0x00,0xaf,0x21,
		0x43,0x41,0x45,0x65,0x63,0x78,0x01,0x00 };
	ProbeKdfTreeParams tree = { sizeof(label), label, sizeof(seed), seed, 8, 256, 0 };
	CK_OBJECT_HANDLE base, gost;
	size_t i;
	section("Named KDFs and Streebog HMAC: generic and GOST 28147 session keys");
	for (i = 0; i < sizeof(keyBytes); ++i) keyBytes[i] = (CK_BYTE)i;
	base = createProbeSecret("create RFC 7836 generic key 00..1f",
		CKK_GENERIC_SECRET, keyBytes, 32);
	if (base != CK_INVALID_HANDLE)
	{
		tryDerive("KDF_HMAC-256, NULL parameter, generic base key",
			MECH_KDF_HMAC_256, base, NULL, 0, &generic32, 0, NULL, 0);
		tryDerive("KDF_HMAC-256, raw 8-byte seed (format hypothesis)",
			MECH_KDF_HMAC_256, base, seed, sizeof(seed), &generic32, 0, NULL, 0);
		tryDerive("KDF_TREE-256, SDK struct, R=8 L=256 offset=0",
			MECH_KDF_TREE_256, base, &tree, sizeof(tree), &generic32, 0, NULL, 0);
		tree.ulOffset = 1;
		tryDerive("KDF_TREE-256, SDK struct, R=8 L=256 offset=1",
			MECH_KDF_TREE_256, base, &tree, sizeof(tree), &generic32, 0, NULL, 0);
		tree.ulOffset = 0;
		tree.ulL = 32;
		tryDerive("KDF_TREE-256, SDK struct, R=8 L=32 offset=0",
			MECH_KDF_TREE_256, base, &tree, sizeof(tree), &generic32, 0, NULL, 0);
		tree.ulL = 256;
		tryDerive("KDF_TREE-256, CKA_VALUE_LEN=16",
			MECH_KDF_TREE_256, base, &tree, sizeof(tree), &generic16, 0, NULL, 0);
		tryDerive("KDF_TREE-256, CKA_VALUE_LEN=64",
			MECH_KDF_TREE_256, base, &tree, sizeof(tree), &generic64, 0, NULL, 0);
		probeHmacOnKey("CKK_GENERIC_SECRET, 32 known bytes", base, message, sizeof(message));
		destroy(base);
	}
	gost = createProbeSecret("create CKK_GOST28147 with RFC 7836 bytes and CKA_DERIVE",
		CKK_GOST28147, keyBytes, 32);
	if (gost != CK_INVALID_HANDLE)
	{
		tryDerive("KDF_HMAC-256, NULL parameter, GOST 28147 base key",
			MECH_KDF_HMAC_256, gost, NULL, 0, &generic32, 0, NULL, 0);
		tryDerive("KDF_TREE-256, SDK struct, GOST 28147 base key",
			MECH_KDF_TREE_256, gost, &tree, sizeof(tree), &generic32, 0, NULL, 0);
		probeHmacOnKey("CKK_GOST28147, 32 known bytes", gost, message, sizeof(message));
		destroy(gost);
	}
	base = createProbeSecret("create short generic key, 1 byte", CKK_GENERIC_SECRET, keyBytes, 1);
	if (base != CK_INVALID_HANDLE)
	{
		probeHmacOnKey("CKK_GENERIC_SECRET, 1 byte", base, message, sizeof(message));
		destroy(base);
	}
	base = createProbeSecret("create long generic key, 64 bytes", CKK_GENERIC_SECRET, keyBytes, 64);
	if (base != CK_INVALID_HANDLE)
	{
		probeHmacOnKey("CKK_GENERIC_SECRET, 64 bytes", base, message, sizeof(message));
		destroy(base);
	}
	gost = generateSdkHmacKey();
	if (gost != CK_INVALID_HANDLE)
	{
		describeKey(gost);
		probeHmacOnKey("SDK-generated CKK_GOST28147; CKA_SIGN/VERIFY omitted", gost,
			message, sizeof(message));
		destroy(gost);
	}
}

/* ---- main ---------------------------------------------------------------- */

static int loadLibrary(void)
{
	CK_C_GetFunctionList getList;
	libraryHandle = dlopen(opt.module, RTLD_NOW);
	if (libraryHandle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 0; }
	getList = (CK_C_GetFunctionList)dlsym(libraryHandle, "C_GetFunctionList");
	if (getList == NULL || getList(&p11) != CKR_OK || p11 == NULL_PTR)
	{ fprintf(stderr, "C_GetFunctionList missing or failed\n"); return 0; }
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
	CK_RV rv;
	int i;

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] != '-' && opt.module == NULL) opt.module = argv[i];
		else if (strcmp(argv[i], "--user-pin") == 0) opt.userPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--user-pin-env") == 0) opt.userPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--slot") == 0)
		{
			opt.slot = strtoul(argValue(argc, argv, &i), NULL, 0);
			opt.slotGiven = 1;
		}
		else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
	}
	if (opt.module == NULL || opt.userPin == NULL)
	{
		fprintf(stderr,
			"usage: %s <path to librtpkcs11ecp.so> [options]\n"
			"  --user-pin PIN         the user PIN (required unless --user-pin-env is set)\n"
			"  --user-pin-env NAME    take the user PIN from the environment\n"
			"  --slot N               the slot (default: the first with a token)\n",
			argv[0]);
		return 2;
	}
	if (!loadLibrary()) return 1;
	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize: 0x%lx\n", (unsigned long)rv); return 1; }
	rv = p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK || slotCount == 0) { fprintf(stderr, "no token present (0x%lx)\n", (unsigned long)rv); return 1; }
	theSlot = opt.slotGiven ? opt.slot : slots[0];
	line("rutoken-derive-probe: CKM_GOSTR3410_12_DERIVE on slot %lu", (unsigned long)theSlot);
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession: 0x%lx\n", (unsigned long)rv); return 1; }
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)opt.userPin, (CK_ULONG)strlen(opt.userPin));
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
	{
		fprintf(stderr, "C_Login: %s (0x%lx); nothing was changed\n", rvName(rv), (unsigned long)rv);
		return 1;
	}
	deleteProbeObjects();

	probeMechanisms();
	probePluginCall();
	probeCurves();
	probeParameterValues();
	probeUnmeasuredVko();
	probeParameterForms();
	probeResults();
	probe512();
	probeBaseKeys();
	probeDocumentedKdfsAndHmac();

	section("Clean-up");
	deleteProbeObjects();
	p11->C_Logout(session);
	p11->C_CloseSession(session);
	p11->C_Finalize(NULL_PTR);
	line("\nDone.");
	return 0;
}
