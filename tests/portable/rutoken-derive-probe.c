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
 *  11. in --interactive mode, run the extended selector, direct KDF,
 *      standalone VKO, key-attribute and vendor-operation matrices;
 *  12. interactive follow-up: exact SDK legacy VKO-2001, twin-key KDF
 *      candidates, short generic-key threshold, every slot's versions,
 *      VKO-512 boundaries, CBC-FSS lengths/multipart and journal IDs;
 *  13. clean-up.
 *
 * It needs only the user PIN. It does not format the token, uses no SO PIN,
 * makes no wrong PIN attempt, and destroys every object it created (they all
 * carry the label below) - also the ones left by an earlier interrupted run.
 *
 * Building it:
 *
 *   cc -std=c11 -O2 -Wall -Wextra -Werror -I src/lib/pkcs11 \
 *      tests/portable/rutoken-derive-probe.c -ldl -o rutoken-derive-probe
 *
 * Running the full interactive matrix: see README-final-probe.txt.
 */

#define _POSIX_C_SOURCE 200809L

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "cryptoki.h"
#include "rutoken.h"

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
static CK_FUNCTION_LIST_EXTENDED_PTR ex = NULL_PTR;
static void* libraryHandle = NULL;
static CK_SLOT_ID theSlot = 0;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
static int cleanupFailed = 0;
static FILE* terminal = NULL;
static char promptedPin[128];
static char logPath[256];
static char modulePath[1024];

static struct {
	const char* module;
	const char* userPin;
	const char* output;
	int interactive;
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
/* SDK CreateGOST34.10-2001.c: CryptoPro GOST R 34.11-94 parameter set. */
static const CK_BYTE DIGEST_1994[]   = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x1e,0x01 };
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
	if (terminal != NULL)
	{
		fprintf(terminal, "[%d] %s\n", sectionNumber, title);
		fflush(terminal);
	}
}

static int promptText(const char* prompt, char* dest, size_t size)
{
	size_t length;
	fprintf(terminal, "%s", prompt);
	fflush(terminal);
	if (fgets(dest, (int)size, terminal) == NULL) return 0;
	length = strcspn(dest, "\r\n");
	if (dest[length] == '\0' && length == size - 1) return 0;
	dest[length] = '\0';
	return 1;
}

static int promptPin(void)
{
	struct termios saved, hidden;
	int ok;
	if (tcgetattr(fileno(terminal), &saved) != 0) return 0;
	hidden = saved;
	hidden.c_lflag &= (tcflag_t)~ECHO;
	if (tcsetattr(fileno(terminal), TCSANOW, &hidden) != 0) return 0;
	ok = promptText("User PIN (hidden): ", promptedPin, sizeof(promptedPin));
	if (tcsetattr(fileno(terminal), TCSANOW, &saved) != 0) return 0;
	fprintf(terminal, "\n");
	fflush(terminal);
	return ok && promptedPin[0] != '\0';
}

static int startLog(void)
{
	int fd;
	if (opt.output != NULL)
	{
		if (strlen(opt.output) >= sizeof(logPath)) return 0;
		strcpy(logPath, opt.output);
	}
	else
	{
		time_t now = time(NULL);
		struct tm local;
		if (now == (time_t)-1 || localtime_r(&now, &local) == NULL ||
		    strftime(logPath, sizeof(logPath), "rutoken-gap-probe-%Y%m%d-%H%M%S.log", &local) == 0)
			return 0;
	}
	fd = open(logPath, O_WRONLY | O_CREAT | O_EXCL, 0600);
	if (fd < 0) { fprintf(terminal, "Cannot create log %s: %s\n", logPath, strerror(errno)); return 0; }
	fflush(stdout);
	if (dup2(fd, fileno(stdout)) < 0) { close(fd); return 0; }
	close(fd);
	setvbuf(stdout, NULL, _IOLBF, 0);
	fprintf(terminal, "Log: %s\n", logPath);
	fflush(terminal);
	return 1;
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
	case CKR_ENCRYPTED_DATA_INVALID: return "CKR_ENCRYPTED_DATA_INVALID";
	case CKR_ENCRYPTED_DATA_LEN_RANGE: return "CKR_ENCRYPTED_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_KEY_NOT_WRAPPABLE: return "CKR_KEY_NOT_WRAPPABLE";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PUBLIC_KEY_INVALID: return "CKR_PUBLIC_KEY_INVALID";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
	case CKR_WRAPPED_KEY_INVALID: return "CKR_WRAPPED_KEY_INVALID";
	case CKR_WRAPPED_KEY_LEN_RANGE: return "CKR_WRAPPED_KEY_LEN_RANGE";
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
	CK_ULONG found = 0, i, removed = 0;
	CK_RV rv = p11->C_FindObjectsInit(session, &search, 1);
	if (rv != CKR_OK) { showRv("find probe objects for clean-up", rv); cleanupFailed = 1; return; }
	rv = p11->C_FindObjects(session, objects, MAX_OBJECTS, &found);
	if (rv != CKR_OK) { showRv("read probe objects for clean-up", rv); cleanupFailed = 1; }
	{
		CK_RV endRv = p11->C_FindObjectsFinal(session);
		if (endRv != CKR_OK) { showRv("finish clean-up search", endRv); cleanupFailed = 1; }
	}
	if (rv != CKR_OK) return;
	for (i = 0; i < found; i++)
	{
		rv = p11->C_DestroyObject(session, objects[i]);
		if (rv == CKR_OK) ++removed;
		else { showRv("destroy a probe object", rv); cleanupFailed = 1; }
	}
	line("    removed %lu probe object(s)", (unsigned long)removed);
	if (found == MAX_OBJECTS) { line("    search reached its object limit"); cleanupFailed = 1; }
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
		line("    token        '%.16s' firmware %d.%d", token.model,
		     token.firmwareVersion.major, token.firmwareVersion.minor);
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

/* The SDK's VKO selector is accepted by the reference device, but its
 * mathematics remains unknown. Measure its dependence on UKM, result type,
 * and direction on disposable token pairs so the log contains enough
 * independent values to identify the operation offline. */
static void probeSelectorKdf(void)
{
	static const CK_BYTE one[] = { 1 };
	static const CK_BYTE padded[8] = { 1 };
	static const CK_BYTE zero[8] = { 0 };
	static const CK_BYTE longUkm[32] = {
		1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
		17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
	};
	static const struct { const char* name; const CK_BYTE* bytes; CK_ULONG len; } ukms[] = {
		{ "one byte 01", one, 1 }, { "padded 01 (8 bytes)", padded, 8 },
		{ "01..08", UKM_1, 8 }, { "01..10", longUkm, 16 },
		{ "01..20", longUkm, 32 }, { "zero (8 bytes)", zero, 8 }
	};
	static const Result generic32 = { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 };
	CK_BYTE param[256], peerPoint[160], ownPoint[160], ab[64], ba[64];
	CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE pub512 = CK_INVALID_HANDLE, priv512 = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE otherPub512 = CK_INVALID_HANDLE, otherPriv512 = CK_INVALID_HANDLE;
	long peerLen, ownLen, lenAB, lenBA;
	size_t i;
	char name[120];
	section("VKO SDK selector 0xD4321026: extra UKM, result types, both directions");
	if (basePriv != CK_INVALID_HANDLE)
	{
		for (i = 0; i < sizeof(ukms) / sizeof(ukms[0]); ++i)
		{
			snprintf(name, sizeof(name), "256-bit key, selector 0x1026, UKM %s", ukms[i].name);
			tryDerive(name, MECH_GOSTR3410_12_DERIVE, basePriv, param,
				flatParameter(param, MECH_KDF_GOST_256, SAMPLE_256_POINT, 64,
				ukms[i].bytes, ukms[i].len), &PLUGIN_RESULT, 0, NULL, 0);
		}
		tryDerive("256-bit selector 0x1026, generic 32-byte result",
			MECH_GOSTR3410_12_DERIVE, basePriv, param,
			flatParameter(param, MECH_KDF_GOST_256, SAMPLE_256_POINT, 64, UKM_1, 8),
			&generic32, 1, NULL, 0);
		showRv("generate second 256-bit key for selector symmetry",
			genPair("gap-selector-b", 256, CURVE_TC26_A, sizeof(CURVE_TC26_A),
			CK_TRUE, &pub, &priv));
		if (priv != CK_INVALID_HANDLE)
		{
			peerLen = publicPoint(pub, peerPoint, sizeof(peerPoint));
			ownLen = publicPoint(basePub, ownPoint, sizeof(ownPoint));
			if (peerLen == 64 && ownLen == 64)
			{
				lenAB = tryDerive("selector 0x1026: A with B point", MECH_GOSTR3410_12_DERIVE,
					basePriv, param, flatParameter(param, MECH_KDF_GOST_256,
					peerPoint, 64, UKM_1, 8), &PLUGIN_RESULT, 0, ab, sizeof(ab));
				lenBA = tryDerive("selector 0x1026: B with A point", MECH_GOSTR3410_12_DERIVE,
					priv, param, flatParameter(param, MECH_KDF_GOST_256,
					ownPoint, 64, UKM_1, 8), &PLUGIN_RESULT, 0, ba, sizeof(ba));
				if (lenAB > 0 && lenAB == lenBA)
					line("      selector 256-bit agreement equal: %s",
					     memcmp(ab, ba, (size_t)lenAB) == 0 ? "YES" : "NO");
			}
		}
		destroy(pub); destroy(priv);
	}
	showRv("generate two 512-bit keys for selector symmetry",
		genPair("gap-selector-512a", 512, CURVE_512_C, sizeof(CURVE_512_C),
		CK_TRUE, &pub512, &priv512));
	if (priv512 != CK_INVALID_HANDLE)
	{
		CK_RV rv = genPair("gap-selector-512b", 512, CURVE_512_C,
			sizeof(CURVE_512_C), CK_TRUE, &otherPub512, &otherPriv512);
		showRv("generate second 512-bit key", rv);
		for (i = 0; i < 5; ++i)
		{
			snprintf(name, sizeof(name), "512-bit key, selector 0x1026, UKM %s", ukms[i].name);
			tryDerive(name, MECH_GOSTR3410_12_DERIVE, priv512, param,
				flatParameter(param, MECH_KDF_GOST_256, SAMPLE_512_POINT, 128,
				ukms[i].bytes, ukms[i].len), &PLUGIN_RESULT, 0, NULL, 0);
		}
		tryDerive("512-bit selector 0x1026, generic 32-byte result",
			MECH_GOSTR3410_12_DERIVE, priv512, param,
			flatParameter(param, MECH_KDF_GOST_256, SAMPLE_512_POINT, 128, UKM_1, 8),
			&generic32, 1, NULL, 0);
		if (otherPriv512 != CK_INVALID_HANDLE)
		{
			peerLen = publicPoint(otherPub512, peerPoint, sizeof(peerPoint));
			ownLen = publicPoint(pub512, ownPoint, sizeof(ownPoint));
			if (peerLen == 128 && ownLen == 128)
			{
				lenAB = tryDerive("selector 0x1026: 512 A with B point",
					MECH_GOSTR3410_12_DERIVE, priv512, param,
					flatParameter(param, MECH_KDF_GOST_256, peerPoint, 128, UKM_1, 8),
					&PLUGIN_RESULT, 0, ab, sizeof(ab));
				lenBA = tryDerive("selector 0x1026: 512 B with A point",
					MECH_GOSTR3410_12_DERIVE, otherPriv512, param,
					flatParameter(param, MECH_KDF_GOST_256, ownPoint, 128, UKM_1, 8),
					&PLUGIN_RESULT, 0, ba, sizeof(ba));
				if (lenAB > 0 && lenAB == lenBA)
					line("      selector 512-bit agreement equal: %s",
					     memcmp(ab, ba, (size_t)lenAB) == 0 ? "YES" : "NO");
			}
		}
	}
	destroy(pub512); destroy(priv512); destroy(otherPub512); destroy(otherPriv512);
}

/* A second output template mirrors the full SDK style. A successful result
 * here, unlike a mere error-code difference, gives an implementable vector. */
static void tryFullKdfResult(const char* what, CK_MECHANISM_TYPE mechanism,
			     CK_OBJECT_HANDLE base, const void* param, CK_ULONG paramLen,
			     CK_KEY_TYPE type, int requestedLen)
{
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ULONG valueLen = requestedLen < 0 ? 0 : (CK_ULONG)requestedLen;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_MODIFIABLE, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
		{ CKA_SENSITIVE, &no, sizeof(no) },
		{ CKA_VALUE_LEN, &valueLen, sizeof(valueLen) }
	};
	CK_MECHANISM mech = { mechanism, (CK_VOID_PTR)param, paramLen };
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_ULONG count = requestedLen < 0 ? 8 : 9;
	CK_RV rv = p11->C_DeriveKey(session, &mech, base, attrs, count, &key);
	showRv(what, rv);
	if (rv == CKR_OK && key != CK_INVALID_HANDLE) describeKey(key);
	destroy(key);
}

static void probeKdfOnBase(const char* baseName, CK_OBJECT_HANDLE base)
{
	static const CK_BYTE label[] = { 'k','d','f' };
	static const CK_BYTE seed[32] = {
		1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
		17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32
	};
	static const struct { const char* name; Result result; } outputs[] = {
		{ "GOST28147 no length", { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 0 } },
		{ "GOST28147 32 bytes", { CKK_GOST28147, 32, CK_FALSE, -1, -1, 0, 0 } },
		{ "generic no length", { CKK_GENERIC_SECRET, -1, CK_FALSE, -1, -1, 0, 0 } },
		{ "generic 32 bytes", { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 } },
		{ "Magma no length", { CKK_MAGMA, -1, CK_FALSE, -1, -1, 0, 0 } },
		{ "Kuznechik no length", { CKK_KUZNECHIK, -1, CK_FALSE, -1, -1, 0, 0 } },
		{ "GOST28147 token result", { CKK_GOST28147, -1, CK_TRUE, -1, -1, 0, 0 } }
	};
	ProbeKdfTreeParams tree = { sizeof(label), (CK_BYTE_PTR)label, 8,
		(CK_BYTE_PTR)seed, 8, 256, 0 };
	Result gost = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 0 };
	char name[160];
	size_t i;
	line("    KDF base: %s", baseName);
	for (i = 0; i < sizeof(outputs) / sizeof(outputs[0]); ++i)
	{
		snprintf(name, sizeof(name), "KDF_HMAC NULL, %s, %s", baseName, outputs[i].name);
		tryDerive(name, MECH_KDF_HMAC_256, base, NULL, 0, &outputs[i].result, 0, NULL, 0);
		snprintf(name, sizeof(name), "KDF_TREE SDK struct, %s, %s", baseName, outputs[i].name);
		tryDerive(name, MECH_KDF_TREE_256, base, &tree, sizeof(tree), &outputs[i].result, 0, NULL, 0);
	}
	tryFullKdfResult("KDF_HMAC NULL, full SDK-style GOST result", MECH_KDF_HMAC_256,
		base, NULL, 0, CKK_GOST28147, -1);
	tryFullKdfResult("KDF_TREE struct, full SDK-style GOST result", MECH_KDF_TREE_256,
		base, &tree, sizeof(tree), CKK_GOST28147, -1);
	tryFullKdfResult("KDF_TREE struct, full SDK-style generic 32 result", MECH_KDF_TREE_256,
		base, &tree, sizeof(tree), CKK_GENERIC_SECRET, 32);
	tryDerive("KDF_HMAC raw seed 8, GOST result", MECH_KDF_HMAC_256,
		base, seed, 8, &gost, 0, NULL, 0);
	tryDerive("KDF_HMAC raw seed 32, GOST result", MECH_KDF_HMAC_256,
		base, seed, 32, &gost, 0, NULL, 0);
	tryDerive("KDF_HMAC SDK tree struct (format hypothesis), GOST result",
		MECH_KDF_HMAC_256, base, &tree, sizeof(tree), &gost, 0, NULL, 0);
	if (strcmp(baseName, "SDK-generated GOST28147") != 0) return;
	/* The SDK documents this struct only for TREE; vary its fields on a
	 * generated key to distinguish a bad result template from a bad KDF. */
	for (i = 0; i < 7; ++i)
	{
		static const struct { CK_ULONG r, l, offset, seedLen; } fields[] = {
			{ 8, 256, 1, 8 }, { 8, 32, 0, 8 }, { 8, 512, 0, 8 },
			{ 16, 256, 0, 8 }, { 32, 256, 0, 8 },
			{ 8, 256, 0, 32 }, { 8, 256, 2, 8 }
		};
		tree.ulR = fields[i].r; tree.ulL = fields[i].l;
		tree.ulOffset = fields[i].offset; tree.ulSeedLength = fields[i].seedLen;
		snprintf(name, sizeof(name), "KDF_TREE GOST result R=%lu L=%lu offset=%lu seed=%lu",
			(unsigned long)tree.ulR, (unsigned long)tree.ulL,
			(unsigned long)tree.ulOffset, (unsigned long)tree.ulSeedLength);
		tryDerive(name, MECH_KDF_TREE_256, base, &tree, sizeof(tree), &gost, 0, NULL, 0);
	}
}

static void probeKdfMatrix(void)
{
	CK_BYTE known[32];
	CK_OBJECT_HANDLE key;
	size_t i;
	section("Direct KDF_HMAC and KDF_TREE: output templates, bases and parameter fields");
	for (i = 0; i < sizeof(known); ++i) known[i] = (CK_BYTE)i;
	key = createProbeSecret("KDF base: known GOST28147 session key, CKA_DERIVE TRUE",
		CKK_GOST28147, known, sizeof(known));
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known GOST28147", key);
		destroy(key);
	}
	key = generateSdkHmacKey();
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("SDK-generated GOST28147", key);
		destroy(key);
	}
	key = createProbeSecret("KDF base: known Magma session key, CKA_DERIVE TRUE",
		CKK_MAGMA, known, sizeof(known));
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known Magma", key);
		destroy(key);
	}
	key = createProbeSecret("KDF base: known Kuznechik session key, CKA_DERIVE TRUE",
		CKK_KUZNECHIK, known, sizeof(known));
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known Kuznechik", key);
		destroy(key);
	}
}

static void probeStandaloneVkoAndLegacy(void)
{
	typedef struct { const char* name; const void* bytes; CK_ULONG len; } ProbeForm;
	static const struct { const char* name; Result result; } outputs[] = {
		{ "GOST28147", { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 0 } },
		{ "generic 32", { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 } },
		{ "generic 64", { CKK_GENERIC_SECRET, 64, CK_FALSE, -1, -1, 0, 0 } },
		{ "Magma twin 64", { CKK_MAGMA_TWIN_KEY, 64, CK_FALSE, -1, -1, 0, 0 } },
		{ "Kuznechik twin 64", { CKK_KUZNECHIK_TWIN_KEY, 64, CK_FALSE, -1, -1, 0, 0 } }
	};
	CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
	CK_ECDH1_DERIVE_PARAMS ecdh = { CKD_NULL, 8, (CK_BYTE_PTR)UKM_1,
		128, (CK_BYTE_PTR)SAMPLE_512_POINT };
	CK_GOSTR3410_DERIVE_PARAMS gost;
	CK_BYTE flat[256], raw[136], valueM[128], valueK[128];
	long lenM, lenK;
	size_t i;
	char name[160];
	section("Standalone VKO-512, legacy GOST derive, and KEG twin-key control");
	showRv("generate 512-bit base key for standalone VKO",
		genPair("gap-standalone-512", 512, CURVE_512_C, sizeof(CURVE_512_C),
		CK_TRUE, &pub, &priv));
	if (priv != CK_INVALID_HANDLE)
	{
		ProbeForm forms[7];
		CK_ULONG flatLen = flatParameter(flat, CKD_NULL, SAMPLE_512_POINT, 128, UKM_1, 8);
		memcpy(raw, SAMPLE_512_POINT, 128);
		memcpy(raw + 128, UKM_1, 8);
		gost.kdf = CKD_NULL;
		gost.pPublicData = (CK_BYTE_PTR)SAMPLE_512_POINT;
		gost.ulPublicDataLen = 128;
		gost.pUKM = (CK_BYTE_PTR)UKM_1;
		gost.ulUKMLen = 8;
		forms[0] = (ProbeForm){ "ECDH1 struct", &ecdh, sizeof(ecdh) };
		forms[1] = (ProbeForm){ "GOST derive struct", &gost, sizeof(gost) };
		forms[2] = (ProbeForm){ "flat CKD_NULL", flat, flatLen };
		forms[3] = (ProbeForm){ "raw point", raw, 128 };
		forms[4] = (ProbeForm){ "raw point + UKM", raw, 136 };
		forms[5] = (ProbeForm){ "UKM only", UKM_1, 8 };
		forms[6] = (ProbeForm){ "NULL", NULL, 0 };
		for (i = 0; i < sizeof(forms) / sizeof(forms[0]); ++i)
		{
			size_t j;
			for (j = 0; j < sizeof(outputs) / sizeof(outputs[0]); ++j)
			{
				snprintf(name, sizeof(name), "VKO-512 %s -> %s", forms[i].name, outputs[j].name);
				tryDerive(name, MECH_VKO_512, priv, forms[i].bytes, forms[i].len,
					&outputs[j].result, 0, NULL, 0);
			}
		}
		lenM = tryDerive("KEG-512 -> Magma twin (control)", MECH_GOST_KEG,
			priv, &ecdh, sizeof(ecdh), &outputs[3].result, 0, valueM, sizeof(valueM));
		lenK = tryDerive("KEG-512 -> Kuznechik twin", MECH_GOST_KEG,
			priv, &ecdh, sizeof(ecdh), &outputs[4].result, 0, valueK, sizeof(valueK));
		if (lenM > 0 && lenM == lenK)
			line("      KEG twin values equal: %s",
			     memcmp(valueM, valueK, (size_t)lenM) == 0 ? "YES" : "NO");
		gost.kdf = MECH_KDF_GOST_256;
		tryDerive("legacy CKM_GOSTR3410_DERIVE, 512-bit GOST struct, selector 0x1026",
			MECH_GOSTR3410_DERIVE, priv, &gost, sizeof(gost), &outputs[0].result, 0, NULL, 0);
		tryDerive("legacy CKM_GOSTR3410_DERIVE, 512-bit ECDH1 struct",
			MECH_GOSTR3410_DERIVE, priv, &ecdh, sizeof(ecdh), &outputs[0].result, 0, NULL, 0);
	}
	destroy(pub); destroy(priv);
	if (basePriv != CK_INVALID_HANDLE)
	{
		CK_BYTE flat256[128];
		CK_ECDH1_DERIVE_PARAMS ecdh256 = { CKD_NULL, 8, (CK_BYTE_PTR)UKM_1,
			64, (CK_BYTE_PTR)SAMPLE_256_POINT };
		gost.kdf = CKD_NULL;
		gost.pPublicData = (CK_BYTE_PTR)SAMPLE_256_POINT;
		gost.ulPublicDataLen = 64;
		gost.pUKM = (CK_BYTE_PTR)UKM_1;
		gost.ulUKMLen = 8;
		tryDerive("legacy CKM_GOSTR3410_DERIVE, 256-bit ECDH1 struct",
			MECH_GOSTR3410_DERIVE, basePriv, &ecdh256, sizeof(ecdh256),
			&outputs[0].result, 0, NULL, 0);
		tryDerive("legacy CKM_GOSTR3410_DERIVE, 256-bit GOST struct, generic result",
			MECH_GOSTR3410_DERIVE, basePriv, &gost, sizeof(gost),
			&outputs[1].result, 0, NULL, 0);
		tryDerive("legacy CKM_GOSTR3410_DERIVE, 256-bit flat selector 0x1026",
			MECH_GOSTR3410_DERIVE, basePriv, flat256,
			flatParameter(flat256, MECH_KDF_GOST_256, SAMPLE_256_POINT, 64, UKM_1, 8),
			&outputs[0].result, 0, NULL, 0);
	}
}

static void probeGeneratedKeyAttributes(void)
{
	static const CK_BYTE id[] = { 'g','a','p','-','a','t','t','r' };
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_KEY_TYPE gost = CKK_GOST28147;
	CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
	CK_MECHANISM mech = { CKM_GOST28147_KEY_GEN, NULL_PTR, 0 };
	CK_ATTRIBUTE attrs[12] = {
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &gost, sizeof(gost) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_GOST28147_PARAMS, (CK_VOID_PTR)GOST28147_CP_A, sizeof(GOST28147_CP_A) },
		{ CKA_ENCRYPT, &yes, sizeof(yes) },
		{ CKA_DECRYPT, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_ID, (CK_VOID_PTR)id, sizeof(id) }
	};
	static const struct { const char* name; CK_ATTRIBUTE_TYPE type; CK_BBOOL value; } overrides[] = {
		{ "CKA_DERIVE FALSE", CKA_DERIVE, CK_FALSE },
		{ "CKA_DERIVE TRUE", CKA_DERIVE, CK_TRUE },
		{ "CKA_WRAP TRUE", CKA_WRAP, CK_TRUE },
		{ "CKA_UNWRAP TRUE", CKA_UNWRAP, CK_TRUE },
		{ "CKA_SENSITIVE FALSE", CKA_SENSITIVE, CK_FALSE },
		{ "CKA_EXTRACTABLE TRUE", CKA_EXTRACTABLE, CK_TRUE }
	};
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_RV rv;
	size_t i;
	section("GOST28147 key generation defaults and explicit attribute overrides");
	rv = p11->C_GenerateKey(session, &mech, attrs, 4, &key);
	showRv("minimal session-key template, no GOST parameter OID", rv);
	if (rv == CKR_OK) { describeKey(key); destroy(key); }
	key = CK_INVALID_HANDLE;
	rv = p11->C_GenerateKey(session, &mech, attrs, 5, &key);
	showRv("minimal session-key template with CryptoPro-A OID", rv);
	if (rv == CKR_OK) { describeKey(key); destroy(key); }
	key = CK_INVALID_HANDLE;
	rv = p11->C_GenerateKey(session, &mech, attrs, 9, &key);
	showRv("SDK template with ENCRYPT/DECRYPT and no HMAC flags", rv);
	if (rv == CKR_OK) { describeKey(key); destroy(key); }
	key = CK_INVALID_HANDLE;
	attrs[2].pValue = &yes;
	rv = p11->C_GenerateKey(session, &mech, attrs, 9, &key);
	showRv("SDK template but CKA_TOKEN TRUE", rv);
	if (rv == CKR_OK) { describeKey(key); destroy(key); }
	attrs[2].pValue = &no;
	for (i = 0; i < sizeof(overrides) / sizeof(overrides[0]); ++i)
	{
		CK_BBOOL requested = overrides[i].value;
		char name[120];
		key = CK_INVALID_HANDLE;
		attrs[9].type = overrides[i].type;
		attrs[9].pValue = &requested;
		attrs[9].ulValueLen = sizeof(requested);
		snprintf(name, sizeof(name), "SDK template plus %s", overrides[i].name);
		rv = p11->C_GenerateKey(session, &mech, attrs, 10, &key);
		showRv(name, rv);
		if (rv == CKR_OK) { describeKey(key); destroy(key); }
	}
	{
		CK_BYTE bytes[32];
		static const CK_ULONG lengths[] = { 2, 4, 8, 16, 31 };
		char name[80];
		for (i = 0; i < sizeof(bytes); ++i) bytes[i] = (CK_BYTE)i;
		for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
		{
			snprintf(name, sizeof(name), "create generic session secret of %lu bytes",
				(unsigned long)lengths[i]);
			key = createProbeSecret(name, CKK_GENERIC_SECRET, bytes, lengths[i]);
			destroy(key);
		}
	}
}

static CK_OBJECT_HANDLE createVendorTestKey(void)
{
	static CK_BYTE value[32] = {
		0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
		16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
	};
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_KEY_TYPE gost = CKK_GOST28147;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &gost, sizeof(gost) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_SENSITIVE, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
		{ CKA_ENCRYPT, &yes, sizeof(yes) },
		{ CKA_DECRYPT, &yes, sizeof(yes) },
		{ CKA_WRAP, &yes, sizeof(yes) },
		{ CKA_UNWRAP, &yes, sizeof(yes) },
		{ CKA_VALUE, value, sizeof(value) },
		{ CKA_GOST28147_PARAMS, (CK_VOID_PTR)GOST28147_CP_A, sizeof(GOST28147_CP_A) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 }
	};
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_RV rv = p11->C_CreateObject(session, attrs, sizeof(attrs) / sizeof(attrs[0]), &key);
	showRv("create disposable GOST28147 key with ENCRYPT/DECRYPT/WRAP/UNWRAP", rv);
	return rv == CKR_OK ? key : CK_INVALID_HANDLE;
}

static void tryVendorFss(const char* what, const void* param, CK_ULONG paramLen)
{
	CK_SESSION_HANDLE saved = session, temporary = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;
	CK_BYTE input[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
	CK_BYTE output[128], decrypted[128];
	CK_ULONG outputLen = sizeof(output), decryptedLen = sizeof(decrypted);
	CK_MECHANISM mechanism = { MECH_VENDOR_CBC_FSS, (CK_VOID_PTR)param, paramLen };
	CK_RV rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &temporary);
	showRv("open isolated session for CBC-FSS", rv);
	if (rv != CKR_OK) return;
	session = temporary;
	key = createVendorTestKey();
	if (key != CK_INVALID_HANDLE)
	{
		rv = p11->C_EncryptInit(session, &mechanism, key);
		showRv(what, rv);
		if (rv == CKR_OK)
		{
			rv = p11->C_Encrypt(session, input, sizeof(input), output, &outputLen);
			showRv("CBC-FSS encrypt 16 known bytes", rv);
			if (rv == CKR_OK && outputLen <= sizeof(output))
			{
				hexLine("CBC-FSS ciphertext", output, outputLen);
				rv = p11->C_DecryptInit(session, &mechanism, key);
				showRv("CBC-FSS decrypt init", rv);
				if (rv == CKR_OK)
				{
					rv = p11->C_Decrypt(session, output, outputLen, decrypted, &decryptedLen);
					showRv("CBC-FSS decrypt ciphertext", rv);
					if (rv == CKR_OK && decryptedLen <= sizeof(decrypted))
					{
						hexLine("CBC-FSS plaintext", decrypted, decryptedLen);
						line("      CBC-FSS round trip equal: %s",
						     decryptedLen == sizeof(input) &&
						     memcmp(input, decrypted, sizeof(input)) == 0 ? "YES" : "NO");
					}
				}
			}
		}
		else
		{
			CK_ULONG length = sizeof(decrypted);
			CK_RV decryptRv = p11->C_DecryptInit(session, &mechanism, key);
			showRv("CBC-FSS decrypt init, same parameter", decryptRv);
			if (decryptRv == CKR_OK)
			{
				decryptRv = p11->C_Decrypt(session, input, sizeof(input), decrypted, &length);
				showRv("CBC-FSS decrypt synthetic 16 bytes", decryptRv);
				if (decryptRv == CKR_OK && length <= sizeof(decrypted))
					hexLine("CBC-FSS output", decrypted, length);
			}
		}
		destroy(key);
	}
	p11->C_CloseSession(temporary);
	session = saved;
}

static void tryVendorImport(const char* what, CK_OBJECT_HANDLE unwrappingKey,
			    const void* param, CK_ULONG paramLen,
			    CK_BYTE* blob, CK_ULONG blobLen, CK_KEY_TYPE resultType)
{
	CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
	CK_BBOOL no = CK_FALSE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &secret, sizeof(secret) },
		{ CKA_KEY_TYPE, &resultType, sizeof(resultType) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 }
	};
	CK_MECHANISM mech = { MECH_VENDOR_SECURE_IMPORT, (CK_VOID_PTR)param, paramLen };
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_RV rv = p11->C_UnwrapKey(session, &mech, unwrappingKey, blob, blobLen,
		attrs, sizeof(attrs) / sizeof(attrs[0]), &key);
	showRv(what, rv);
	if (rv == CKR_OK && key != CK_INVALID_HANDLE) describeKey(key);
	destroy(key);
}

static void probeVendorMechanisms(void)
{
	CK_BYTE iv8[8] = { 1,2,3,4,5,6,7,8 };
	CK_BYTE iv16[16] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
	CK_BYTE synthetic[64] = { 0 };
	CK_BYTE wrapped[512];
	CK_OBJECT_HANDLE key, target;
	CK_MECHANISM wrap = { CKM_GOST28147_KEY_WRAP, NULL_PTR, 0 };
	CK_ULONG wrappedLen = sizeof(wrapped);
	CK_RV rv;
	size_t i;
	section("Vendor CBC-FSS and secure import: disposable keys and bounded inputs");
	for (i = 0; i < sizeof(synthetic); ++i) synthetic[i] = (CK_BYTE)i;
	tryVendorFss("CBC-FSS encrypt init, no parameter", NULL, 0);
	tryVendorFss("CBC-FSS encrypt init, 8-byte IV", iv8, sizeof(iv8));
	tryVendorFss("CBC-FSS encrypt init, 16-byte IV", iv16, sizeof(iv16));
	key = createVendorTestKey();
	if (key == CK_INVALID_HANDLE) return;
	tryVendorImport("secure import, NULL parameter, empty blob -> GOST28147",
		key, NULL, 0, synthetic, 0, CKK_GOST28147);
	tryVendorImport("secure import, NULL parameter, synthetic 32-byte blob -> GOST28147",
		key, NULL, 0, synthetic, 32, CKK_GOST28147);
	tryVendorImport("secure import, 8-byte IV, synthetic 64-byte blob -> generic",
		key, iv8, sizeof(iv8), synthetic, 64, CKK_GENERIC_SECRET);
	tryVendorImport("secure import, no unwrapping key, synthetic blob -> GOST28147",
		CK_INVALID_HANDLE, NULL, 0, synthetic, 32, CKK_GOST28147);
	tryVendorImport("secure import, NULL parameter, synthetic 16-byte blob -> GOST28147",
		key, NULL, 0, synthetic, 16, CKK_GOST28147);
	tryVendorImport("secure import, NULL parameter, synthetic 24-byte blob -> GOST28147",
		key, NULL, 0, synthetic, 24, CKK_GOST28147);
	tryVendorImport("secure import, NULL parameter, synthetic 40-byte blob -> GOST28147",
		key, NULL, 0, synthetic, 40, CKK_GOST28147);
	tryVendorImport("secure import, 16-byte parameter, synthetic 64-byte blob -> GOST28147",
		key, iv16, sizeof(iv16), synthetic, 64, CKK_GOST28147);
	tryVendorImport("secure import, 8-byte IV, synthetic 64-byte blob -> GOST28147",
		key, iv8, sizeof(iv8), synthetic, 64, CKK_GOST28147);
	target = createVendorTestKey();
	rv = p11->C_WrapKey(session, &wrap, key,
		target == CK_INVALID_HANDLE ? key : target, wrapped, &wrappedLen);
	showRv("ordinary GOST28147 wrap as a secure-import input candidate", rv);
	if (rv == CKR_OK && wrappedLen <= sizeof(wrapped))
	{
		hexLine("ordinary wrapped blob", wrapped, wrappedLen);
		tryVendorImport("secure import, ordinary wrapped blob -> GOST28147",
			key, NULL, 0, wrapped, wrappedLen, CKK_GOST28147);
		tryVendorImport("secure import, ordinary wrapped blob + 8-byte IV -> GOST28147",
			key, iv8, sizeof(iv8), wrapped, wrappedLen, CKK_GOST28147);
	}
	destroy(target);
	destroy(key);
}

/* The earlier legacy-derive checks used GOST-2012 keys. The official
 * CreateGOST34.10-2001.c and VKO-GOST34.10-2001.c samples instead use this
 * CryptoPro-A curve with the GOST R 34.11-94 digest OID. */
static CK_RV genPair2001(const char* id, CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE type = CKK_GOSTR3410;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_MECHANISM mech = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ATTRIBUTE publicAttrs[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)CURVE_CP_A, sizeof(CURVE_CP_A) },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)DIGEST_1994, sizeof(DIGEST_1994) }
	};
	CK_ATTRIBUTE privateAttrs[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_DERIVE, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)CURVE_CP_A, sizeof(CURVE_CP_A) },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)DIGEST_1994, sizeof(DIGEST_1994) }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech, publicAttrs,
		sizeof(publicAttrs) / sizeof(publicAttrs[0]), privateAttrs,
		sizeof(privateAttrs) / sizeof(privateAttrs[0]), pub, priv);
}

static void probeSlotVersions(void)
{
	CK_SLOT_ID slots[MAX_SLOTS];
	CK_ULONG count = MAX_SLOTS, i;
	CK_RV rv;
	section("Every slot: reader versions, flags and token presence");
	rv = p11->C_GetSlotList(CK_FALSE, slots, &count);
	showRv("C_GetSlotList(tokenPresent=FALSE)", rv);
	if (rv != CKR_OK) return;
	line("    slot count = %lu", (unsigned long)count);
	for (i = 0; i < count && i < MAX_SLOTS; ++i)
	{
		CK_SLOT_INFO info;
		CK_TOKEN_INFO token;
		rv = p11->C_GetSlotInfo(slots[i], &info);
		line("    slot %lu C_GetSlotInfo rv=%s (0x%lx)",
			(unsigned long)slots[i], rvName(rv), (unsigned long)rv);
		if (rv == CKR_OK)
			line("      description='%.64s' manufacturer='%.32s' flags=0x%lx hardware=%u.%u firmware=%u.%u",
				info.slotDescription, info.manufacturerID, (unsigned long)info.flags,
				(unsigned)info.hardwareVersion.major, (unsigned)info.hardwareVersion.minor,
				(unsigned)info.firmwareVersion.major, (unsigned)info.firmwareVersion.minor);
		rv = p11->C_GetTokenInfo(slots[i], &token);
		line("      C_GetTokenInfo rv=%s (0x%lx)%s", rvName(rv), (unsigned long)rv,
			rv == CKR_OK ? " token present" : "");
	}
	if (count > MAX_SLOTS) line("    slot list truncated to %d entries", MAX_SLOTS);
}

static void probeGenericBoundary(void)
{
	CK_BYTE value[40];
	CK_ULONG n;
	CK_OBJECT_HANDLE key;
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_KEY_TYPE type = CKK_GENERIC_SECRET;
	CK_BBOOL no = CK_FALSE;
	CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL_PTR, 0 };
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_VALUE_LEN, &n, sizeof(n) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 }
	};
	CK_RV rv;
	char name[96];
	section("Exact short generic-secret boundary: C_CreateObject and C_GenerateKey");
	for (n = 0; n <= 34; ++n)
	{
		CK_ULONG j;
		for (j = 0; j < n; ++j) value[j] = (CK_BYTE)j;
		snprintf(name, sizeof(name), "C_CreateObject generic secret length %lu", (unsigned long)n);
		key = createProbeSecret(name, CKK_GENERIC_SECRET, value, n);
		destroy(key);
		key = CK_INVALID_HANDLE;
		rv = p11->C_GenerateKey(session, &mech, attrs,
			sizeof(attrs) / sizeof(attrs[0]), &key);
		snprintf(name, sizeof(name), "C_GenerateKey generic secret length %lu", (unsigned long)n);
		showRv(name, rv);
		destroy(key);
	}
}

static void probeLegacySdk2001(void)
{
	static const CK_BYTE ukm16[16] = {
		1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
	};
	CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
	CK_BYTE pointA[128], pointB[128], outAB[64], outBA[64];
	CK_GOSTR3410_DERIVE_PARAMS params;
	CK_RV rv;
	long lenA, lenB, resultAB, resultBA;
	Result generic = { CKK_GENERIC_SECRET, 32, CK_FALSE, -1, -1, 0, 0 };
	section("Exact SDK VKO-GOST34.10-2001: two GOST-2001 key pairs and structured parameter");
	rv = genPair2001("final-2001-a", &pubA, &privA);
	showRv("generate first SDK GOST-2001 key pair (94 digest OID)", rv);
	if (rv != CKR_OK) goto done;
	rv = genPair2001("final-2001-b", &pubB, &privB);
	showRv("generate second SDK GOST-2001 key pair (94 digest OID)", rv);
	if (rv != CKR_OK) goto done;
	lenA = publicPoint(pubA, pointA, sizeof(pointA));
	lenB = publicPoint(pubB, pointB, sizeof(pointB));
	if (lenA != 64 || lenB != 64) { line("    public point length differs from SDK 64 bytes"); goto done; }
	hexLine("GOST-2001 public A", pointA, 64);
	hexLine("GOST-2001 public B", pointB, 64);
	params.kdf = CKD_CPDIVERSIFY_KDF;
	params.pPublicData = pointB;
	params.ulPublicDataLen = 64;
	params.pUKM = (CK_BYTE_PTR)UKM_1;
	params.ulUKMLen = 8;
	resultAB = tryDerive("SDK-2001 CPDIVERSIFY: A with B point, GOST28147 result",
		MECH_GOSTR3410_DERIVE, privA, &params, sizeof(params),
		&PLUGIN_RESULT, 1, outAB, sizeof(outAB));
	params.pPublicData = pointA;
	resultBA = tryDerive("SDK-2001 CPDIVERSIFY: B with A point, GOST28147 result",
		MECH_GOSTR3410_DERIVE, privB, &params, sizeof(params),
		&PLUGIN_RESULT, 1, outBA, sizeof(outBA));
	if (resultAB > 0 && (size_t)resultAB <= sizeof(outAB) && resultAB == resultBA)
		line("      SDK-2001 agreement equal: %s",
			memcmp(outAB, outBA, (size_t)resultAB) == 0 ? "YES" : "NO");
	params.pPublicData = pointB;
	tryFullKdfResult("SDK-2001 CPDIVERSIFY: exact eight-attribute result",
		MECH_GOSTR3410_DERIVE, privA, &params, sizeof(params), CKK_GOST28147, -1);
	params.kdf = CKD_NULL;
	tryDerive("SDK-2001 CKD_NULL", MECH_GOSTR3410_DERIVE, privA,
		&params, sizeof(params), &PLUGIN_RESULT, 0, NULL, 0);
	params.kdf = CKD_CPDIVERSIFY_KDF;
	params.pUKM = (CK_BYTE_PTR)ukm16;
	params.ulUKMLen = 16;
	tryDerive("SDK-2001 CPDIVERSIFY, 16-byte UKM", MECH_GOSTR3410_DERIVE,
		privA, &params, sizeof(params), &PLUGIN_RESULT, 0, NULL, 0);
	params.pUKM = (CK_BYTE_PTR)UKM_1;
	params.ulUKMLen = 8;
	tryDerive("SDK-2001 CPDIVERSIFY, generic result", MECH_GOSTR3410_DERIVE,
		privA, &params, sizeof(params), &generic, 0, NULL, 0);
done:
	destroy(pubB); destroy(privB); destroy(pubA); destroy(privA);
}

static CK_OBJECT_HANDLE createKnownTwin(CK_KEY_TYPE type, const CK_BYTE* value)
{
	CK_OBJECT_CLASS cls = CKO_SECRET_KEY;
	CK_BBOOL no = CK_FALSE, yes = CK_TRUE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_ATTRIBUTE attrs[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_SENSITIVE, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) },
		{ CKA_DERIVE, &yes, sizeof(yes) },
		{ CKA_VALUE, (CK_VOID_PTR)value, 64 },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 }
	};
	CK_RV rv = p11->C_CreateObject(session, attrs,
		sizeof(attrs) / sizeof(attrs[0]), &key);
	showRv(type == CKK_MAGMA_TWIN_KEY ? "create known Magma twin-key, CKA_DERIVE TRUE" :
		"create known Kuznechik twin-key, CKA_DERIVE TRUE", rv);
	return rv == CKR_OK ? key : CK_INVALID_HANDLE;
}

static void probeTwinKdf(void)
{
	CK_BYTE known[64], seed[32];
	CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
	CK_ECDH1_DERIVE_PARAMS keg;
	CK_KEY_DERIVATION_STRING_DATA stringParam;
	Result twin = { CKK_MAGMA_TWIN_KEY, 64, CK_FALSE, -1, -1, 0, 1 };
	Result gost = { CKK_GOST28147, -1, CK_FALSE, -1, -1, 0, 0 };
	CK_RV rv;
	CK_ULONG i;
	section("Direct KDFs on known 64-byte twin keys and a KEG-produced twin key");
	for (i = 0; i < 64; ++i) known[i] = (CK_BYTE)i;
	for (i = 0; i < 32; ++i) seed[i] = (CK_BYTE)(i + 1);
	stringParam = (CK_KEY_DERIVATION_STRING_DATA){ seed, 32 };
	key = createKnownTwin(CKK_MAGMA_TWIN_KEY, known);
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known Magma twin 64", key);
		tryDerive("KDF_HMAC CK_KEY_DERIVATION_STRING_DATA on Magma twin",
			MECH_KDF_HMAC_256, key, &stringParam, sizeof(stringParam),
			&gost, 0, NULL, 0);
		destroy(key);
	}
	key = createKnownTwin(CKK_KUZNECHIK_TWIN_KEY, known);
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known Kuznechik twin 64", key);
		destroy(key);
	}
	key = createProbeSecret("create known generic 64-byte KDF base",
		CKK_GENERIC_SECRET, known, 64);
	if (key != CK_INVALID_HANDLE)
	{
		probeKdfOnBase("known generic 64", key);
		destroy(key);
	}
	rv = genPair("final-kdf-512", 512, CURVE_512_C, sizeof(CURVE_512_C),
		CK_TRUE, &pub, &priv);
	showRv("generate GOST-2012/512 pair for real KEG twin KDF base", rv);
	if (rv != CKR_OK) goto done;
	keg.kdf = CKD_NULL;
	keg.ulSharedDataLen = 32;
	keg.pSharedData = seed;
	keg.ulPublicDataLen = sizeof(SAMPLE_512_POINT);
	keg.pPublicData = (CK_BYTE_PTR)SAMPLE_512_POINT;
	rv = derive(MECH_GOST_KEG, priv, &keg, sizeof(keg), &twin, &key);
	showRv("KEG-512 -> Magma twin with CKA_DERIVE TRUE", rv);
	if (rv != CKR_OK)
	{
		twin.deriveAttribute = 0;
		rv = derive(MECH_GOST_KEG, priv, &keg, sizeof(keg), &twin, &key);
		showRv("KEG-512 -> Magma twin, omitted CKA_DERIVE", rv);
	}
	if (rv == CKR_OK && key != CK_INVALID_HANDLE)
	{
		describeKey(key);
		probeKdfOnBase("KEG-produced Magma twin 64", key);
		tryDerive("KDF_HMAC CK_KEY_DERIVATION_STRING_DATA on KEG twin",
			MECH_KDF_HMAC_256, key, &stringParam, sizeof(stringParam),
			&gost, 0, NULL, 0);
		destroy(key);
	}
done:
	destroy(pub); destroy(priv);
}

static void probeVko512Bounds(void)
{
	static const CK_ULONG lengths[] = { 0, 1, 4, 7, 8, 9, 16, 32 };
	CK_BYTE ukm[32], zero[32] = { 0 };
	CK_ECDH1_DERIVE_PARAMS params;
	CK_OBJECT_HANDLE pub = CK_INVALID_HANDLE, priv = CK_INVALID_HANDLE;
	Result twin = { CKK_MAGMA_TWIN_KEY, 64, CK_FALSE, -1, -1, 0, 0 };
	CK_RV rv;
	CK_ULONG i;
	char name[100];
	section("Standalone VKO-512: UKM, zero, result length and base-key boundaries");
	for (i = 0; i < 32; ++i) ukm[i] = (CK_BYTE)(i + 1);
	rv = genPair("final-vko512", 512, CURVE_512_C, sizeof(CURVE_512_C),
		CK_TRUE, &pub, &priv);
	showRv("generate disposable 512-bit VKO base", rv);
	if (rv != CKR_OK) return;
	params.kdf = CKD_NULL;
	params.pSharedData = ukm;
	params.ulPublicDataLen = sizeof(SAMPLE_512_POINT);
	params.pPublicData = (CK_BYTE_PTR)SAMPLE_512_POINT;
	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
	{
		params.ulSharedDataLen = lengths[i];
		snprintf(name, sizeof(name), "standalone VKO-512 UKM length %lu",
			(unsigned long)lengths[i]);
		tryDerive(name, MECH_VKO_512, priv, &params, sizeof(params),
			&twin, 0, NULL, 0);
	}
	params.pSharedData = zero;
	params.ulSharedDataLen = 8;
	tryDerive("standalone VKO-512 zero 8-byte UKM", MECH_VKO_512,
		priv, &params, sizeof(params), &twin, 0, NULL, 0);
	params.pSharedData = ukm;
	params.kdf = MECH_KDF_GOST_256;
	tryDerive("standalone VKO-512 non-NULL KDF selector", MECH_VKO_512,
		priv, &params, sizeof(params), &twin, 0, NULL, 0);
	params.kdf = CKD_NULL;
	twin.valueLen = 32;
	tryDerive("standalone VKO-512 CKA_VALUE_LEN=32", MECH_VKO_512,
		priv, &params, sizeof(params), &twin, 0, NULL, 0);
	twin.valueLen = 64;
	twin.token = CK_TRUE;
	tryDerive("standalone VKO-512 token result", MECH_VKO_512,
		priv, &params, sizeof(params), &twin, 0, NULL, 0);
	twin.token = CK_FALSE;
	if (basePriv != CK_INVALID_HANDLE)
		tryDerive("standalone VKO-512 with 256-bit base key", MECH_VKO_512,
			basePriv, &params, sizeof(params), &twin, 0, NULL, 0);
	destroy(pub); destroy(priv);
}

static void probeFssOneShot(CK_ULONG inputLen, const void* iv, CK_ULONG ivLen)
{
	CK_SESSION_HANDLE saved = session, temporary = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;
	CK_MECHANISM mech = { MECH_VENDOR_CBC_FSS, (CK_VOID_PTR)iv, ivLen };
	CK_BYTE input[512], cipher[544], plain[544];
	CK_ULONG i, cipherLen = sizeof(cipher), plainLen = sizeof(plain);
	CK_RV rv;
	char name[100];
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &temporary);
	if (rv != CKR_OK) { showRv("open CBC-FSS length-test session", rv); return; }
	session = temporary;
	key = createVendorTestKey();
	if (key == CK_INVALID_HANDLE) goto done;
	for (i = 0; i < inputLen; ++i) input[i] = (CK_BYTE)i;
	rv = p11->C_EncryptInit(session, &mech, key);
	snprintf(name, sizeof(name), "CBC-FSS %lu-byte plaintext, IV length %lu: EncryptInit",
		(unsigned long)inputLen, (unsigned long)ivLen);
	showRv(name, rv);
	if (rv != CKR_OK) goto clean_key;
	rv = p11->C_Encrypt(session, input, inputLen, cipher, &cipherLen);
	showRv("CBC-FSS C_Encrypt", rv);
	if (rv != CKR_OK || cipherLen > sizeof(cipher)) goto clean_key;
	hexLine("CBC-FSS ciphertext", cipher, cipherLen);
	rv = p11->C_DecryptInit(session, &mech, key);
	showRv("CBC-FSS C_DecryptInit", rv);
	if (rv != CKR_OK) goto clean_key;
	rv = p11->C_Decrypt(session, cipher, cipherLen, plain, &plainLen);
	showRv("CBC-FSS C_Decrypt", rv);
	if (rv == CKR_OK && plainLen <= sizeof(plain))
		line("      CBC-FSS round trip equal: %s (plaintext %lu bytes)",
			plainLen == inputLen && memcmp(plain, input, (size_t)inputLen) == 0 ?
			"YES" : "NO", (unsigned long)plainLen);
clean_key:
	destroy(key);
done:
	p11->C_CloseSession(temporary);
	session = saved;
}

static void probeFssMultipart(void)
{
	CK_SESSION_HANDLE saved = session, temporary = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;
	CK_BYTE iv[8] = { 1,2,3,4,5,6,7,8 };
	CK_BYTE input[40], cipher[96], plain[96];
	CK_ULONG i, n, total = 0, recovered = 0;
	CK_MECHANISM mech = { MECH_VENDOR_CBC_FSS, iv, sizeof(iv) };
	CK_RV rv;
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &temporary);
	showRv("open isolated CBC-FSS multipart session", rv);
	if (rv != CKR_OK) return;
	session = temporary;
	key = createVendorTestKey();
	if (key == CK_INVALID_HANDLE) goto done;
	for (i = 0; i < sizeof(input); ++i) input[i] = (CK_BYTE)(i + 1);
	rv = p11->C_EncryptInit(session, &mech, key);
	showRv("CBC-FSS multipart C_EncryptInit", rv);
	if (rv != CKR_OK) goto clean_key;
	n = sizeof(cipher) - total;
	rv = p11->C_EncryptUpdate(session, input, 3, cipher + total, &n);
	showRv("CBC-FSS C_EncryptUpdate 3 bytes", rv);
	if (rv != CKR_OK || n > sizeof(cipher) - total) goto clean_key;
	total += n;
	n = sizeof(cipher) - total;
	rv = p11->C_EncryptUpdate(session, input + 3, 13, cipher + total, &n);
	showRv("CBC-FSS C_EncryptUpdate 13 bytes", rv);
	if (rv != CKR_OK || n > sizeof(cipher) - total) goto clean_key;
	total += n;
	n = sizeof(cipher) - total;
	rv = p11->C_EncryptUpdate(session, input + 16, 24, cipher + total, &n);
	showRv("CBC-FSS C_EncryptUpdate 24 bytes", rv);
	if (rv != CKR_OK || n > sizeof(cipher) - total) goto clean_key;
	total += n;
	n = sizeof(cipher) - total;
	rv = p11->C_EncryptFinal(session, cipher + total, &n);
	showRv("CBC-FSS C_EncryptFinal", rv);
	if (rv != CKR_OK || n > sizeof(cipher) - total) goto clean_key;
	total += n;
	hexLine("CBC-FSS multipart ciphertext", cipher, total);
	rv = p11->C_DecryptInit(session, &mech, key);
	showRv("CBC-FSS multipart C_DecryptInit", rv);
	if (rv != CKR_OK) goto clean_key;
	n = sizeof(plain) - recovered;
	rv = p11->C_DecryptUpdate(session, cipher, 5, plain + recovered, &n);
	showRv("CBC-FSS C_DecryptUpdate 5 bytes", rv);
	if (rv != CKR_OK || n > sizeof(plain) - recovered) goto clean_key;
	recovered += n;
	n = sizeof(plain) - recovered;
	rv = p11->C_DecryptUpdate(session, cipher + 5, total - 5, plain + recovered, &n);
	showRv("CBC-FSS C_DecryptUpdate remainder", rv);
	if (rv != CKR_OK || n > sizeof(plain) - recovered) goto clean_key;
	recovered += n;
	n = sizeof(plain) - recovered;
	rv = p11->C_DecryptFinal(session, plain + recovered, &n);
	showRv("CBC-FSS C_DecryptFinal", rv);
	if (rv != CKR_OK || n > sizeof(plain) - recovered) goto clean_key;
	recovered += n;
	line("      CBC-FSS multipart round trip equal: %s",
		recovered == sizeof(input) && memcmp(plain, input, sizeof(input)) == 0 ?
		"YES" : "NO");
clean_key:
	destroy(key);
done:
	p11->C_CloseSession(temporary);
	session = saved;
}

static void probeFssBufferAndErrors(void)
{
	static const CK_ULONG invalidLengths[] = { 0, 1, 7, 8, 9, 16 };
	CK_SESSION_HANDLE saved = session, temporary = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE key;
	CK_BYTE iv[8] = { 1,2,3,4,5,6,7,8 };
	CK_BYTE input[16], cipher[64], output[64];
	CK_ULONG i, needed = 0, cipherLen, outLen;
	CK_MECHANISM mech = { MECH_VENDOR_CBC_FSS, iv, sizeof(iv) };
	CK_RV rv;
	char name[96];
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
		NULL_PTR, NULL_PTR, &temporary);
	showRv("open isolated CBC-FSS error-test session", rv);
	if (rv != CKR_OK) return;
	session = temporary;
	key = createVendorTestKey();
	if (key == CK_INVALID_HANDLE) goto done;
	for (i = 0; i < sizeof(input); ++i) input[i] = (CK_BYTE)i;
	rv = p11->C_EncryptInit(session, &mech, key);
	showRv("CBC-FSS length-query EncryptInit", rv);
	if (rv != CKR_OK) goto clean_key;
	rv = p11->C_Encrypt(session, input, sizeof(input), NULL_PTR, &needed);
	showRv("CBC-FSS C_Encrypt output-length query", rv);
	line("      required ciphertext length: %lu", (unsigned long)needed);
	if (rv != CKR_OK || needed == 0 || needed > sizeof(cipher)) goto clean_key;
	cipherLen = needed - 1;
	rv = p11->C_Encrypt(session, input, sizeof(input), cipher, &cipherLen);
	showRv("CBC-FSS C_Encrypt one-byte-short output buffer", rv);
	line("      reported required length after short buffer: %lu", (unsigned long)cipherLen);
	if (rv == CKR_BUFFER_TOO_SMALL)
	{
		cipherLen = sizeof(cipher);
		rv = p11->C_Encrypt(session, input, sizeof(input), cipher, &cipherLen);
		showRv("CBC-FSS C_Encrypt after short buffer", rv);
	}
	if (rv != CKR_OK || cipherLen > sizeof(cipher)) goto clean_key;
	hexLine("CBC-FSS valid ciphertext for padding tests", cipher, cipherLen);
	for (i = 0; i < sizeof(invalidLengths) / sizeof(invalidLengths[0]); ++i)
	{
		CK_BYTE bad[64] = { 0 };
		CK_ULONG len = invalidLengths[i];
		outLen = sizeof(output);
		rv = p11->C_DecryptInit(session, &mech, key);
		if (rv != CKR_OK) { showRv("CBC-FSS invalid-ciphertext DecryptInit", rv); break; }
		snprintf(name, sizeof(name), "CBC-FSS decrypt synthetic ciphertext length %lu",
			(unsigned long)len);
		rv = p11->C_Decrypt(session, bad, len, output, &outLen);
		showRv(name, rv);
		if (rv == CKR_OK && outLen <= sizeof(output)) hexLine("decrypted synthetic", output, outLen);
	}
	cipher[cipherLen - 1] ^= 1;
	outLen = sizeof(output);
	rv = p11->C_DecryptInit(session, &mech, key);
	showRv("CBC-FSS tampered ciphertext DecryptInit", rv);
	if (rv == CKR_OK)
	{
		rv = p11->C_Decrypt(session, cipher, cipherLen, output, &outLen);
		showRv("CBC-FSS decrypt ciphertext with flipped last byte", rv);
		if (rv == CKR_OK && outLen <= sizeof(output)) hexLine("tampered plaintext", output, outLen);
	}
clean_key:
	destroy(key);
done:
	p11->C_CloseSession(temporary);
	session = saved;
}

static void probeFssExtended(void)
{
	static const CK_ULONG lengths[] = { 0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 127, 128, 256 };
	CK_BYTE iv[8] = { 1,2,3,4,5,6,7,8 };
	CK_ULONG i;
	section("CBC-FSS length boundaries, long messages and multipart");
	for (i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
		probeFssOneShot(lengths[i], iv, sizeof(iv));
	probeFssOneShot(31, NULL, 0);
	probeFssMultipart();
	probeFssBufferAndErrors();
}

static CK_RV genPairForJournal(const char* id, int modern,
	CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE type = CKK_GOSTR3410;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	const CK_BYTE* curve = modern ? CURVE_TC26_A : CURVE_CP_A;
	CK_ULONG curveLen = modern ? sizeof(CURVE_TC26_A) : sizeof(CURVE_CP_A);
	const CK_BYTE* digest = modern ? DIGEST_256 : DIGEST_1994;
	CK_ULONG digestLen = modern ? sizeof(DIGEST_256) : sizeof(DIGEST_1994);
	CK_MECHANISM mech = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_ATTRIBUTE publicAttrs[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)digest, digestLen }
	};
	CK_ATTRIBUTE privateAttrs[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &type, sizeof(type) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR)PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR)id, (CK_ULONG)strlen(id) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR)curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR)digest, digestLen }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech, publicAttrs,
		sizeof(publicAttrs) / sizeof(publicAttrs[0]), privateAttrs,
		sizeof(privateAttrs) / sizeof(privateAttrs[0]), pub, priv);
}

static void readProbeJournal(const char* when)
{
	CK_BYTE* buf;
	CK_ULONG length = 0, capacity;
	CK_RV rv;
	if (ex == NULL_PTR || ex->C_EX_GetJournal == NULL_PTR) return;
	rv = ex->C_EX_GetJournal(theSlot, NULL_PTR, &length);
	showRv(when, rv);
	if (rv != CKR_OK) return;
	line("      journal length query: %lu bytes", (unsigned long)length);
	if (length > 65536) { line("      journal exceeds 65536-byte probe limit"); return; }
	capacity = length;
	buf = malloc(length ? (size_t)length : 1);
	if (buf == NULL) { line("      cannot allocate journal buffer"); return; }
	rv = ex->C_EX_GetJournal(theSlot, buf, &length);
	showRv("C_EX_GetJournal content", rv);
	if (rv == CKR_OK && length <= capacity) hexLine("journal TLV", buf, length);
	free(buf);
}

static void signForJournal(const char* what, CK_OBJECT_HANDLE key)
{
	CK_BYTE digest[32], signature[128];
	CK_ULONG length = sizeof(signature), i;
	CK_MECHANISM mech = { CKM_GOSTR3410, NULL_PTR, 0 };
	CK_RV rv;
	for (i = 0; i < sizeof(digest); ++i) digest[i] = (CK_BYTE)(i + 1);
	rv = p11->C_SignInit(session, &mech, key);
	showRv(what, rv);
	if (rv == CKR_OK)
	{
		rv = p11->C_Sign(session, digest, sizeof(digest), signature, &length);
		showRv("C_Sign fixed 32-byte digest", rv);
		if (rv == CKR_OK && length <= sizeof(signature))
			hexLine("signature", signature, length);
	}
	readProbeJournal(what);
}

static void probeJournalIds(void)
{
	CK_OBJECT_HANDLE pubA = CK_INVALID_HANDLE, privA = CK_INVALID_HANDLE;
	CK_OBJECT_HANDLE pubB = CK_INVALID_HANDLE, privB = CK_INVALID_HANDLE;
	CK_RV rv;
	section("Journal tag 85: same key twice, then another key with a different CKA_ID");
	if (ex == NULL_PTR || ex->C_EX_GetJournal == NULL_PTR)
	{ line("    extended journal function unavailable"); return; }
	readProbeJournal("journal before new signatures");
	rv = genPairForJournal("final-journal-A", 0, &pubA, &privA);
	showRv("generate legacy journal key A, ID 'final-journal-A'", rv);
	if (rv != CKR_OK)
	{
		rv = genPairForJournal("final-journal-A", 1, &pubA, &privA);
		showRv("generate modern journal key A, ID 'final-journal-A'", rv);
	}
	if (rv != CKR_OK) goto done;
	rv = genPairForJournal("final-journal-B", 0, &pubB, &privB);
	showRv("generate legacy journal key B, ID 'final-journal-B'", rv);
	if (rv != CKR_OK)
	{
		rv = genPairForJournal("final-journal-B", 1, &pubB, &privB);
		showRv("generate modern journal key B, ID 'final-journal-B'", rv);
	}
	if (rv != CKR_OK) goto done;
	signForJournal("journal: sign A first time", privA);
	signForJournal("journal: sign A second time", privA);
	signForJournal("journal: sign B", privB);
done:
	destroy(pubB); destroy(privB); destroy(pubA); destroy(privA);
}

/* ---- main ---------------------------------------------------------------- */

static int loadLibrary(void)
{
	CK_C_GetFunctionList getList;
	CK_C_EX_GetFunctionListExtended getExtended;
	libraryHandle = dlopen(opt.module, RTLD_NOW);
	if (libraryHandle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 0; }
	getList = (CK_C_GetFunctionList)dlsym(libraryHandle, "C_GetFunctionList");
	if (getList == NULL || getList(&p11) != CKR_OK || p11 == NULL_PTR)
	{ fprintf(stderr, "C_GetFunctionList missing or failed\n"); return 0; }
	getExtended = (CK_C_EX_GetFunctionListExtended)
		dlsym(libraryHandle, "C_EX_GetFunctionListExtended");
	if (getExtended != NULL && getExtended(&ex) != CKR_OK) ex = NULL_PTR;
	return 1;
}

static const char* argValue(int argc, char** argv, int* i)
{
	if (*i + 1 >= argc) { fprintf(stderr, "%s needs a value\n", argv[*i]); exit(2); }
	return argv[++(*i)];
}

static int chooseSlot(const CK_SLOT_ID* slots, CK_ULONG count)
{
	CK_ULONG i;
	char answer[64], *end;
	if (opt.slotGiven)
	{
		for (i = 0; i < count; ++i) if (slots[i] == opt.slot) break;
		if (i == count) { fprintf(stderr, "requested slot has no token\n"); return 0; }
		theSlot = opt.slot;
		return 1;
	}
	if (!opt.interactive || count == 1) { theSlot = slots[0]; return 1; }
	fprintf(terminal, "Available tokens:\n");
	for (i = 0; i < count; ++i)
	{
		CK_TOKEN_INFO info;
		if (p11->C_GetTokenInfo(slots[i], &info) == CKR_OK)
			fprintf(terminal, "  slot %lu: %.32s (%.16s)\n",
				(unsigned long)slots[i], info.label, info.model);
		else fprintf(terminal, "  slot %lu: token info unavailable\n", (unsigned long)slots[i]);
	}
	for (;;)
	{
		unsigned long requested;
		if (!promptText("Slot number (Enter = first): ", answer, sizeof(answer))) return 0;
		if (answer[0] == '\0') { theSlot = slots[0]; return 1; }
		errno = 0;
		requested = strtoul(answer, &end, 0);
		if (errno == 0 && end != answer && *end == '\0')
			for (i = 0; i < count; ++i)
				if (slots[i] == (CK_SLOT_ID)requested && (unsigned long)slots[i] == requested)
				{ theSlot = slots[i]; return 1; }
		fprintf(terminal, "Choose a listed slot.\n");
	}
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
		else if (strcmp(argv[i], "--interactive") == 0) opt.interactive = 1;
		else if (strcmp(argv[i], "--log") == 0) opt.output = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--user-pin") == 0) opt.userPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--user-pin-env") == 0) opt.userPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--slot") == 0)
		{
			opt.slot = strtoul(argValue(argc, argv, &i), NULL, 0);
			opt.slotGiven = 1;
		}
		else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
	}
	if (!opt.interactive && opt.output != NULL)
	{
		fprintf(stderr, "--log requires --interactive\n");
		return 2;
	}
	if (opt.interactive)
	{
		terminal = fopen("/dev/tty", "r+");
		if (terminal == NULL && isatty(STDIN_FILENO))
		{
			int fd = dup(STDIN_FILENO);
			if (fd >= 0) terminal = fdopen(fd, "r+");
			if (terminal == NULL && fd >= 0) close(fd);
		}
		if (terminal == NULL) { fprintf(stderr, "--interactive needs a terminal\n"); return 2; }
		if (opt.module == NULL)
		{
			if (!promptText("Absolute path to PKCS #11 module: ", modulePath, sizeof(modulePath)) ||
			    modulePath[0] != '/') return 2;
			opt.module = modulePath;
		}
	}
	if (opt.module == NULL || (!opt.interactive && opt.userPin == NULL))
	{
		fprintf(stderr,
			"usage: %s <path to librtpkcs11ecp.so> [options]\n"
			"  --interactive          prompt for module, slot and hidden PIN; write one log\n"
			"  --log FILE             log path for --interactive (must not exist)\n"
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
	if (!chooseSlot(slots, slotCount)) return 1;
	if (opt.interactive)
	{
		if (opt.userPin == NULL && !promptPin()) { fprintf(stderr, "PIN input failed\n"); return 1; }
		if (opt.userPin == NULL) opt.userPin = promptedPin;
		if (!startLog()) { fprintf(stderr, "cannot start log\n"); return 1; }
	}
	line("rutoken-derive-probe: CKM_GOSTR3410_12_DERIVE on slot %lu", (unsigned long)theSlot);
	rv = p11->C_OpenSession(theSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK) { fprintf(stderr, "C_OpenSession: 0x%lx\n", (unsigned long)rv); return 1; }
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)opt.userPin, (CK_ULONG)strlen(opt.userPin));
	if (opt.userPin == promptedPin) memset(promptedPin, 0, sizeof(promptedPin));
	if (rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN)
	{
		line("C_Login: %s (0x%lx); nothing was changed", rvName(rv), (unsigned long)rv);
		if (terminal != NULL) fprintf(terminal, "Login failed: %s; see %s\n", rvName(rv), logPath);
		p11->C_CloseSession(session);
		p11->C_Finalize(NULL_PTR);
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
	if (opt.interactive)
	{
		probeSelectorKdf();
		probeKdfMatrix();
		probeStandaloneVkoAndLegacy();
		probeGeneratedKeyAttributes();
		probeVendorMechanisms();
		probeSlotVersions();
		probeGenericBoundary();
		probeLegacySdk2001();
		probeTwinKdf();
		probeVko512Bounds();
		probeFssExtended();
		probeJournalIds();
	}

	section("Clean-up");
	deleteProbeObjects();
	p11->C_Logout(session);
	p11->C_CloseSession(session);
	rv = p11->C_Finalize(NULL_PTR);
	if (rv != CKR_OK) { showRv("C_Finalize", rv); cleanupFailed = 1; }
	line("\nDone.");
	if (terminal != NULL)
	{
		fprintf(terminal, "%s Log: %s\n", cleanupFailed ? "Clean-up needs attention." : "Done.", logPath);
		fclose(terminal);
	}
	return cleanupFailed ? 1 : 0;
}
