/*
 * One-run behaviour probe for a physical Rutoken ECP through the Aktiv
 * PKCS #11 library.
 *
 * The compatibility profile in src/lib/SoftHSM.cpp emulates a Rutoken ECP so
 * software written for the real token can be tested where no token can be
 * plugged in. Several questions the profile still answers from the standard
 * or from reasoning rather than from the device are collected in
 * docs/PLAN.md. This program answers them in a single non-interactive run
 * against a live token and the vendor library: it reports, in one text log,
 * what the device actually does for key agreement (CKM_GOST_KEG) on 256- and
 * 512-bit keys, the free-memory behaviour, the raw CK_TOKEN_INFO including
 * utcTime, the PIN-not-default flags, short-PIN handling, the PIN attempt
 * counter and unblocking, the token seen from two processes at once, and
 * C_EX_InitToken. What the OpenSC probe already answered (extended token
 * info sizing, name, licenses, Flash volumes, the read-only C_EX_SlotManage
 * modes, the empty journal) is not repeated here.
 *
 * It is written against the extension ABI declared in src/lib/pkcs11, the
 * same headers the module itself is built from; the vendor library keeps its
 * own copies and only has to agree field for field.
 *
 * Running it:
 *
 *   cc -I src/lib/pkcs11 tests/portable/rutoken-device-probe.c -ldl \
 *      -o rutoken-device-probe
 *   ./rutoken-device-probe /usr/lib/librtpkcs11ecp.so \
 *       --user-pin 12345678 --so-pin 87654321 --write --format
 *
 * Nothing is interactive: the PINs are command-line arguments (or taken from
 * the environment with --user-pin-env / --so-pin-env), and there is no
 * prompt or terminal read. Without --write the run only reads and does
 * on-device key agreement, which changes no persistent state; --write adds
 * the PIN tests and the attempt-counter walk (all recoverable); --format
 * adds C_InitToken and C_EX_InitToken, which reformat the token. The owner's
 * token is a test token, so the destructive parts are expected to be used.
 *
 * Safety that is deliberate, not accidental: the SO (administrator) attempt
 * counter is never driven to zero, because a locked SO PIN on a real Rutoken
 * cannot be recovered without a factory key. The probe makes at most one
 * wrong SO attempt, and only when at least SO_SAFETY_MARGIN attempts remain,
 * then clears it with a correct login. The user PIN may be driven to a full
 * lockout, which C_EX_UnblockUserPIN recovers under the SO. With --format
 * the last thing the probe does is reformat the token back to the PINs,
 * label, retry counts and PIN lengths it started with.
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "cryptoki.h"
#include "rutoken.h"

#define SO_SAFETY_MARGIN 4
#define MAX_SLOTS 64
#define MAX_OBJECTS 4096

/* Objects the probe creates carry this label and ID, and only objects with
 * this label are ever deleted, including any left by an interrupted run. */
static const char PROBE_LABEL[] = "SoftHSM device probe";
static const CK_BYTE PROBE_ID[] = {
	'S', 'o', 'f', 't', 'H', 'S', 'M', '-', 'd', 'e', 'v', '-', 'p', 'r', 'o', 'b', 'e'
};

static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
static CK_FUNCTION_LIST_EXTENDED_PTR ex = NULL_PTR;
static void* libraryHandle = NULL;
static const char* progPath = NULL;
static CK_BYTE origLabel[32];
static int origLabelKnown = 0;

static struct {
	const char* module;
	const char* userPin;
	const char* soPin;
	int write;
	int format;
	int child;            /* internal: acting as the second process */
	const char* childDir; /* internal: coordination directory */
	const char* childPin; /* internal: the PIN in force when the child starts */
	const char* childNew; /* internal: the PIN the parent changes to */
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
	case CKR_CANCEL: return "CKR_CANCEL";
	case CKR_HOST_MEMORY: return "CKR_HOST_MEMORY";
	case CKR_SLOT_ID_INVALID: return "CKR_SLOT_ID_INVALID";
	case CKR_GENERAL_ERROR: return "CKR_GENERAL_ERROR";
	case CKR_FUNCTION_FAILED: return "CKR_FUNCTION_FAILED";
	case CKR_ARGUMENTS_BAD: return "CKR_ARGUMENTS_BAD";
	case CKR_NO_EVENT: return "CKR_NO_EVENT";
	case CKR_ATTRIBUTE_READ_ONLY: return "CKR_ATTRIBUTE_READ_ONLY";
	case CKR_ATTRIBUTE_SENSITIVE: return "CKR_ATTRIBUTE_SENSITIVE";
	case CKR_ATTRIBUTE_TYPE_INVALID: return "CKR_ATTRIBUTE_TYPE_INVALID";
	case CKR_ATTRIBUTE_VALUE_INVALID: return "CKR_ATTRIBUTE_VALUE_INVALID";
	case CKR_DATA_INVALID: return "CKR_DATA_INVALID";
	case CKR_DATA_LEN_RANGE: return "CKR_DATA_LEN_RANGE";
	case CKR_DEVICE_ERROR: return "CKR_DEVICE_ERROR";
	case CKR_DEVICE_MEMORY: return "CKR_DEVICE_MEMORY";
	case CKR_DEVICE_REMOVED: return "CKR_DEVICE_REMOVED";
	case CKR_FUNCTION_CANCELED: return "CKR_FUNCTION_CANCELED";
	case CKR_KEY_HANDLE_INVALID: return "CKR_KEY_HANDLE_INVALID";
	case CKR_KEY_SIZE_RANGE: return "CKR_KEY_SIZE_RANGE";
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
	case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
	case CKR_SESSION_COUNT: return "CKR_SESSION_COUNT";
	case CKR_SESSION_HANDLE_INVALID: return "CKR_SESSION_HANDLE_INVALID";
	case CKR_SESSION_READ_ONLY: return "CKR_SESSION_READ_ONLY";
	case CKR_SESSION_EXISTS: return "CKR_SESSION_EXISTS";
	case CKR_SESSION_READ_ONLY_EXISTS: return "CKR_SESSION_READ_ONLY_EXISTS";
	case CKR_SESSION_READ_WRITE_SO_EXISTS: return "CKR_SESSION_READ_WRITE_SO_EXISTS";
	case CKR_SIGNATURE_INVALID: return "CKR_SIGNATURE_INVALID";
	case CKR_SIGNATURE_LEN_RANGE: return "CKR_SIGNATURE_LEN_RANGE";
	case CKR_TEMPLATE_INCOMPLETE: return "CKR_TEMPLATE_INCOMPLETE";
	case CKR_TEMPLATE_INCONSISTENT: return "CKR_TEMPLATE_INCONSISTENT";
	case CKR_TOKEN_NOT_PRESENT: return "CKR_TOKEN_NOT_PRESENT";
	case CKR_TOKEN_NOT_RECOGNIZED: return "CKR_TOKEN_NOT_RECOGNIZED";
	case CKR_TOKEN_WRITE_PROTECTED: return "CKR_TOKEN_WRITE_PROTECTED";
	case CKR_USER_ALREADY_LOGGED_IN: return "CKR_USER_ALREADY_LOGGED_IN";
	case CKR_USER_NOT_LOGGED_IN: return "CKR_USER_NOT_LOGGED_IN";
	case CKR_USER_PIN_NOT_INITIALIZED: return "CKR_USER_PIN_NOT_INITIALIZED";
	case CKR_USER_TYPE_INVALID: return "CKR_USER_TYPE_INVALID";
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN: return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	case CKR_USER_TOO_MANY_TYPES: return "CKR_USER_TOO_MANY_TYPES";
	case CKR_CRYPTOKI_NOT_INITIALIZED: return "CKR_CRYPTOKI_NOT_INITIALIZED";
	case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	case CKR_CURVE_NOT_SUPPORTED: return "CKR_CURVE_NOT_SUPPORTED";
	case CKR_FUNCTION_NOT_SUPPORTED: return "CKR_FUNCTION_NOT_SUPPORTED";
	/* Rutoken vendor codes from rutoken.h. */
	case CKR_CORRUPTED_MAPFILE: return "CKR_CORRUPTED_MAPFILE";
	case CKR_WRONG_VERSION_FIELD: return "CKR_WRONG_VERSION_FIELD";
	case CKR_LICENSE_READ_ONLY: return "CKR_LICENSE_READ_ONLY";
	case CKR_INAPPROPRIATE_PIN: return "CKR_INAPPROPRIATE_PIN";
	case CKR_PIN_IN_HISTORY: return "CKR_PIN_IN_HISTORY";
	default: return "?";
	}
}

static void showRv(const char* what, CK_RV rv)
{
	line("    %-48s rv = %s (0x%lx)", what, rvName(rv), (unsigned long) rv);
}

static void hexDump(const char* name, const unsigned char* data, size_t length)
{
	size_t i;
	printf("%-22s", name);
	for (i = 0; i < length; i++)
	{
		if (i % 16 == 0) printf("\n    ");
		printf("%02X ", data[i]);
	}
	printf("\n");
	fflush(stdout);
}

/* ---- small utilities --------------------------------------------------- */

/* Read one attribute into caller's buffer; returns the length the token
 * reports, or (CK_ULONG)-1 on failure. */
static CK_ULONG readAttribute(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object,
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

static int findProbeObjects(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* out, CK_ULONG max)
{
	CK_ATTRIBUTE search[1];
	CK_ULONG found = 0;
	CK_RV rv;
	search[0].type = CKA_LABEL;
	search[0].pValue = (CK_VOID_PTR) PROBE_LABEL;
	search[0].ulValueLen = sizeof(PROBE_LABEL) - 1;
	rv = p11->C_FindObjectsInit(session, search, 1);
	if (rv != CKR_OK) { showRv("C_FindObjectsInit(probe label)", rv); return 0; }
	p11->C_FindObjects(session, out, max, &found);
	p11->C_FindObjectsFinal(session);
	return (int) found;
}

static void deleteProbeObjects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	int n, i;
	n = findProbeObjects(session, objects, MAX_OBJECTS);
	for (i = 0; i < n; i++)
		p11->C_DestroyObject(session, objects[i]);
	if (n > 0)
		line("    cleaned up %d probe object(s)", n);
}

static CK_ULONG freeExtendedMemory(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO_EXTENDED info;
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	if (ex == NULL || ex->C_EX_GetTokenInfoExtended == NULL)
		return (CK_ULONG) -1;
	if (ex->C_EX_GetTokenInfoExtended(slot, &info) != CKR_OK)
		return (CK_ULONG) -1;
	return info.ulFreeMemory;
}

/* ---- 1. raw CK_TOKEN_INFO, including utcTime --------------------------- */

static void probeTokenInfo(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO info;
	CK_RV rv;
	section("CK_TOKEN_INFO as bytes, including utcTime and the memory fields");
	memset(&info, 0, sizeof(info));
	rv = p11->C_GetTokenInfo(slot, &info);
	showRv("C_GetTokenInfo", rv);
	if (rv != CKR_OK) return;
	memcpy(origLabel, info.label, 32);
	origLabelKnown = 1;
	hexDump("label[32]", info.label, 32);
	hexDump("manufacturerID[32]", info.manufacturerID, 32);
	hexDump("model[16]", info.model, 16);
	hexDump("serialNumber[16]", info.serialNumber, 16);
	line("flags                  0x%lx", (unsigned long) info.flags);
	line("ulMaxSessionCount      %lu", (unsigned long) info.ulMaxSessionCount);
	line("ulSessionCount         %lu", (unsigned long) info.ulSessionCount);
	line("ulMaxRwSessionCount    %lu", (unsigned long) info.ulMaxRwSessionCount);
	line("ulRwSessionCount       %lu", (unsigned long) info.ulRwSessionCount);
	line("ulMaxPinLen            %lu", (unsigned long) info.ulMaxPinLen);
	line("ulMinPinLen            %lu", (unsigned long) info.ulMinPinLen);
	line("ulTotalPublicMemory    %lu", (unsigned long) info.ulTotalPublicMemory);
	line("ulFreePublicMemory     %lu", (unsigned long) info.ulFreePublicMemory);
	line("ulTotalPrivateMemory   %lu", (unsigned long) info.ulTotalPrivateMemory);
	line("ulFreePrivateMemory    %lu", (unsigned long) info.ulFreePrivateMemory);
	line("hardwareVersion        %u.%u", info.hardwareVersion.major, info.hardwareVersion.minor);
	line("firmwareVersion        %u.%u", info.firmwareVersion.major, info.firmwareVersion.minor);
	/* utcTime is the headline: the profile fills it with the current time,
	 * which the owner wants empty. Print the 16 bytes raw so the fill byte -
	 * space, zero or digits - is unambiguous. */
	hexDump("utcTime[16]", info.utcTime, 16);
	line("utcTime as text        '%.16s'", info.utcTime);
	line("CKF_CLOCK_ON_TOKEN     %s",
	     (info.flags & CKF_CLOCK_ON_TOKEN) ? "set" : "clear");
}

/* ---- 2. CKM_GOST_KEG on 256- and 512-bit keys -------------------------- */

/* GOST R 34.10-2012 parameter OIDs, DER-encoded as the CKA_GOSTR3410_PARAMS
 * attribute carries them. */
static const CK_BYTE CURVE_256_A[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x01 };
static const CK_BYTE CURVE_256_B[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x02 };
static const CK_BYTE CURVE_256_C[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x01,0x03 };
static const CK_BYTE CURVE_512_A[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x01 };
static const CK_BYTE CURVE_512_B[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x02 };
static const CK_BYTE CURVE_512_C[] = { 0x06,0x09,0x2a,0x85,0x03,0x07,0x01,0x02,0x01,0x02,0x03 };
static const CK_BYTE DIGEST_256[]  = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x02 };
static const CK_BYTE DIGEST_512[]  = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x03 };

/* Generate a GOST key pair on the device. bits is 256 or 512; curve/curveLen
 * is the domain OID. Returns CKR_OK and fills the handles on success. The
 * keys are session objects when possible; if the device refuses those they
 * are retried as token objects, which carry the probe label for cleanup. */
static CK_RV generateGostPair(CK_SESSION_HANDLE session, int bits,
			      const CK_BYTE* curve, CK_ULONG curveLen,
			      const CK_BYTE* digest, CK_ULONG digestLen,
			      CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv, int asToken)
{
	CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = (bits == 512) ? CKK_GOSTR3410_512 : CKK_GOSTR3410;
	CK_MECHANISM mechanism;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_BBOOL tokenFlag = asToken ? CK_TRUE : CK_FALSE;
	CK_ATTRIBUTE publicTemplate[] = {
		{ CKA_CLASS, &publicClass, sizeof(publicClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &tokenFlag, sizeof(tokenFlag) },
		{ CKA_PRIVATE, &no, sizeof(no) },
		{ CKA_DERIVE, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) PROBE_ID, sizeof(PROBE_ID) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) digest, digestLen }
	};
	CK_ATTRIBUTE privateTemplate[] = {
		{ CKA_CLASS, &privateClass, sizeof(privateClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &tokenFlag, sizeof(tokenFlag) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_DERIVE, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) PROBE_ID, sizeof(PROBE_ID) },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) curve, curveLen },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) digest, digestLen }
	};
	mechanism.mechanism = (bits == 512) ? CKM_GOSTR3410_512_KEY_PAIR_GEN
					    : CKM_GOSTR3410_KEY_PAIR_GEN;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mechanism,
				      publicTemplate, sizeof(publicTemplate) / sizeof(publicTemplate[0]),
				      privateTemplate, sizeof(privateTemplate) / sizeof(privateTemplate[0]),
				      pub, priv);
}

/* Derive a twin key by CKM_GOST_KEG from a private key and a peer public
 * value, then report the result's type, length and (if readable) its bytes.
 * Returns the derived handle or CK_INVALID_HANDLE; on success the caller
 * reads CKA_VALUE through the out buffer. */
static CK_OBJECT_HANDLE deriveKEG(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE priv,
				  const CK_BYTE* peer, CK_ULONG peerLen,
				  const CK_BYTE* ukm, CK_ULONG ukmLen, CK_KEY_TYPE twinType,
				  CK_BYTE* valueOut, CK_ULONG* valueLen, const char* what)
{
	CK_ECDH1_DERIVE_PARAMS params;
	CK_MECHANISM mechanism;
	CK_OBJECT_CLASS secretClass = CKO_SECRET_KEY;
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_ATTRIBUTE outputTemplate[] = {
		{ CKA_CLASS, &secretClass, sizeof(secretClass) },
		{ CKA_KEY_TYPE, &twinType, sizeof(twinType) },
		{ CKA_TOKEN, &no, sizeof(no) },
		{ CKA_EXTRACTABLE, &yes, sizeof(yes) }
	};
	CK_OBJECT_HANDLE derived = CK_INVALID_HANDLE;
	CK_RV rv;
	params.kdf = CKD_NULL;
	params.ulSharedDataLen = ukmLen;
	params.pSharedData = (CK_BYTE_PTR) ukm;
	params.ulPublicDataLen = peerLen;
	params.pPublicData = (CK_BYTE_PTR) peer;
	mechanism.mechanism = CKM_GOST_KEG;
	mechanism.pParameter = &params;
	mechanism.ulParameterLen = sizeof(params);
	rv = p11->C_DeriveKey(session, &mechanism, priv, outputTemplate,
			      sizeof(outputTemplate) / sizeof(outputTemplate[0]), &derived);
	showRv(what, rv);
	if (rv != CKR_OK) return CK_INVALID_HANDLE;
	if (valueOut && valueLen)
	{
		CK_ULONG got = readAttribute(session, derived, CKA_VALUE, valueOut, *valueLen);
		if (got == (CK_ULONG) -1)
		{
			line("        CKA_VALUE not readable (sensitive or non-extractable on the device)");
			*valueLen = 0;
		}
		else
			*valueLen = got;
	}
	return derived;
}

/* Key agreement on one key size: two freshly generated pairs, each side
 * deriving from its own private key and the other's public key, must reach
 * the same bytes. This needs no external vector and proves the device
 * performs KEG end to end. Run for each twin key type the standard allows. */
static void probeKEGAgreement(CK_SESSION_HANDLE session, int bits,
			      const CK_BYTE* curve, CK_ULONG curveLen,
			      const CK_BYTE* digest, CK_ULONG digestLen)
{
	static const CK_BYTE ukm[32] = {
		0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
		0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
	};
	struct { CK_KEY_TYPE type; const char* name; } twins[] = {
		{ CKK_MAGMA_TWIN_KEY, "CKK_MAGMA_TWIN_KEY" },
		{ CKK_KUZNECHIK_TWIN_KEY, "CKK_KUZNECHIK_TWIN_KEY" },
		{ CKK_GENERIC_SECRET, "CKK_GENERIC_SECRET" }
	};
	CK_OBJECT_HANDLE alicePub, alicePriv, bobPub, bobPriv;
	CK_BYTE alicePeer[256], bobPeer[256];
	CK_ULONG alicePeerLen = sizeof(alicePeer), bobPeerLen = sizeof(bobPeer);
	CK_ULONG expectPeer = (bits == 512) ? 128 : 64;
	CK_RV rv;
	int t, asToken;

	section("CKM_GOST_KEG agreement on %d-bit GOST 2012 keys (device-generated)", bits);

	for (asToken = 0; asToken <= 1; asToken++)
	{
		rv = generateGostPair(session, bits, curve, curveLen, digest, digestLen,
				      &alicePub, &alicePriv, asToken);
		if (rv == CKR_OK) break;
		showRv(asToken ? "C_GenerateKeyPair (token objects)"
			       : "C_GenerateKeyPair (session objects)", rv);
	}
	if (rv != CKR_OK) { line("    cannot generate a %d-bit pair; skipping", bits); return; }
	rv = generateGostPair(session, bits, curve, curveLen, digest, digestLen,
			      &bobPub, &bobPriv, asToken);
	if (rv != CKR_OK) { showRv("C_GenerateKeyPair (second pair)", rv); return; }
	line("    generated two %d-bit pairs as %s objects", bits, asToken ? "token" : "session");

	alicePeerLen = readAttribute(session, alicePub, CKA_VALUE, alicePeer, sizeof(alicePeer));
	bobPeerLen = readAttribute(session, bobPub, CKA_VALUE, bobPeer, sizeof(bobPeer));
	if (alicePeerLen == (CK_ULONG) -1 || bobPeerLen == (CK_ULONG) -1)
	{
		line("    cannot read the generated public values; skipping agreement");
		return;
	}
	line("    public value length %lu (expected %lu for %d-bit)",
	     (unsigned long) alicePeerLen, (unsigned long) expectPeer, bits);

	for (t = 0; t < (int)(sizeof(twins) / sizeof(twins[0])); t++)
	{
		CK_BYTE fromAlice[128], fromBob[128];
		CK_ULONG lenA = sizeof(fromAlice), lenB = sizeof(fromBob);
		CK_OBJECT_HANDLE dA, dB;
		char what[128];
		line("  twin key type %s:", twins[t].name);
		snprintf(what, sizeof(what), "C_DeriveKey alice<-bob, %s", twins[t].name);
		dA = deriveKEG(session, alicePriv, bobPeer, bobPeerLen, ukm, sizeof(ukm),
			       twins[t].type, fromAlice, &lenA, what);
		snprintf(what, sizeof(what), "C_DeriveKey bob<-alice, %s", twins[t].name);
		dB = deriveKEG(session, bobPriv, alicePeer, alicePeerLen, ukm, sizeof(ukm),
			       twins[t].type, fromBob, &lenB, what);
		if (dA != CK_INVALID_HANDLE && dB != CK_INVALID_HANDLE)
		{
			if (lenA > 0 && lenB > 0)
			{
				line("        derived length %lu / %lu", (unsigned long) lenA, (unsigned long) lenB);
				if (lenA == lenB && memcmp(fromAlice, fromBob, lenA) == 0)
				{
					line("        AGREE: both sides reached the same %lu bytes", (unsigned long) lenA);
					hexDump("        shared", fromAlice, lenA);
				}
				else
					line("        DISAGREE: the two sides differ");
			}
			else
				line("        derived on both sides; value not extractable, agreement not checkable here");
		}
		if (dA != CK_INVALID_HANDLE) p11->C_DestroyObject(session, dA);
		if (dB != CK_INVALID_HANDLE) p11->C_DestroyObject(session, dB);
	}
	p11->C_DestroyObject(session, alicePub);
	p11->C_DestroyObject(session, alicePriv);
	p11->C_DestroyObject(session, bobPub);
	p11->C_DestroyObject(session, bobPriv);
}

/* Generation across parameter sets: which curves the device actually makes
 * keys on, for 256 and 512. The profile currently generates 512 on paramSetA
 * only; the device reading decides whether B and C should follow. */
static void probeGeneration(CK_SESSION_HANDLE session)
{
	struct { int bits; const CK_BYTE* curve; CK_ULONG len; const CK_BYTE* digest; CK_ULONG dlen; const char* name; } sets[] = {
		{ 256, CURVE_256_A, sizeof(CURVE_256_A), DIGEST_256, sizeof(DIGEST_256), "256 paramSetA" },
		{ 256, CURVE_256_B, sizeof(CURVE_256_B), DIGEST_256, sizeof(DIGEST_256), "256 paramSetB" },
		{ 256, CURVE_256_C, sizeof(CURVE_256_C), DIGEST_256, sizeof(DIGEST_256), "256 paramSetC" },
		{ 512, CURVE_512_A, sizeof(CURVE_512_A), DIGEST_512, sizeof(DIGEST_512), "512 paramSetA" },
		{ 512, CURVE_512_B, sizeof(CURVE_512_B), DIGEST_512, sizeof(DIGEST_512), "512 paramSetB" },
		{ 512, CURVE_512_C, sizeof(CURVE_512_C), DIGEST_512, sizeof(DIGEST_512), "512 paramSetC" }
	};
	int i;
	section("GOST 2012 key generation across parameter sets");
	for (i = 0; i < (int)(sizeof(sets) / sizeof(sets[0])); i++)
	{
		CK_OBJECT_HANDLE pub, priv;
		CK_RV rv = generateGostPair(session, sets[i].bits, sets[i].curve, sets[i].len,
					    sets[i].digest, sets[i].dlen, &pub, &priv, 0);
		if (rv != CKR_OK)
			rv = generateGostPair(session, sets[i].bits, sets[i].curve, sets[i].len,
					      sets[i].digest, sets[i].dlen, &pub, &priv, 1);
		showRv(sets[i].name, rv);
		if (rv == CKR_OK)
		{
			CK_BYTE value[256];
			CK_ULONG len = readAttribute(session, pub, CKA_VALUE, value, sizeof(value));
			if (len != (CK_ULONG) -1)
				line("        public value %lu bytes", (unsigned long) len);
			p11->C_DestroyObject(session, pub);
			p11->C_DestroyObject(session, priv);
		}
	}
}

/* ---- 3. CKM_GOSTR3410 sign, with and without a hash-OID parameter ------ */

/* The profile refuses a mechanism parameter on CKM_GOSTR3410 and
 * CKM_GOSTR3410_512, because those mechanisms sign a ready digest and name no
 * hash. docs/PLAN.md asks whether software ever sends the OID there the way
 * it does to the combined mechanisms; this records what the device accepts.
 * It signs a fixed buffer the size of the digest (32 or 64 bytes). */
static void probeGostSignParameter(CK_SESSION_HANDLE session)
{
	struct { int bits; CK_MECHANISM_TYPE mech; const char* mname;
		 const CK_BYTE* curve; CK_ULONG clen; const CK_BYTE* digest; CK_ULONG dlen;
		 const CK_BYTE* oid; CK_ULONG oidLen; CK_ULONG hashLen; } cases[] = {
		{ 256, CKM_GOSTR3410, "CKM_GOSTR3410",
		  CURVE_256_A, sizeof(CURVE_256_A), DIGEST_256, sizeof(DIGEST_256),
		  DIGEST_256, sizeof(DIGEST_256), 32 },
		{ 512, CKM_GOSTR3410_512, "CKM_GOSTR3410_512",
		  CURVE_512_A, sizeof(CURVE_512_A), DIGEST_512, sizeof(DIGEST_512),
		  DIGEST_512, sizeof(DIGEST_512), 64 }
	};
	int i;
	section("CKM_GOSTR3410 / _512 signing, hash-OID parameter or none");
	for (i = 0; i < (int)(sizeof(cases) / sizeof(cases[0])); i++)
	{
		CK_OBJECT_HANDLE pub, priv;
		CK_BYTE hash[64];
		CK_BYTE signature[256];
		CK_ULONG sigLen;
		CK_MECHANISM mechanism;
		CK_RV rv;
		int asToken = 0;
		memset(hash, 0x5a, sizeof(hash));
		rv = generateGostPair(session, cases[i].bits, cases[i].curve, cases[i].clen,
				      cases[i].digest, cases[i].dlen, &pub, &priv, 0);
		if (rv != CKR_OK)
		{
			asToken = 1;
			rv = generateGostPair(session, cases[i].bits, cases[i].curve, cases[i].clen,
					      cases[i].digest, cases[i].dlen, &pub, &priv, 1);
		}
		line("  %s (key %s):", cases[i].mname, rv == CKR_OK ? "ready" : "generation failed");
		if (rv != CKR_OK) { showRv("C_GenerateKeyPair", rv); continue; }

		mechanism.mechanism = cases[i].mech;
		mechanism.pParameter = NULL_PTR;
		mechanism.ulParameterLen = 0;
		rv = p11->C_SignInit(session, &mechanism, priv);
		showRv("C_SignInit, no parameter", rv);
		if (rv == CKR_OK)
		{
			sigLen = sizeof(signature);
			rv = p11->C_Sign(session, hash, cases[i].hashLen, signature, &sigLen);
			showRv("C_Sign, no parameter", rv);
			if (rv == CKR_OK) line("        signature %lu bytes", (unsigned long) sigLen);
		}

		mechanism.pParameter = (CK_VOID_PTR) cases[i].oid;
		mechanism.ulParameterLen = cases[i].oidLen;
		rv = p11->C_SignInit(session, &mechanism, priv);
		showRv("C_SignInit, hash-OID parameter", rv);
		if (rv == CKR_OK)
		{
			sigLen = sizeof(signature);
			rv = p11->C_Sign(session, hash, cases[i].hashLen, signature, &sigLen);
			showRv("C_Sign, hash-OID parameter", rv);
			if (rv == CKR_OK) line("        signature %lu bytes", (unsigned long) sigLen);
		}
		(void) asToken;
		p11->C_DestroyObject(session, pub);
		p11->C_DestroyObject(session, priv);
	}
}

/* ---- 4. journal after a signature ------------------------------------- */

static void readJournal(CK_SLOT_ID slot, const char* when)
{
	CK_BYTE buffer[8192];
	CK_ULONG size = 0;
	CK_RV rv;
	if (ex == NULL || ex->C_EX_GetJournal == NULL)
	{
		line("    C_EX_GetJournal is not in the table");
		return;
	}
	rv = ex->C_EX_GetJournal(slot, NULL_PTR, &size);
	line("    size query %s: rv = %s, size = %lu", when, rvName(rv), (unsigned long) size);
	if (rv != CKR_OK || size == 0) return;
	if (size > sizeof(buffer)) size = sizeof(buffer);
	rv = ex->C_EX_GetJournal(slot, buffer, &size);
	showRv("C_EX_GetJournal (read)", rv);
	if (rv == CKR_OK) hexDump("journal", buffer, size);
}

static void probeJournal(CK_SESSION_HANDLE session, CK_SLOT_ID slot)
{
	CK_OBJECT_HANDLE pub, priv;
	CK_BYTE hash[32];
	CK_BYTE signature[256];
	CK_ULONG sigLen = sizeof(signature);
	CK_MECHANISM mechanism;
	CK_RV rv;
	section("C_EX_GetJournal before and after a GOST signature");
	readJournal(slot, "before signing");

	memset(hash, 0x33, sizeof(hash));
	rv = generateGostPair(session, 256, CURVE_256_A, sizeof(CURVE_256_A),
			      DIGEST_256, sizeof(DIGEST_256), &pub, &priv, 1);
	if (rv != CKR_OK)
	{
		showRv("C_GenerateKeyPair for journal", rv);
		return;
	}
	mechanism.mechanism = CKM_GOSTR3410_WITH_GOSTR3411_12_256;
	mechanism.pParameter = NULL_PTR;
	mechanism.ulParameterLen = 0;
	rv = p11->C_SignInit(session, &mechanism, priv);
	showRv("C_SignInit (journal fill)", rv);
	if (rv == CKR_OK)
	{
		static const CK_BYTE data[] = "SoftHSM device probe journal data";
		rv = p11->C_Sign(session, (CK_BYTE_PTR) data, sizeof(data) - 1, signature, &sigLen);
		showRv("C_Sign (journal fill)", rv);
	}
	readJournal(slot, "after signing");
	p11->C_DestroyObject(session, pub);
	p11->C_DestroyObject(session, priv);
}

/* ---- 5. free memory against object creation and deletion --------------- */

/* Create one token data object with a value of the given size. CKO_DATA
 * carries CKA_APPLICATION, not CKA_ID, so only the label is set (which is all
 * the cleanup searches on). */
static CK_RV createDataObject(CK_SESSION_HANDLE session, CK_BYTE* value, CK_ULONG size,
			      CK_OBJECT_HANDLE* out)
{
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_BBOOL yes = CK_TRUE;
	CK_ATTRIBUTE t[] = {
		{ CKA_CLASS, &dataClass, sizeof(dataClass) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_APPLICATION, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_VALUE, value, size }
	};
	*out = CK_INVALID_HANDLE;
	return p11->C_CreateObject(session, t, sizeof(t) / sizeof(t[0]), out);
}

static void probeMemory(CK_SESSION_HANDLE session, CK_SLOT_ID slot)
{
	CK_OBJECT_HANDLE created[512];
	int count = 0, i;
	CK_ULONG startExt, startPub, startPriv;
	CK_TOKEN_INFO info;
	CK_BYTE value[2048];
	CK_OBJECT_HANDLE probe = CK_INVALID_HANDLE;
	CK_RV rv;

	section("Free memory as token objects are created and deleted");
	if (!opt.write)
	{
		line("    skipped (needs --write: it writes token objects)");
		return;
	}
	memset(value, 0x77, sizeof(value));
	startExt = freeExtendedMemory(slot);
	memset(&info, 0, sizeof(info));
	p11->C_GetTokenInfo(slot, &info);
	startPub = info.ulFreePublicMemory;
	startPriv = info.ulFreePrivateMemory;
	line("    start: extended free %lu, C_GetTokenInfo public %lu private %lu",
	     (unsigned long) startExt, (unsigned long) startPub, (unsigned long) startPriv);

	/* Prefer data objects (cheap, fast) if the device accepts them; some
	 * tokens refuse CKO_DATA, so fall back to GOST token key pairs, which
	 * always consume memory, with a smaller cap. */
	rv = createDataObject(session, value, sizeof(value), &probe);
	if (rv == CKR_OK)
	{
		created[count++] = probe;
		line("    object kind: %u-byte CKO_DATA token objects", (unsigned) sizeof(value));
		for (i = 1; i < (int)(sizeof(created) / sizeof(created[0])); i++)
		{
			CK_OBJECT_HANDLE object;
			rv = createDataObject(session, value, sizeof(value), &object);
			if (rv != CKR_OK)
			{
				line("    creation stopped at object %d: rv = %s (exhaustion)", count, rvName(rv));
				break;
			}
			created[count++] = object;
			if (count <= 4 || count % 32 == 0)
				line("    after %d objects: extended free %lu, public %lu", count,
				     (unsigned long) freeExtendedMemory(slot),
				     (p11->C_GetTokenInfo(slot, &info) == CKR_OK)
					     ? (unsigned long) info.ulFreePublicMemory : 0UL);
		}
	}
	else
	{
		line("    CKO_DATA refused (rv = %s); falling back to GOST token key pairs", rvName(rv));
		for (i = 0; i < 16; i++)
		{
			CK_OBJECT_HANDLE pub, priv;
			rv = generateGostPair(session, 256, CURVE_256_A, sizeof(CURVE_256_A),
					      DIGEST_256, sizeof(DIGEST_256), &pub, &priv, 1);
			if (rv != CKR_OK)
			{
				line("    key-pair creation stopped at %d: rv = %s", i, rvName(rv));
				break;
			}
			line("    after %d key pairs: extended free %lu", i + 1,
			     (unsigned long) freeExtendedMemory(slot));
		}
	}
	line("    created %d objects", count);
	line("    low point: extended free %lu", (unsigned long) freeExtendedMemory(slot));
	for (i = 0; i < count; i++)
		p11->C_DestroyObject(session, created[i]);
	deleteProbeObjects(session);
	line("    after deleting all: extended free %lu (started %lu)",
	     (unsigned long) freeExtendedMemory(slot), (unsigned long) startExt);
}

/* ---- 6. PIN flags, short PINs and the attempt counter ------------------ */

static void extReport(CK_SLOT_ID slot, const char* when)
{
	CK_TOKEN_INFO_EXTENDED info;
	CK_TOKEN_INFO base;
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	if (ex && ex->C_EX_GetTokenInfoExtended &&
	    ex->C_EX_GetTokenInfoExtended(slot, &info) == CKR_OK)
	{
		line("    [%s] flags 0x%lx  ADMIN_NOT_DEFAULT=%d USER_NOT_DEFAULT=%d  "
		     "SO left %lu/%lu  user left %lu/%lu", when,
		     (unsigned long) info.flags,
		     (info.flags & TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT) ? 1 : 0,
		     (info.flags & TOKEN_FLAGS_USER_PIN_NOT_DEFAULT) ? 1 : 0,
		     (unsigned long) info.ulAdminRetryCountLeft, (unsigned long) info.ulMaxAdminRetryCount,
		     (unsigned long) info.ulUserRetryCountLeft, (unsigned long) info.ulMaxUserRetryCount);
	}
	memset(&base, 0, sizeof(base));
	if (p11->C_GetTokenInfo(slot, &base) == CKR_OK)
		line("        C_GetTokenInfo flags 0x%lx (COUNT_LOW user=%d so=%d, FINAL_TRY user=%d, LOCKED user=%d)",
		     (unsigned long) base.flags,
		     (base.flags & CKF_USER_PIN_COUNT_LOW) ? 1 : 0,
		     (base.flags & CKF_SO_PIN_COUNT_LOW) ? 1 : 0,
		     (base.flags & CKF_USER_PIN_FINAL_TRY) ? 1 : 0,
		     (base.flags & CKF_USER_PIN_LOCKED) ? 1 : 0);
}

/* One user login attempt in a throwaway RW session; logs out on success.
 * Returns the C_Login rv. */
static CK_RV tryUserLogin(CK_SLOT_ID slot, const char* pin)
{
	CK_SESSION_HANDLE session;
	CK_RV rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				      NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK) return rv;
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) pin, strlen(pin));
	if (rv == CKR_OK) p11->C_Logout(session);
	p11->C_CloseSession(session);
	return rv;
}

static CK_RV trySoLogin(CK_SLOT_ID slot, const char* pin)
{
	CK_SESSION_HANDLE session;
	CK_RV rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				      NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK) return rv;
	rv = p11->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR) pin, strlen(pin));
	if (rv == CKR_OK) p11->C_Logout(session);
	p11->C_CloseSession(session);
	return rv;
}

/* Change the user PIN in an RW USER session: old -> new. */
static CK_RV setUserPin(CK_SLOT_ID slot, const char* oldPin, const char* newPin)
{
	CK_SESSION_HANDLE session;
	CK_RV rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				      NULL_PTR, NULL_PTR, &session);
	if (rv != CKR_OK) return rv;
	rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) oldPin, strlen(oldPin));
	if (rv == CKR_OK)
	{
		rv = p11->C_SetPIN(session, (CK_UTF8CHAR_PTR) oldPin, strlen(oldPin),
				   (CK_UTF8CHAR_PTR) newPin, strlen(newPin));
		p11->C_Logout(session);
	}
	p11->C_CloseSession(session);
	return rv;
}

static void probePinFlags(CK_SLOT_ID slot)
{
	section("PIN-not-default flags across a user PIN change");
	if (!opt.write)
	{
		line("    current state only (needs --write to change a PIN):");
		extReport(slot, "as found");
		return;
	}
	extReport(slot, "as found");
	/* Change the user PIN to a different value and back; the device should
	 * set USER_PIN_NOT_DEFAULT once it differs from factory. The flag may
	 * stay set after changing back - that is itself the answer. */
	{
		const char* alt = "998877";
		CK_RV rv = setUserPin(slot, opt.userPin, alt);
		showRv("C_SetPIN user -> alternate", rv);
		if (rv == CKR_OK)
		{
			extReport(slot, "after change away from factory");
			rv = setUserPin(slot, alt, opt.userPin);
			showRv("C_SetPIN user -> original", rv);
			extReport(slot, "after change back to factory value");
		}
	}
}

static void probeShortPins(CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;
	section("Short PIN handling on C_SetPIN, C_InitPIN and C_Login");
	if (!opt.write)
	{
		line("    skipped (needs --write)");
		return;
	}
	/* C_SetPIN to a 5-character PIN under the user. */
	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv == CKR_OK)
	{
		rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
		if (rv == CKR_OK)
		{
			rv = p11->C_SetPIN(session, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin),
					   (CK_UTF8CHAR_PTR) "12345", 5);
			showRv("C_SetPIN user to 5 characters", rv);
			p11->C_Logout(session);
		}
		else showRv("C_Login user for short C_SetPIN", rv);
		p11->C_CloseSession(session);
	}
	/* C_InitPIN to a 5-character PIN under the SO. */
	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv == CKR_OK)
	{
		rv = p11->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin));
		if (rv == CKR_OK)
		{
			rv = p11->C_InitPIN(session, (CK_UTF8CHAR_PTR) "12345", 5);
			showRv("C_InitPIN to 5 characters", rv);
			/* If it unexpectedly succeeded, put the user PIN back. */
			if (rv == CKR_OK)
			{
				p11->C_InitPIN(session, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
				line("        restored the user PIN with C_InitPIN");
			}
			p11->C_Logout(session);
		}
		else showRv("C_Login SO for short C_InitPIN", rv);
		p11->C_CloseSession(session);
	}
	/* C_Login with 3, 4 and 5 characters: report the code and how the user
	 * attempt counter moves. Each wrong attempt spends one; a correct login
	 * after resets it. */
	{
		const char* shorts[] = { "123", "1234", "12345" };
		int i;
		extReport(slot, "before short logins");
		for (i = 0; i < 3; i++)
		{
			rv = tryUserLogin(slot, shorts[i]);
			line("    C_Login user with %d chars: rv = %s", (int) strlen(shorts[i]), rvName(rv));
			extReport(slot, "after");
		}
		rv = tryUserLogin(slot, opt.userPin);
		showRv("C_Login user with the correct PIN (reset)", rv);
		extReport(slot, "after the correct login");
	}
}

static void probeAttemptCounter(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO_EXTENDED info;
	int guard = 0;
	CK_RV rv;
	section("User PIN attempt counter to lockout and recovery");
	if (!opt.write)
	{
		line("    skipped (needs --write)");
		return;
	}
	extReport(slot, "before wrong attempts");
	/* Wrong user logins one at a time until the PIN locks, reporting the
	 * counter at each step. The PIN value is unchanged by a wrong attempt. */
	for (guard = 0; guard < 64; guard++)
	{
		rv = tryUserLogin(slot, "000000");
		line("    wrong user attempt %d: rv = %s", guard + 1, rvName(rv));
		extReport(slot, "after wrong attempt");
		if (rv == CKR_PIN_LOCKED) break;
	}
	/* Recover with C_EX_UnblockUserPIN under the SO, then confirm. */
	if (ex && ex->C_EX_UnblockUserPIN)
	{
		CK_SESSION_HANDLE session;
		rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
		if (rv == CKR_OK)
		{
			rv = p11->C_Login(session, CKU_SO, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin));
			if (rv == CKR_OK)
			{
				rv = ex->C_EX_UnblockUserPIN(session);
				showRv("C_EX_UnblockUserPIN under SO", rv);
				p11->C_Logout(session);
			}
			else showRv("C_Login SO for unblock", rv);
			p11->C_CloseSession(session);
		}
	}
	extReport(slot, "after unblock");
	rv = tryUserLogin(slot, opt.userPin);
	showRv("C_Login user after unblock", rv);
	extReport(slot, "final");

	/* The SO counter is only touched if it is safe: one wrong attempt, and
	 * only with a wide margin, then cleared with a correct login. A locked
	 * SO PIN on a real Rutoken is not recoverable without a factory key. */
	memset(&info, 0, sizeof(info));
	info.ulSizeofThisStructure = sizeof(info);
	if (ex && ex->C_EX_GetTokenInfoExtended &&
	    ex->C_EX_GetTokenInfoExtended(slot, &info) == CKR_OK)
	{
		if (info.ulAdminRetryCountLeft >= SO_SAFETY_MARGIN)
		{
			rv = trySoLogin(slot, "00000000");
			line("    one wrong SO attempt (margin %lu): rv = %s",
			     (unsigned long) info.ulAdminRetryCountLeft, rvName(rv));
			extReport(slot, "after one wrong SO attempt");
			rv = trySoLogin(slot, opt.soPin);
			showRv("C_Login SO with the correct PIN (reset)", rv);
			extReport(slot, "after the correct SO login");
		}
		else
			line("    SO attempt test skipped: only %lu left, below the safety margin %d",
			     (unsigned long) info.ulAdminRetryCountLeft, SO_SAFETY_MARGIN);
	}
}

/* ---- 7. the token seen from two processes at once ---------------------- */

static int waitForFile(const char* path, int timeoutMs)
{
	int waited = 0;
	while (waited < timeoutMs)
	{
		struct timespec ts;
		if (access(path, F_OK) == 0) return 1;
		ts.tv_sec = 0;
		ts.tv_nsec = 100 * 1000 * 1000; /* 100 ms */
		nanosleep(&ts, NULL);
		waited += 100;
	}
	return 0;
}

/* The child process: loads the library itself, logs in with the old PIN,
 * signals ready, waits, then checks whether its already-open login survives
 * a change made by the parent and whether a fresh login sees the new PIN. */
static int runChild(void)
{
	CK_SLOT_ID slots[MAX_SLOTS];
	CK_ULONG slotCount = MAX_SLOTS;
	CK_SESSION_HANDLE held, fresh;
	CK_OBJECT_HANDLE object = CK_INVALID_HANDLE;
	char ready[1024], go[1024];
	CK_RV rv;
	CK_OBJECT_CLASS dataClass = CKO_DATA;
	CK_BBOOL yes = CK_TRUE;
	CK_BYTE value[8] = { 1,2,3,4,5,6,7,8 };

	if (p11->C_Initialize(NULL_PTR) != CKR_OK) { line("CHILD: C_Initialize failed"); return 1; }
	if (p11->C_GetSlotList(CK_TRUE, slots, &slotCount) != CKR_OK || slotCount == 0)
	{ line("CHILD: no token"); p11->C_Finalize(NULL_PTR); return 1; }

	rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &held);
	if (rv == CKR_OK)
		rv = p11->C_Login(held, CKU_USER, (CK_UTF8CHAR_PTR) opt.childPin, strlen(opt.childPin));
	line("CHILD: initial login with the old PIN: rv = %s", rvName(rv));

	snprintf(ready, sizeof(ready), "%s/ready", opt.childDir);
	snprintf(go, sizeof(go), "%s/go", opt.childDir);
	fclose(fopen(ready, "w"));

	if (!waitForFile(go, 30000)) { line("CHILD: parent never signalled go"); }

	/* Does the login the child already holds still let it make a private
	 * object after the parent changed the PIN out from under it? */
	{
		CK_ATTRIBUTE t[] = {
			{ CKA_CLASS, &dataClass, sizeof(dataClass) },
			{ CKA_TOKEN, &yes, sizeof(yes) },
			{ CKA_PRIVATE, &yes, sizeof(yes) },
			{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
			{ CKA_APPLICATION, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
			{ CKA_VALUE, value, sizeof(value) }
		};
		rv = p11->C_CreateObject(held, t, sizeof(t) / sizeof(t[0]), &object);
		line("CHILD: private object in the held session after the change: rv = %s", rvName(rv));
		if (rv == CKR_OK) p11->C_DestroyObject(held, object);
	}

	/* Log out and close the held session first, so the fresh login is not
	 * reported CKR_USER_ALREADY_LOGGED_IN; then ask whether this old process
	 * now accepts the new PIN, the old one, or neither. */
	p11->C_Logout(held);
	p11->C_CloseSession(held);
	rv = p11->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &fresh);
	if (rv == CKR_OK)
	{
		CK_RV n = p11->C_Login(fresh, CKU_USER, (CK_UTF8CHAR_PTR) opt.childPin, strlen(opt.childPin));
		line("CHILD: fresh login with the OLD PIN: rv = %s", rvName(n));
		if (n == CKR_OK) p11->C_Logout(fresh);
		n = p11->C_Login(fresh, CKU_USER, (CK_UTF8CHAR_PTR) opt.childNew, strlen(opt.childNew));
		line("CHILD: fresh login with the NEW PIN: rv = %s", rvName(n));
		if (n == CKR_OK) p11->C_Logout(fresh);
		p11->C_CloseSession(fresh);
	}
	p11->C_Finalize(NULL_PTR);
	return 0;
}

static void probeTwoProcess(CK_SLOT_ID slot)
{
	char dirTemplate[] = "/tmp/rtprobeXXXXXX";
	char ready[1024], go[1024];
	char* dir;
	pid_t pid;
	CK_RV rv;

	section("The token from two processes: PIN changed under an open login");
	if (!opt.write)
	{
		line("    skipped (needs --write: it changes a PIN)");
		return;
	}
	dir = mkdtemp(dirTemplate);
	if (dir == NULL) { line("    mkdtemp failed; skipping"); return; }
	snprintf(ready, sizeof(ready), "%s/ready", dir);
	snprintf(go, sizeof(go), "%s/go", dir);

	pid = fork();
	if (pid < 0) { line("    fork failed; skipping"); return; }
	if (pid == 0)
	{
		/* Re-exec a clean copy so the child's PKCS #11 state is its own; a
		 * forked copy would share the parent's library locks. */
		execl(progPath, progPath, opt.module, "--child",
		      "--child-dir", dir, "--user-pin", opt.userPin,
		      "--child-new", opt.childNew, (char*) NULL);
		_exit(127);
	}

	if (!waitForFile(ready, 30000))
		line("    child never became ready; continuing anyway");
	rv = setUserPin(slot, opt.userPin, opt.childNew);
	showRv("parent C_SetPIN user old -> new", rv);
	fclose(fopen(go, "w"));
	waitpid(pid, NULL, 0);

	/* Put the PIN back so the token keeps its starting value. */
	rv = setUserPin(slot, opt.childNew, opt.userPin);
	showRv("parent C_SetPIN user new -> old (restore)", rv);
	unlink(ready); unlink(go); rmdir(dir);
}

/* ---- 8. C_InitToken and C_EX_InitToken --------------------------------- */

static void exInitToken(CK_SLOT_ID slot, const char* soPin,
			const char* newAdmin, const char* newUser,
			CK_ULONG minAdmin, CK_ULONG minUser,
			CK_ULONG maxAdminRetry, CK_ULONG maxUserRetry,
			const CK_BYTE* label, CK_ULONG labelLen, const char* what)
{
	CK_RUTOKEN_INIT_PARAM param;
	CK_RV rv;
	if (ex == NULL || ex->C_EX_InitToken == NULL)
	{
		line("    C_EX_InitToken is not in the table");
		return;
	}
	memset(&param, 0, sizeof(param));
	param.ulSizeofThisStructure = sizeof(param);
	param.UseRepairMode = 0;
	param.pNewAdminPin = (CK_BYTE_PTR) newAdmin;
	param.ulNewAdminPinLen = newAdmin ? strlen(newAdmin) : 0;
	param.pNewUserPin = (CK_BYTE_PTR) newUser;
	param.ulNewUserPinLen = newUser ? strlen(newUser) : 0;
	param.ChangeUserPINPolicy = 0;
	param.ulMinAdminPinLen = minAdmin;
	param.ulMinUserPinLen = minUser;
	param.ulMaxAdminRetryCount = maxAdminRetry;
	param.ulMaxUserRetryCount = maxUserRetry;
	param.pTokenLabel = (CK_BYTE_PTR) label;
	param.ulLabelLen = labelLen;
	param.ulSmMode = 0;
	rv = ex->C_EX_InitToken(slot, (CK_UTF8CHAR_PTR) soPin, soPin ? strlen(soPin) : 0, &param);
	showRv(what, rv);
}

static void probeInitToken(CK_SLOT_ID slot, CK_SESSION_HANDLE openSession)
{
	CK_BYTE label[32];
	CK_RV rv;
	section("C_EX_InitToken and C_InitToken");
	if (!opt.format)
	{
		line("    skipped (needs --format: it reformats the token)");
		return;
	}
	memset(label, ' ', sizeof(label));
	memcpy(label, "SoftHSM probe reinit", 20);

	/* With a session still open the device should refuse. */
	line("  with a session still open (expecting CKR_SESSION_EXISTS):");
	exInitToken(slot, opt.soPin, opt.soPin, opt.userPin, 6, 6, 10, 10,
		    label, sizeof(label), "C_EX_InitToken, session open");

	/* Close every session before the real format. */
	if (openSession != CK_INVALID_HANDLE) p11->C_CloseSession(openSession);
	p11->C_CloseAllSessions(slot);

	/* Short SO PINs through the standard C_InitToken (no session needed). */
	line("  standard C_InitToken with short SO PINs:");
	rv = p11->C_InitToken(slot, (CK_UTF8CHAR_PTR) "123", 3, label);
	showRv("C_InitToken, 3-character SO PIN", rv);
	rv = p11->C_InitToken(slot, (CK_UTF8CHAR_PTR) "12345", 5, label);
	showRv("C_InitToken, 5-character SO PIN", rv);

	/* Out-of-range retry and length limits through C_EX_InitToken. */
	line("  C_EX_InitToken with out-of-range limits:");
	exInitToken(slot, opt.soPin, opt.soPin, opt.userPin, 6, 6, 99, 99,
		    label, sizeof(label), "retry counts 99/99");
	exInitToken(slot, opt.soPin, opt.soPin, opt.userPin, 1, 1, 10, 10,
		    label, sizeof(label), "min PIN lengths 1/1");

	/* A real format, then read back the slot id and serial. */
	line("  a real C_EX_InitToken, then slot and serial:");
	exInitToken(slot, opt.soPin, opt.soPin, opt.userPin, 6, 6, 10, 10,
		    label, sizeof(label), "C_EX_InitToken (format)");
	{
		CK_SLOT_ID after[MAX_SLOTS];
		CK_ULONG afterCount = MAX_SLOTS;
		CK_TOKEN_INFO info;
		if (p11->C_GetSlotList(CK_TRUE, after, &afterCount) == CKR_OK && afterCount > 0)
		{
			line("        token now on slot %lu (was %lu)", (unsigned long) after[0], (unsigned long) slot);
			memset(&info, 0, sizeof(info));
			if (p11->C_GetTokenInfo(after[0], &info) == CKR_OK)
				hexDump("        serialNumber", info.serialNumber, 16);
			slot = after[0];
		}
	}

	/* Restore: format back to the starting PINs, label, retries and lengths. */
	line("  restore to the starting state:");
	exInitToken(slot, opt.soPin, opt.soPin, opt.userPin, 6, 6, 10, 10,
		    origLabelKnown ? origLabel : label,
		    origLabelKnown ? (CK_ULONG) sizeof(origLabel) : (CK_ULONG) sizeof(label),
		    "C_EX_InitToken (restore)");
}

/* ---- 9. TC26 published KEG vectors through key import (best effort) ----- */

static void reverseInto(CK_BYTE* dst, const CK_BYTE* src, CK_ULONG len)
{
	CK_ULONG i;
	for (i = 0; i < len; i++) dst[i] = src[len - 1 - i];
}

static int hexToBytes(const char* hex, CK_BYTE* out, CK_ULONG outMax)
{
	CK_ULONG n = 0;
	while (hex[0] && hex[1] && n < outMax)
	{
		unsigned int b;
		if (sscanf(hex, "%2x", &b) != 1) return -1;
		out[n++] = (CK_BYTE) b;
		hex += 2;
	}
	return (int) n;
}

/* Try to import the sample private key and reproduce the published 64-byte
 * ETALON with CKM_GOST_KEG. A real token usually refuses importing raw GOST
 * private-key material; failure is recorded, not an error.
 *
 * The private scalars below are big-endian - SoftHSM's storage order, in
 * which our own module and the end-to-end test reproduce these ETALONs. A
 * real Rutoken takes CKA_VALUE little-endian, so the probe tries the stored
 * big-endian order first and its reverse second, and reports which (if
 * either) matches. The public values and UKM are the published PKCS #11
 * little-endian form, unchanged. */
static void probeKEGImportVectors(CK_SESSION_HANDLE session)
{
	struct { int bits; const char* priv; const char* pub; const char* ukm;
		 const char* etalon; const CK_BYTE* curve; CK_ULONG clen;
		 const CK_BYTE* digest; CK_ULONG dlen; const char* name; } v[] = {
		{ 256,
		  "0debb7875a83206ad1b4167c0a3e35c3c3a75b0aefebcc01d81a18ff9f8e7d9f",
		  "c0ec907466beb2eb5ea1bbd2f6015b710c775b88efca1f558cc81038617f8888"
		  "8884f2471bba3e2468564213f04e71700151747941f6a3032085321e9b3aa602",
		  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		  "bc2b44f590b48adcea709a0485f7054462a7b3bc738d7cbbf972bd309d671900"
		  "39eb73d0237a338ffa142d810f844206fcd36d6296df6f6f9149749b2db1e62b",
		  CURVE_256_A, sizeof(CURVE_256_A), DIGEST_256, sizeof(DIGEST_256), "sample_keg_256" },
		{ 512,
		  "12fd7a70067479a0f66c59f9a25534adfbc7abfd3cc72d79806f8b402601644b"
		  "3005ed365a2d8989a8ccae640d5fc08dd27dfbbfe137cf528e1ac6d445192e01",
		  "c65bd705b6860198bad4a70eb937b6b48084e260adf7b1074a89182862c5bffe"
		  "6486283541330b150fe48a737cb3e5bb043e4a1134035a6d479b189351be41c9"
		  "be9a7e2afc246276fe4e2356845293b03178e2ec003ca8a814324f16350bc0ab"
		  "534187de86c76be29a940a8db2ad71646aa0c952fdf411206548813eb9f754a1",
		  "c3ef0428d4b7a1f4c5025f2e65dd2b2ea583aeefdb67c7f4214a6a298e99e325",
		  "7dac56e48a4dc170faa8fcbae20db845450cccc4c6328bdc8d01157cefa2a5f1"
		  "1f1cbad8866166f01ffaab0152e24bf4609d5f46a5c899c787900d08b9fcad24",
		  CURVE_512_C, sizeof(CURVE_512_C), DIGEST_512, sizeof(DIGEST_512), "sample_keg_512" }
	};
	int i, order;
	section("TC26 published KEG vectors through key import (best effort)");
	line("    note: importing raw GOST private keys is often refused by hardware");
	for (i = 0; i < (int)(sizeof(v) / sizeof(v[0])); i++)
	{
		CK_BYTE priv[64], pub[128], ukm[32], etalon[64];
		CK_BYTE privOrder[64];
		int privLen, pubLen, ukmLen, etalonLen;
		privLen = hexToBytes(v[i].priv, priv, sizeof(priv));
		pubLen = hexToBytes(v[i].pub, pub, sizeof(pub));
		ukmLen = hexToBytes(v[i].ukm, ukm, sizeof(ukm));
		etalonLen = hexToBytes(v[i].etalon, etalon, sizeof(etalon));
		if (privLen < 0 || pubLen < 0 || ukmLen < 0 || etalonLen < 0)
		{ line("    %s: bad vector encoding", v[i].name); continue; }

		line("  %s:", v[i].name);
		for (order = 0; order < 2; order++)
		{
			CK_OBJECT_CLASS privateClass = CKO_PRIVATE_KEY;
			CK_KEY_TYPE keyType = (v[i].bits == 512) ? CKK_GOSTR3410_512 : CKK_GOSTR3410;
			CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
			CK_OBJECT_HANDLE key = CK_INVALID_HANDLE, derived;
			CK_BYTE out[64];
			CK_ULONG outLen = sizeof(out);
			CK_RV rv;
			if (order == 0) memcpy(privOrder, priv, privLen);
			else reverseInto(privOrder, priv, privLen);
			{
				CK_ATTRIBUTE t[] = {
					{ CKA_CLASS, &privateClass, sizeof(privateClass) },
					{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
					{ CKA_TOKEN, &no, sizeof(no) },
					{ CKA_PRIVATE, &yes, sizeof(yes) },
					{ CKA_DERIVE, &yes, sizeof(yes) },
					{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
					{ CKA_ID, (CK_VOID_PTR) PROBE_ID, sizeof(PROBE_ID) },
					{ CKA_VALUE, privOrder, (CK_ULONG) privLen },
					{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) v[i].curve, v[i].clen },
					{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) v[i].digest, v[i].dlen }
				};
				rv = p11->C_CreateObject(session, t, sizeof(t) / sizeof(t[0]), &key);
			}
			line("    import (%s order): rv = %s",
			     order == 0 ? "stored BE" : "reversed LE", rvName(rv));
			if (rv != CKR_OK) continue;
			derived = deriveKEG(session, key, pub, pubLen, ukm, ukmLen,
					    CKK_MAGMA_TWIN_KEY, out, &outLen, "C_DeriveKey against the sample peer");
			if (derived != CK_INVALID_HANDLE)
			{
				if (outLen == (CK_ULONG) etalonLen && memcmp(out, etalon, outLen) == 0)
					line("        MATCHES the published ETALON");
				else if (outLen > 0)
					line("        derived %lu bytes, does NOT match the ETALON", (unsigned long) outLen);
				p11->C_DestroyObject(session, derived);
			}
			p11->C_DestroyObject(session, key);
		}
	}
}

/* ---- loading and main -------------------------------------------------- */

static int loadLibrary(void)
{
	CK_C_GetFunctionList getList;
	CK_C_EX_GetFunctionListExtended getListExtended;
	CK_RV rv;
	libraryHandle = dlopen(opt.module, RTLD_NOW);
	if (libraryHandle == NULL) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 0; }
	getList = (CK_C_GetFunctionList) dlsym(libraryHandle, "C_GetFunctionList");
	if (getList == NULL || getList(&p11) != CKR_OK || p11 == NULL_PTR)
	{ fprintf(stderr, "C_GetFunctionList is missing or failed\n"); return 0; }
	getListExtended = (CK_C_EX_GetFunctionListExtended)
		dlsym(libraryHandle, "C_EX_GetFunctionListExtended");
	if (getListExtended != NULL)
	{
		rv = getListExtended(&ex);
		if (rv != CKR_OK || ex == NULL_PTR)
		{
			fprintf(stderr, "C_EX_GetFunctionListExtended returned 0x%lx\n", (unsigned long) rv);
			ex = NULL_PTR;
		}
	}
	else
		fprintf(stderr, "warning: C_EX_GetFunctionListExtended is not exported; "
				"extension probes will be skipped\n");
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
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_SLOT_ID slot;
	CK_RV rv;
	int i;

	progPath = argv[0];
	opt.userPin = "12345678";
	opt.soPin = "87654321";
	opt.childNew = "445566";

	for (i = 1; i < argc; i++)
	{
		if (argv[i][0] != '-' && opt.module == NULL) opt.module = argv[i];
		else if (strcmp(argv[i], "--user-pin") == 0) opt.userPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--so-pin") == 0) opt.soPin = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--user-pin-env") == 0) opt.userPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--so-pin-env") == 0) opt.soPin = getenv(argValue(argc, argv, &i));
		else if (strcmp(argv[i], "--write") == 0) opt.write = 1;
		else if (strcmp(argv[i], "--format") == 0) { opt.write = 1; opt.format = 1; }
		else if (strcmp(argv[i], "--child") == 0) opt.child = 1;
		else if (strcmp(argv[i], "--child-dir") == 0) opt.childDir = argValue(argc, argv, &i);
		else if (strcmp(argv[i], "--child-new") == 0) opt.childNew = argValue(argc, argv, &i);
		else { fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
	}
	opt.childPin = opt.userPin;

	if (opt.module == NULL)
	{
		fprintf(stderr,
			"usage: %s <path to the Rutoken PKCS #11 library> [options]\n"
			"  --user-pin PIN       user PIN (default 12345678)\n"
			"  --so-pin PIN         SO/administrator PIN (default 87654321)\n"
			"  --user-pin-env NAME  take the user PIN from environment NAME\n"
			"  --so-pin-env NAME    take the SO PIN from environment NAME\n"
			"  --write              run the PIN tests and the attempt-counter walk\n"
			"  --format             also run C_InitToken / C_EX_InitToken (reformats)\n"
			"Everything is non-interactive. The SO PIN is never driven to lockout.\n",
			argv[0]);
		return 2;
	}
	if (opt.userPin == NULL || opt.soPin == NULL)
	{ fprintf(stderr, "a PIN resolved to NULL (bad --*-pin-env?)\n"); return 2; }

	if (!loadLibrary()) return 1;

	if (opt.child)
	{
		int r = runChild();
		if (libraryHandle) dlclose(libraryHandle);
		return r;
	}

	line("Rutoken device probe");
	line("  module    %s", opt.module);
	line("  mode      read + crypto%s%s", opt.write ? " + PIN tests" : "",
	     opt.format ? " + format" : "");
	if (ex) line("  extended table version %u.%u", ex->version.major, ex->version.minor);

	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize returned 0x%lx\n", (unsigned long) rv); return 1; }
	rv = p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK || slotCount == 0)
	{ fprintf(stderr, "no token present (0x%lx)\n", (unsigned long) rv); p11->C_Finalize(NULL_PTR); return 1; }
	slot = slots[0];
	line("  token on slot %lu", (unsigned long) slot);

	probeTokenInfo(slot);

	/* A logged-in user session for everything that creates or uses keys. */
	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv == CKR_OK)
	{
		rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
		showRv("C_Login user for the crypto probes", rv);
	}
	else { showRv("C_OpenSession", rv); session = CK_INVALID_HANDLE; }

	if (session != CK_INVALID_HANDLE)
	{
		deleteProbeObjects(session);
		probeKEGAgreement(session, 256, CURVE_256_A, sizeof(CURVE_256_A), DIGEST_256, sizeof(DIGEST_256));
		probeKEGAgreement(session, 512, CURVE_512_A, sizeof(CURVE_512_A), DIGEST_512, sizeof(DIGEST_512));
		probeKEGImportVectors(session);
		probeGeneration(session);
		probeGostSignParameter(session);
		probeJournal(session, slot);
		probeMemory(session, slot);
		p11->C_Logout(session);
		p11->C_CloseSession(session);
		session = CK_INVALID_HANDLE;
	}

	/* PIN state: own sessions, and no user session open (SO login needs it). */
	probePinFlags(slot);
	probeShortPins(slot);
	probeAttemptCounter(slot);

	probeTwoProcess(slot);

	/* Destructive formatting goes last; it wipes the keys above. */
	probeInitToken(slot, CK_INVALID_HANDLE);

	line("\nDone.");
	p11->C_Finalize(NULL_PTR);
	if (libraryHandle) dlclose(libraryHandle);
	return 0;
}
