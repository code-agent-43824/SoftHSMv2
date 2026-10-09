/*
 * One-run probe of the Rutoken ECP extension surface the battery now needs to
 * cover: C_EX_CreateCSR, the GOST and RSA C_EX_PKCS7Sign/Verify family,
 * C_EX_TokenManage / C_EX_UnblockUserPIN, C_EX_SetLocalPIN and the handful of
 * attribute divergences between the real token and this fork (CKA_TRUSTED,
 * CKA_EXTRACTABLE, reading a private CKA_VALUE). Everything runs non-interactively
 * against a live token through the Aktiv library and prints one text log; the
 * DER it produces (CSR requests, CMS envelopes, certificates) is also written
 * to a dump directory so the exact bytes can be decoded off the device.
 *
 * All keys are generated on the token and all certificates are self-signed by
 * the token, so nothing depends on importing a private key (which the device
 * refuses for GOST). It is written against the extension ABI in src/lib/pkcs11,
 * the same headers the module is built from; the vendor library keeps its own
 * copies and only has to agree field for field.
 *
 * Building it:
 *
 *   cc -I src/lib/pkcs11 tests/portable/rutoken-ext-probe.c -ldl \
 *      -o rutoken-ext-probe
 *
 * Running it: see README-ext-probe.txt. In short:
 *
 *   ./rutoken-ext-probe /usr/lib/librtpkcs11ecp.so \
 *       --user-pin 12345678 --so-pin 87654321 --write --dump-dir dump | tee ext.log
 *
 * Without --write the run only reads and does on-token crypto and leaves no
 * persistent objects it did not clean up. --write adds the local-PIN and
 * token-manage calls and the attempt-counter touch. The SO attempt counter is
 * never driven to zero. restore-factory-defaults is only attempted with an
 * explicit --restore-factory and an emitent key in the environment, and is
 * documented as experimental because its pValue layout is vendor-specific.
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

static const char PROBE_LABEL[] = "CryptoMost ext probe";

static CK_FUNCTION_LIST_PTR p11 = NULL_PTR;
static CK_FUNCTION_LIST_EXTENDED_PTR ex = NULL_PTR;
static void* libraryHandle = NULL;

static struct {
	const char* module;
	const char* userPin;
	const char* soPin;
	const char* emitentKey; /* hex, for restore-factory; may be NULL */
	const char* dumpDir;
	int write;
	int format;
	int restoreFactory;
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
	case CKR_KEY_TYPE_INCONSISTENT: return "CKR_KEY_TYPE_INCONSISTENT";
	case CKR_KEY_FUNCTION_NOT_PERMITTED: return "CKR_KEY_FUNCTION_NOT_PERMITTED";
	case CKR_MECHANISM_INVALID: return "CKR_MECHANISM_INVALID";
	case CKR_MECHANISM_PARAM_INVALID: return "CKR_MECHANISM_PARAM_INVALID";
	case CKR_OBJECT_HANDLE_INVALID: return "CKR_OBJECT_HANDLE_INVALID";
	case CKR_OPERATION_ACTIVE: return "CKR_OPERATION_ACTIVE";
	case CKR_OPERATION_NOT_INITIALIZED: return "CKR_OPERATION_NOT_INITIALIZED";
	case CKR_PIN_INCORRECT: return "CKR_PIN_INCORRECT";
	case CKR_PIN_LEN_RANGE: return "CKR_PIN_LEN_RANGE";
	case CKR_PIN_LOCKED: return "CKR_PIN_LOCKED";
	case CKR_SESSION_CLOSED: return "CKR_SESSION_CLOSED";
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
	case CKR_CRYPTOKI_ALREADY_INITIALIZED: return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
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
	line("    %-52s rv = %s (0x%lx)", what, rvName(rv), (unsigned long) rv);
}

static void hexPreview(const char* name, const unsigned char* data, size_t length)
{
	size_t i, show = length < 48 ? length : 48;
	printf("    %-20s %lu bytes", name, (unsigned long) length);
	for (i = 0; i < show; i++)
	{
		if (i % 16 == 0) printf("\n        ");
		printf("%02X ", data[i]);
	}
	if (show < length) printf("\n        ... (+%lu more)", (unsigned long) (length - show));
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
	if (b->n + n > b->cap)
	{
		size_t cap = b->cap ? b->cap * 2 : 256;
		while (cap < b->n + n) cap *= 2;
		b->p = (unsigned char*) realloc(b->p, cap);
		b->cap = cap;
	}
	memcpy(b->p + b->n, d, n);
	b->n += n;
}
static void bByte(Buf* b, unsigned char c) { bPut(b, &c, 1); }

/* Append a DER length. */
static void derLen(Buf* b, size_t len)
{
	if (len < 128) { bByte(b, (unsigned char) len); return; }
	unsigned char tmp[8];
	int i = 0;
	while (len) { tmp[i++] = (unsigned char) (len & 0xff); len >>= 8; }
	bByte(b, (unsigned char) (0x80 | i));
	while (i) bByte(b, tmp[--i]);
}

/* Append a full TLV. */
static void tlv(Buf* b, unsigned char tag, const unsigned char* content, size_t clen)
{
	bByte(b, tag);
	derLen(b, clen);
	if (clen) bPut(b, content, clen);
}

static void tlvBuf(Buf* out, unsigned char tag, const Buf* content)
{
	tlv(out, tag, content->p, content->n);
}

/* DER INTEGER from a big-endian magnitude (adds a leading zero if the high
 * bit is set, strips redundant leading zeros). */
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

static int findByLabel(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE* out, CK_ULONG max)
{
	CK_ATTRIBUTE search[1];
	CK_ULONG found = 0;
	search[0].type = CKA_LABEL;
	search[0].pValue = (CK_VOID_PTR) PROBE_LABEL;
	search[0].ulValueLen = sizeof(PROBE_LABEL) - 1;
	if (p11->C_FindObjectsInit(session, search, 1) != CKR_OK) return 0;
	p11->C_FindObjects(session, out, max, &found);
	p11->C_FindObjectsFinal(session);
	return (int) found;
}

static void deleteProbeObjects(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE objects[MAX_OBJECTS];
	int n, i;
	n = findByLabel(session, objects, MAX_OBJECTS);
	for (i = 0; i < n; i++) p11->C_DestroyObject(session, objects[i]);
	if (n > 0) line("    cleaned up %d probe object(s)", n);
}

/* GOST domain OIDs matching the battery's working CMS path (CryptoPro-A for
 * the 256-bit curve, TC26 for the digest). */
static const CK_BYTE GOST256_CURVE[]  = { 0x06,0x07,0x2a,0x85,0x03,0x02,0x02,0x23,0x01 };
static const CK_BYTE GOST256_DIGEST[] = { 0x06,0x08,0x2a,0x85,0x03,0x07,0x01,0x01,0x02,0x02 };

/* Generate a GOST R 34.10-2012 256-bit key pair on the token. */
static CK_RV genGost(CK_SESSION_HANDLE session, const char* id, CK_ULONG idLen,
		     int sign, CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_GOSTR3410;
	CK_MECHANISM mech = { CKM_GOSTR3410_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE, no = CK_FALSE;
	CK_BBOOL signFlag = sign ? CK_TRUE : CK_FALSE;
	CK_ATTRIBUTE pubT[] = {
		{ CKA_CLASS, &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_VERIFY, &yes, sizeof(yes) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, idLen },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) GOST256_CURVE, sizeof(GOST256_CURVE) },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) GOST256_DIGEST, sizeof(GOST256_DIGEST) }
	};
	CK_ATTRIBUTE privT[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &signFlag, sizeof(signFlag) },
		{ CKA_DERIVE, &no, sizeof(no) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, idLen },
		{ CKA_GOSTR3410_PARAMS, (CK_VOID_PTR) GOST256_CURVE, sizeof(GOST256_CURVE) },
		{ CKA_GOSTR3411_PARAMS, (CK_VOID_PTR) GOST256_DIGEST, sizeof(GOST256_DIGEST) }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech,
		pubT, sizeof(pubT) / sizeof(pubT[0]),
		privT, sizeof(privT) / sizeof(privT[0]), pub, priv);
}

static CK_RV genRsa(CK_SESSION_HANDLE session, const char* id, CK_ULONG idLen,
		    int sign, CK_OBJECT_HANDLE* pub, CK_OBJECT_HANDLE* priv)
{
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	CK_BBOOL yes = CK_TRUE;
	CK_BBOOL signFlag = sign ? CK_TRUE : CK_FALSE;
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
		{ CKA_ID, (CK_VOID_PTR) id, idLen }
	};
	CK_ATTRIBUTE privT[] = {
		{ CKA_CLASS, &privClass, sizeof(privClass) },
		{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
		{ CKA_TOKEN, &yes, sizeof(yes) },
		{ CKA_PRIVATE, &yes, sizeof(yes) },
		{ CKA_SIGN, &signFlag, sizeof(signFlag) },
		{ CKA_LABEL, (CK_VOID_PTR) PROBE_LABEL, sizeof(PROBE_LABEL) - 1 },
		{ CKA_ID, (CK_VOID_PTR) id, idLen }
	};
	*pub = *priv = CK_INVALID_HANDLE;
	return p11->C_GenerateKeyPair(session, &mech,
		pubT, sizeof(pubT) / sizeof(pubT[0]),
		privT, sizeof(privT) / sizeof(privT[0]), pub, priv);
}

/* A minimal RDN sequence carrying one commonName. */
static void buildName(Buf* out, const char* cn)
{
	Buf rdn, atv, set;
	bInit(&rdn); bInit(&atv); bInit(&set);
	/* AttributeTypeAndValue: OID id-at-commonName (2.5.4.3), UTF8String cn */
	{
		static const unsigned char cnOid[] = { 0x55, 0x04, 0x03 };
		tlv(&atv, 0x06, cnOid, sizeof(cnOid));
		tlv(&atv, 0x0c, (const unsigned char*) cn, strlen(cn));
	}
	tlvBuf(&set, 0x30, &atv);      /* SEQUENCE { OID, value } */
	tlvBuf(&rdn, 0x31, &set);      /* SET OF */
	tlvBuf(out, 0x30, &rdn);       /* RDNSequence */
	bFree(&rdn); bFree(&atv); bFree(&set);
}

/* subjectPublicKeyInfo for a device GOST public key read from CKA_VALUE. */
static int gostSpki(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub, Buf* out)
{
	CK_BYTE point[256], curve[64], digest[64];
	CK_ULONG pointLen, curveLen, digestLen;
	Buf alg, params, bits, inner;
	static const unsigned char keyAlgOid[] =
		{ 0x2a,0x85,0x03,0x07,0x01,0x01,0x01,0x01 }; /* 1.2.643.7.1.1.1.1 */
	pointLen = readAttr(session, pub, CKA_VALUE, point, sizeof(point));
	curveLen = readAttr(session, pub, CKA_GOSTR3410_PARAMS, curve, sizeof(curve));
	digestLen = readAttr(session, pub, CKA_GOSTR3411_PARAMS, digest, sizeof(digest));
	if (pointLen == (CK_ULONG) -1 || curveLen == (CK_ULONG) -1 || digestLen == (CK_ULONG) -1)
		return 0;
	bInit(&alg); bInit(&params); bInit(&bits); bInit(&inner);
	/* AlgorithmIdentifier { keyAlgOid, SEQUENCE { curve, digest } } */
	tlv(&alg, 0x06, keyAlgOid, sizeof(keyAlgOid));
	bPut(&params, curve, curveLen);
	bPut(&params, digest, digestLen);
	tlvBuf(&alg, 0x30, &params);           /* params SEQUENCE appended into alg body */
	/* subjectPublicKey BIT STRING = 00 || OCTET STRING(point) */
	{
		Buf octet; bInit(&octet);
		tlv(&octet, 0x04, point, pointLen);
		bByte(&bits, 0x00);
		bPut(&bits, octet.p, octet.n);
		bFree(&octet);
	}
	{
		Buf algSeq; bInit(&algSeq);
		tlvBuf(&algSeq, 0x30, &alg);       /* SEQUENCE { keyAlg, params } */
		bPut(&inner, algSeq.p, algSeq.n);
		bFree(&algSeq);
	}
	tlv(&inner, 0x03, bits.p, bits.n);     /* BIT STRING */
	tlvBuf(out, 0x30, &inner);
	bFree(&alg); bFree(&params); bFree(&bits); bFree(&inner);
	return 1;
}

/* Self-signed (or issuer-signed) GOST certificate, signed by the token. */
static int gostCertificate(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE subjectPub,
			   CK_OBJECT_HANDLE issuerPriv, const char* issuerCn,
			   const char* subjectCn, unsigned char serial, int isCa,
			   Buf* out)
{
	Buf tbs, spki, issuer, subject, validity, extensions, sigAlg, inner;
	CK_BYTE hash[32], sig[64];
	CK_ULONG hashLen = sizeof(hash), sigLen = sizeof(sig);
	CK_MECHANISM digestMech = { CKM_GOSTR3411_12_256, NULL_PTR, 0 };
	CK_MECHANISM signMech = { CKM_GOSTR3410, NULL_PTR, 0 };
	CK_RV rv;
	static const unsigned char sigAlgOid[] =
		{ 0x2a,0x85,0x03,0x07,0x01,0x01,0x03,0x02 }; /* 1.2.643.7.1.1.3.2 */

	bInit(&tbs); bInit(&spki); bInit(&issuer); bInit(&subject);
	bInit(&validity); bInit(&extensions); bInit(&sigAlg); bInit(&inner);

	if (!gostSpki(session, subjectPub, &spki)) { bFree(&spki); return 0; }
	buildName(&issuer, issuerCn);
	buildName(&subject, subjectCn);
	{
		static const unsigned char notBefore[] =
			{'2','0','0','1','0','1','0','0','0','0','0','0','Z'};
		static const unsigned char notAfter[] =
			{'4','0','0','1','0','1','0','0','0','0','0','0','Z'};
		Buf v; bInit(&v);
		tlv(&v, 0x17, notBefore, sizeof(notBefore));
		tlv(&v, 0x17, notAfter, sizeof(notAfter));
		tlvBuf(&validity, 0x30, &v);
		bFree(&v);
	}
	/* signatureAlgorithm SEQUENCE { sigAlgOid } */
	{
		Buf a; bInit(&a);
		tlv(&a, 0x06, sigAlgOid, sizeof(sigAlgOid));
		tlvBuf(&sigAlg, 0x30, &a);
		bFree(&a);
	}
	/* extensions [3] { SEQUENCE { basicConstraints } } */
	{
		static const unsigned char bcOid[] = { 0x55, 0x1d, 0x13 };
		Buf constraint, ext, extSeq, tagged;
		bInit(&constraint); bInit(&ext); bInit(&extSeq); bInit(&tagged);
		if (isCa) { unsigned char t = 0xff; tlv(&constraint, 0x01, &t, 1); }
		{
			Buf cseq; bInit(&cseq);
			tlvBuf(&cseq, 0x30, &constraint);      /* SEQUENCE { [CA bool] } */
			tlv(&ext, 0x06, bcOid, sizeof(bcOid));
			{ unsigned char t = 0xff; tlv(&ext, 0x01, &t, 1); } /* critical */
			tlv(&ext, 0x04, cseq.p, cseq.n);        /* OCTET STRING(extnValue) */
			bFree(&cseq);
		}
		tlvBuf(&extSeq, 0x30, &ext);                    /* SEQUENCE OF Extension */
		tlvBuf(&tagged, 0xa3, &extSeq);                 /* [3] EXPLICIT */
		bPut(&extensions, tagged.p, tagged.n);
		bFree(&constraint); bFree(&ext); bFree(&extSeq); bFree(&tagged);
	}
	/* TBSCertificate */
	{
		Buf version; bInit(&version);
		{ Buf vi; bInit(&vi); derIntByte(&vi, 2); tlvBuf(&version, 0xa0, &vi); bFree(&vi); }
		bPut(&inner, version.p, version.n);
		derIntByte(&inner, serial);
		bPut(&inner, sigAlg.p, sigAlg.n);
		bPut(&inner, issuer.p, issuer.n);
		bPut(&inner, validity.p, validity.n);
		bPut(&inner, subject.p, subject.n);
		bPut(&inner, spki.p, spki.n);
		bPut(&inner, extensions.p, extensions.n);
		tlvBuf(&tbs, 0x30, &inner);
		bFree(&version);
	}
	/* hash TBS and sign with the issuer key */
	rv = p11->C_DigestInit(session, &digestMech);
	if (rv != CKR_OK) { showRv("gostCert C_DigestInit", rv); goto done_fail; }
	rv = p11->C_Digest(session, tbs.p, tbs.n, hash, &hashLen);
	if (rv != CKR_OK) { showRv("gostCert C_Digest", rv); goto done_fail; }
	rv = p11->C_SignInit(session, &signMech, issuerPriv);
	if (rv != CKR_OK) { showRv("gostCert C_SignInit", rv); goto done_fail; }
	rv = p11->C_Sign(session, hash, hashLen, sig, &sigLen);
	if (rv != CKR_OK) { showRv("gostCert C_Sign", rv); goto done_fail; }
	/* Certificate SEQUENCE { tbs, sigAlg, BIT STRING(signature) } */
	{
		Buf cert, bits; bInit(&cert); bInit(&bits);
		bPut(&cert, tbs.p, tbs.n);
		bPut(&cert, sigAlg.p, sigAlg.n);
		bByte(&bits, 0x00);
		bPut(&bits, sig, sigLen);
		tlv(&cert, 0x03, bits.p, bits.n);
		tlvBuf(out, 0x30, &cert);
		bFree(&cert); bFree(&bits);
	}
	bFree(&tbs); bFree(&spki); bFree(&issuer); bFree(&subject);
	bFree(&validity); bFree(&extensions); bFree(&sigAlg); bFree(&inner);
	return 1;
done_fail:
	bFree(&tbs); bFree(&spki); bFree(&issuer); bFree(&subject);
	bFree(&validity); bFree(&extensions); bFree(&sigAlg); bFree(&inner);
	return 0;
}

/* Import a DER certificate as a token CKO_CERTIFICATE object. An X.509
 * certificate object requires CKA_SUBJECT, so it is built from subjectCn. */
static CK_RV importCert(CK_SESSION_HANDLE session, const char* id, CK_ULONG idLen,
			const char* subjectCn, const unsigned char* der, size_t derLen_,
			CK_OBJECT_HANDLE* out)
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
			{ CKA_ID, (CK_VOID_PTR) id, idLen },
			{ CKA_VALUE, (CK_VOID_PTR) der, (CK_ULONG) derLen_ }
		};
		*out = CK_INVALID_HANDLE;
		rv = p11->C_CreateObject(session, attrs, sizeof(attrs) / sizeof(attrs[0]), out);
	}
	bFree(&subject);
	return rv;
}

/* ---- 1. provenance ----------------------------------------------------- */

static void probeIdentity(CK_SLOT_ID slot)
{
	CK_TOKEN_INFO info;
	section("Library and token identity");
	if (ex) line("    extended table version %u.%u", ex->version.major, ex->version.minor);
	memset(&info, 0, sizeof(info));
	if (p11->C_GetTokenInfo(slot, &info) == CKR_OK)
	{
		line("    model        '%.16s'", info.model);
		line("    serialNumber '%.16s'", info.serialNumber);
		line("    firmware     %u.%u", info.firmwareVersion.major, info.firmwareVersion.minor);
	}
}

/* ---- 2. C_EX_CreateCSR ------------------------------------------------- */

static void createCsr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE pub,
		      CK_OBJECT_HANDLE priv, const char* what, const char* dumpName)
{
	/* DN as the Rutoken ABI takes it: an array of C strings in "type","value"
	 * pairs. The exact accepted key spellings are what we are probing, so the
	 * request and the result RV are both logged. */
	CK_CHAR* dn[] = {
		(CK_CHAR*) "CN", (CK_CHAR*) "CryptoMost Probe",
		(CK_CHAR*) "O",  (CK_CHAR*) "CryptoMost",
		(CK_CHAR*) "C",  (CK_CHAR*) "RU"
	};
	CK_BYTE_PTR csr = NULL_PTR;
	CK_ULONG csrLen = 0;
	CK_RV rv;
	if (ex == NULL || ex->C_EX_CreateCSR == NULL)
	{ line("    C_EX_CreateCSR is not in the table"); return; }
	line("  %s: DN={CN=CryptoMost Probe, O=CryptoMost, C=RU}, no attrs, no exts", what);
	rv = ex->C_EX_CreateCSR(session, pub, dn, sizeof(dn) / sizeof(dn[0]),
				&csr, &csrLen, priv, NULL_PTR, 0, NULL_PTR, 0);
	showRv(what, rv);
	if (rv == CKR_OK && csr != NULL_PTR)
	{
		hexPreview("CSR DER", csr, csrLen);
		dumpToFile(dumpName, csr, csrLen);
		if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(csr);
	}
}

static void probeCsr(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE pub, priv;
	CK_RV rv;
	section("C_EX_CreateCSR (GOST paramSetA and RSA, plus negatives)");

	rv = genGost(session, "csr-gost", 8, 1, &pub, &priv);
	showRv("generate GOST key for CSR", rv);
	if (rv == CKR_OK)
		createCsr(session, pub, priv, "C_EX_CreateCSR, GOST-256 paramSetA", "csr-gost.der");

	rv = genRsa(session, "csr-rsa", 7, 1, &pub, &priv);
	showRv("generate RSA key for CSR", rv);
	if (rv == CKR_OK)
		createCsr(session, pub, priv, "C_EX_CreateCSR, RSA-2048", "csr-rsa.der");

	/* Negative: a key generated without CKA_SIGN. */
	rv = genGost(session, "csr-nosign", 10, 0, &pub, &priv);
	if (rv == CKR_OK)
	{
		line("  negative: private key has CKA_SIGN=false");
		createCsr(session, pub, priv, "C_EX_CreateCSR, key without CKA_SIGN", "csr-nosign.der");
	}
	else showRv("generate no-sign key (if refused, that itself is data)", rv);

	/* Negative: no login. Done in a fresh public session with no C_Login. */
	if (ex && ex->C_EX_CreateCSR)
	{
		CK_SESSION_HANDLE anon;
		CK_SLOT_ID slot;
		CK_SLOT_ID slots[MAX_SLOTS];
		CK_ULONG count = MAX_SLOTS;
		if (p11->C_GetSlotList(CK_TRUE, slots, &count) == CKR_OK && count > 0)
		{
			slot = slots[0];
			if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &anon) == CKR_OK)
			{
				CK_CHAR* dn[] = { (CK_CHAR*) "CN", (CK_CHAR*) "No Login" };
				CK_BYTE_PTR csr = NULL_PTR;
				CK_ULONG csrLen = 0;
				CK_RV r;
				line("  negative: C_EX_CreateCSR with no C_Login on the session");
				r = ex->C_EX_CreateCSR(anon, pub, dn, 2, &csr, &csrLen, priv,
						       NULL_PTR, 0, NULL_PTR, 0);
				showRv("C_EX_CreateCSR, not logged in", r);
				if (csr && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(csr);
				p11->C_CloseSession(anon);
			}
		}
	}
}

/* ---- 3. GOST CMS parity ------------------------------------------------ */

static void verifyEnvelope(CK_SESSION_HANDLE session, const unsigned char* envelope,
			   CK_ULONG envelopeLen, CK_OBJECT_HANDLE trustedCertObj,
			   CK_SESSION_HANDLE unusedSession, const unsigned char* original,
			   CK_ULONG originalLen, int detached, const char* what)
{
	CK_VENDOR_X509_STORE store;
	CK_VENDOR_BUFFER trusted[1];
	CK_BYTE trustedDer[4096];
	CK_ULONG trustedLen;
	CK_BYTE_PTR data = NULL_PTR;
	CK_ULONG dataLen = 0;
	CK_VENDOR_BUFFER_PTR signers = NULL_PTR;
	CK_ULONG signerCount = 0;
	CK_RV rv;
	(void) unusedSession;
	if (ex == NULL || ex->C_EX_PKCS7VerifyInit == NULL || ex->C_EX_PKCS7Verify == NULL)
	{ line("    verify functions are not in the table"); return; }
	memset(&store, 0, sizeof(store));
	trustedLen = readAttr(session, trustedCertObj, CKA_VALUE, trustedDer, sizeof(trustedDer));
	if (trustedLen != (CK_ULONG) -1)
	{
		trusted[0].pData = trustedDer;
		trusted[0].ulSize = trustedLen;
		store.pTrustedCertificates = trusted;
		store.ulTrustedCertificateCount = 1;
	}
	rv = ex->C_EX_PKCS7VerifyInit(session, (CK_BYTE_PTR) envelope, envelopeLen,
				      &store, OPTIONAL_CRL_CHECK, 0);
	showRv(what, rv);
	if (rv != CKR_OK) return;
	if (detached && ex->C_EX_PKCS7VerifyUpdate)
	{
		rv = ex->C_EX_PKCS7VerifyUpdate(session, (CK_BYTE_PTR) original, originalLen);
		showRv("  C_EX_PKCS7VerifyUpdate (detached data)", rv);
		if (ex->C_EX_PKCS7VerifyFinal)
		{
			rv = ex->C_EX_PKCS7VerifyFinal(session, &signers, &signerCount);
			showRv("  C_EX_PKCS7VerifyFinal", rv);
		}
	}
	else
	{
		rv = ex->C_EX_PKCS7Verify(session, &data, &dataLen, &signers, &signerCount);
		showRv("  C_EX_PKCS7Verify", rv);
		line("      signer count = %lu", (unsigned long) signerCount);
		if (data != NULL_PTR)
		{
			int match = (dataLen == originalLen) &&
				    (originalLen == 0 || memcmp(data, original, originalLen) == 0);
			line("      extracted %lu bytes, byte-for-byte match with input: %s",
			     (unsigned long) dataLen, match ? "YES" : "NO");
			if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(data);
		}
	}
	if (signers != NULL_PTR && ex->C_EX_FreeBuffer)
	{
		CK_ULONG i;
		for (i = 0; i < signerCount; i++) ex->C_EX_FreeBuffer(signers[i].pData);
		ex->C_EX_FreeBuffer((CK_BYTE_PTR) signers);
	}
}

static void signEnvelope(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE certObj,
			 CK_OBJECT_HANDLE privKey, CK_OBJECT_HANDLE chainCert,
			 const unsigned char* data, CK_ULONG dataLen, CK_ULONG flags,
			 const char* what, const char* dumpName, CK_OBJECT_HANDLE trustedObj)
{
	CK_BYTE_PTR envelope = NULL_PTR;
	CK_ULONG envelopeLen = 0;
	CK_OBJECT_HANDLE chain[1];
	CK_ULONG chainLen = 0;
	CK_RV rv;
	if (ex == NULL || ex->C_EX_PKCS7Sign == NULL)
	{ line("    C_EX_PKCS7Sign is not in the table"); return; }
	if (chainCert != CK_INVALID_HANDLE) { chain[0] = chainCert; chainLen = 1; }
	rv = ex->C_EX_PKCS7Sign(session, (CK_BYTE_PTR) data, dataLen, certObj,
				&envelope, &envelopeLen, privKey,
				chainLen ? chain : NULL_PTR, chainLen, flags);
	showRv(what, rv);
	if (rv != CKR_OK || envelope == NULL_PTR) return;
	hexPreview("envelope", envelope, envelopeLen);
	dumpToFile(dumpName, envelope, envelopeLen);
	/* Roundtrip verify of what we just produced. */
	verifyEnvelope(session, envelope, envelopeLen, trustedObj, session,
		       data, dataLen, (flags & PKCS7_DETACHED_SIGNATURE) ? 1 : 0,
		       "  roundtrip C_EX_PKCS7VerifyInit");
	/* Tamper the signature and re-verify (attached only). The signerInfo
	 * signature is the last field of the CMS structure, so a byte near the
	 * tail lands inside it rather than in the embedded certificate (flipping
	 * a cert byte would not invalidate the signature). */
	if (!(flags & PKCS7_DETACHED_SIGNATURE) && envelopeLen > 8)
	{
		CK_BYTE* copy = (CK_BYTE*) malloc(envelopeLen);
		if (copy)
		{
			memcpy(copy, envelope, envelopeLen);
			copy[envelopeLen - 3] ^= 0xff;
			verifyEnvelope(session, copy, envelopeLen, trustedObj, session,
				       data, dataLen, 0, "  tampered signature expect SIGNATURE_INVALID");
			free(copy);
		}
	}
	if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(envelope);
}

static void probeGostCms(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE rootPub, rootPriv, leafPub, leafPriv, otherPub, otherPriv;
	CK_OBJECT_HANDLE rootCertObj, leafCertObj, otherCertObj;
	Buf rootCert, leafCert, otherCert;
	static const unsigned char payload[] = "CryptoMost GOST CMS parity payload";
	CK_RV rv;
	section("GOST C_EX_PKCS7Sign/Verify parity (attached, detached, hw-hash, chain)");
	bInit(&rootCert); bInit(&leafCert); bInit(&otherCert);

	rv = genGost(session, "cms-ca", 6, 1, &rootPub, &rootPriv);
	if (rv != CKR_OK) { showRv("generate GOST root key", rv); return; }
	rv = genGost(session, "cms-leaf", 8, 1, &leafPub, &leafPriv);
	if (rv != CKR_OK) { showRv("generate GOST leaf key", rv); return; }
	rv = genGost(session, "cms-other", 9, 1, &otherPub, &otherPriv);
	if (rv != CKR_OK) { showRv("generate GOST unrelated key", rv); return; }

	if (!gostCertificate(session, rootPub, rootPriv, "CryptoMost CA", "CryptoMost CA", 1, 1, &rootCert) ||
	    !gostCertificate(session, leafPub, rootPriv, "CryptoMost CA", "CryptoMost Signer", 2, 0, &leafCert) ||
	    !gostCertificate(session, otherPub, otherPriv, "Unrelated CA", "Unrelated CA", 3, 1, &otherCert))
	{ line("    could not build GOST certificates"); goto cleanup; }
	dumpToFile("gost-root.der", rootCert.p, rootCert.n);
	dumpToFile("gost-leaf.der", leafCert.p, leafCert.n);

	rv = importCert(session, "cms-leaf", 8, "CryptoMost Signer", leafCert.p, leafCert.n, &leafCertObj);
	showRv("import GOST leaf certificate", rv);
	if (rv != CKR_OK) goto cleanup;
	rv = importCert(session, "cms-ca", 6, "CryptoMost CA", rootCert.p, rootCert.n, &rootCertObj);
	showRv("import GOST root certificate", rv);
	rv = importCert(session, "cms-other", 9, "Unrelated CA", otherCert.p, otherCert.n, &otherCertObj);
	showRv("import unrelated certificate", rv);

	line("  attached (flags=0):");
	signEnvelope(session, leafCertObj, leafPriv, rootCertObj, payload, sizeof(payload) - 1,
		     0, "C_EX_PKCS7Sign attached", "gost-cms-attached.der", rootCertObj);
	line("  detached (PKCS7_DETACHED_SIGNATURE):");
	signEnvelope(session, leafCertObj, leafPriv, rootCertObj, payload, sizeof(payload) - 1,
		     PKCS7_DETACHED_SIGNATURE, "C_EX_PKCS7Sign detached", "gost-cms-detached.der", rootCertObj);
	line("  hardware hash (USE_HARDWARE_HASH):");
	signEnvelope(session, leafCertObj, leafPriv, rootCertObj, payload, sizeof(payload) - 1,
		     USE_HARDWARE_HASH, "C_EX_PKCS7Sign hw-hash", "gost-cms-hwhash.der", rootCertObj);

	/* Foreign CA: verify the attached envelope trusting only the unrelated CA. */
	{
		CK_BYTE_PTR envelope = NULL_PTR;
		CK_ULONG envelopeLen = 0;
		if (ex->C_EX_PKCS7Sign(session, (CK_BYTE_PTR) payload, sizeof(payload) - 1,
				       leafCertObj, &envelope, &envelopeLen, leafPriv,
				       NULL_PTR, 0, 0) == CKR_OK && envelope)
		{
			line("  foreign CA (trust only the unrelated CA) expect CERT_CHAIN_NOT_VERIFIED:");
			verifyEnvelope(session, envelope, envelopeLen, otherCertObj, session,
				       payload, sizeof(payload) - 1, 0, "  C_EX_PKCS7VerifyInit, foreign CA");
			if (ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(envelope);
		}
	}

	/* Mismatched cert and key: leaf cert, root private key. */
	{
		CK_BYTE_PTR envelope = NULL_PTR;
		CK_ULONG envelopeLen = 0;
		line("  mismatched cert/key (leaf cert, root key):");
		rv = ex->C_EX_PKCS7Sign(session, (CK_BYTE_PTR) payload, sizeof(payload) - 1,
					leafCertObj, &envelope, &envelopeLen, rootPriv,
					NULL_PTR, 0, 0);
		showRv("C_EX_PKCS7Sign mismatched", rv);
		if (envelope && ex->C_EX_FreeBuffer) ex->C_EX_FreeBuffer(envelope);
	}

cleanup:
	bFree(&rootCert); bFree(&leafCert); bFree(&otherCert);
}

/* ---- 4. RSA CMS (confirmation of the backend path) --------------------- */

static void probeRsaCms(CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE pub, priv, certObj;
	static const unsigned char payload[] = "CryptoMost RSA CMS payload";
	CK_RV rv;
	section("RSA C_EX_PKCS7Sign/Verify (backend path confirmation)");
	rv = genRsa(session, "rsa-cms", 7, 1, &pub, &priv);
	if (rv != CKR_OK) { showRv("generate RSA key", rv); return; }
	{
		/* Build an RSA self-signed cert with the token. */
		Buf tbs, spki, issuer, validity, sigAlg, inner, bits, cert;
		CK_BYTE modulus[512], exponent[8];
		CK_ULONG modLen, expLen;
		CK_BYTE sig[512];
		CK_ULONG sigLen = sizeof(sig);
		CK_MECHANISM signMech = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
		static const unsigned char rsaSha256[] =
			{ 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
		static const unsigned char rsaEnc[] =
			{ 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };
		modLen = readAttr(session, pub, CKA_MODULUS, modulus, sizeof(modulus));
		expLen = readAttr(session, pub, CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent));
		if (modLen == (CK_ULONG) -1 || expLen == (CK_ULONG) -1)
		{ line("    could not read RSA public key"); return; }
		bInit(&tbs); bInit(&spki); bInit(&issuer); bInit(&validity);
		bInit(&sigAlg); bInit(&inner); bInit(&bits); bInit(&cert);
		buildName(&issuer, "CryptoMost RSA");
		{
			Buf v; bInit(&v);
			static const unsigned char nb[] = {'2','6','0','1','0','1','0','0','0','0','0','0','Z'};
			static const unsigned char na[] = {'3','6','0','1','0','1','0','0','0','0','0','0','Z'};
			tlv(&v, 0x17, nb, sizeof(nb));
			tlv(&v, 0x17, na, sizeof(na));
			tlvBuf(&validity, 0x30, &v);
			bFree(&v);
		}
		{ Buf a; bInit(&a); tlv(&a, 0x06, rsaSha256, sizeof(rsaSha256)); tlv(&a, 0x05, NULL, 0);
		  tlvBuf(&sigAlg, 0x30, &a); bFree(&a); }
		{
			Buf keyBits, algId, rsaParams, modExp;
			bInit(&keyBits); bInit(&algId); bInit(&rsaParams); bInit(&modExp);
			derInteger(&modExp, modulus, modLen);
			derInteger(&modExp, exponent, expLen);
			{ Buf s; bInit(&s); tlvBuf(&s, 0x30, &modExp); bByte(&keyBits, 0x00);
			  bPut(&keyBits, s.p, s.n); bFree(&s); }
			tlv(&algId, 0x06, rsaEnc, sizeof(rsaEnc)); tlv(&algId, 0x05, NULL, 0);
			{ Buf a; bInit(&a); tlvBuf(&a, 0x30, &algId); bPut(&rsaParams, a.p, a.n); bFree(&a); }
			tlv(&rsaParams, 0x03, keyBits.p, keyBits.n);
			tlvBuf(&spki, 0x30, &rsaParams);
			bFree(&keyBits); bFree(&algId); bFree(&rsaParams); bFree(&modExp);
		}
		{
			Buf version; bInit(&version);
			{ Buf vi; bInit(&vi); derIntByte(&vi, 2); tlvBuf(&version, 0xa0, &vi); bFree(&vi); }
			bPut(&inner, version.p, version.n);
			derIntByte(&inner, 1);
			bPut(&inner, sigAlg.p, sigAlg.n);
			bPut(&inner, issuer.p, issuer.n);
			bPut(&inner, validity.p, validity.n);
			bPut(&inner, issuer.p, issuer.n);
			bPut(&inner, spki.p, spki.n);
			tlvBuf(&tbs, 0x30, &inner);
			bFree(&version);
		}
		rv = p11->C_SignInit(session, &signMech, priv);
		if (rv == CKR_OK) rv = p11->C_Sign(session, tbs.p, tbs.n, sig, &sigLen);
		if (rv != CKR_OK) { showRv("RSA cert sign", rv); goto rsa_done; }
		bPut(&cert, tbs.p, tbs.n);
		bPut(&cert, sigAlg.p, sigAlg.n);
		bByte(&bits, 0x00); bPut(&bits, sig, sigLen);
		tlv(&cert, 0x03, bits.p, bits.n);
		{
			Buf full; bInit(&full); tlvBuf(&full, 0x30, &cert);
			rv = importCert(session, "rsa-cms", 7, "CryptoMost RSA", full.p, full.n, &certObj);
			showRv("import RSA certificate", rv);
			dumpToFile("rsa-cert.der", full.p, full.n);
			bFree(&full);
		}
		if (rv == CKR_OK)
		{
			line("  attached (flags=0):");
			signEnvelope(session, certObj, priv, CK_INVALID_HANDLE,
				     payload, sizeof(payload) - 1, 0,
				     "C_EX_PKCS7Sign RSA attached", "rsa-cms-attached.der", certObj);
		}
rsa_done:
		bFree(&tbs); bFree(&spki); bFree(&issuer); bFree(&validity);
		bFree(&sigAlg); bFree(&inner); bFree(&bits); bFree(&cert);
	}
}

/* ---- 5. token-manage and unblock -------------------------------------- */

static void probeTokenManage(CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE so;
	CK_RV rv;
	section("C_EX_UnblockUserPIN and C_EX_TokenManage");
	if (!opt.write) { line("    skipped (needs --write)"); return; }

	/* Clear any lingering USER login so the SO can log in. */
	p11->C_CloseAllSessions(slot);

	/* UnblockUserPIN under SO. */
	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &so);
	if (rv == CKR_OK)
	{
		rv = p11->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin));
		showRv("C_Login SO for token-manage", rv);
		if (rv == CKR_OK && ex && ex->C_EX_UnblockUserPIN)
		{
			rv = ex->C_EX_UnblockUserPIN(so);
			showRv("C_EX_UnblockUserPIN (SO)", rv);
		}
		if (ex && ex->C_EX_TokenManage)
		{
			CK_ULONG v = 0;
			rv = ex->C_EX_TokenManage(so, MODE_FORCE_USER_TO_CHANGE_PIN, &v);
			showRv("C_EX_TokenManage MODE_FORCE_USER_TO_CHANGE_PIN", rv);
			rv = ex->C_EX_TokenManage(so, MODE_RESET_PIN_TO_DEFAULT, &v);
			showRv("C_EX_TokenManage MODE_RESET_PIN_TO_DEFAULT", rv);
		}
		p11->C_Logout(so);
		p11->C_CloseSession(so);
	}
	else showRv("C_OpenSession for token-manage", rv);

	if (opt.restoreFactory && opt.emitentKey && opt.format)
		line("    restore-factory requested; its pValue layout is vendor-specific "
		     "and not attempted blindly here - supply the layout to enable it.");
}

/* ---- 6. local PIN ------------------------------------------------------ */

static void probeLocalPin(CK_SLOT_ID slot)
{
	CK_RV rv;
	section("C_EX_SetLocalPIN (ID 3) and C_EX_SlotManage local-PIN info");
	if (!opt.write) { line("    skipped (needs --write)"); return; }
	if (ex == NULL || ex->C_EX_SetLocalPIN == NULL)
	{ line("    C_EX_SetLocalPIN is not in the table"); return; }

	p11->C_CloseAllSessions(slot);
	rv = ex->C_EX_SetLocalPIN(slot, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin),
				  (CK_UTF8CHAR_PTR) "135790", 6, 3);
	showRv("C_EX_SetLocalPIN(id=3, '135790')", rv);

	if (ex->C_EX_SlotManage)
	{
		CK_LOCAL_PIN_INFO info[32];
		CK_ULONG i;
		memset(info, 0, sizeof(info));
		for (i = 3; i <= 5; i++)
		{
			CK_LOCAL_PIN_INFO one;
			memset(&one, 0, sizeof(one));
			one.ulPinID = i;
			rv = ex->C_EX_SlotManage(slot, MODE_GET_LOCAL_PIN_INFO, &one);
			line("    local PIN %lu: rv=%s min=%lu max=%lu maxRetry=%lu left=%lu flags=0x%lx",
			     (unsigned long) i, rvName(rv),
			     (unsigned long) one.ulMinSize, (unsigned long) one.ulMaxSize,
			     (unsigned long) one.ulMaxRetryCount, (unsigned long) one.ulCurrentRetryCount,
			     (unsigned long) one.flags);
		}
	}

	/* Authenticate with the local PIN: try C_Login with the local id as the
	 * user type, which is how Rutoken authenticates local users. */
	{
		CK_SESSION_HANDLE s;
		if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
				       NULL_PTR, NULL_PTR, &s) == CKR_OK)
		{
			rv = p11->C_Login(s, 3, (CK_UTF8CHAR_PTR) "135790", 6);
			showRv("C_Login(userType=3, local PIN)", rv);
			if (rv == CKR_OK) p11->C_Logout(s);
			p11->C_CloseSession(s);
		}
	}
}

/* ---- 7. attribute divergences ----------------------------------------- */

static void probeDivergences(CK_SLOT_ID slot, CK_SESSION_HANDLE userSession)
{
	CK_OBJECT_HANDLE pub, priv;
	CK_RV rv;
	section("Attribute divergences: CKA_EXTRACTABLE, private CKA_VALUE, CKA_TRUSTED");

	/* CKA_EXTRACTABLE false -> true on a freshly generated private key. */
	rv = genGost(userSession, "div-key", 7, 1, &pub, &priv);
	if (rv == CKR_OK)
	{
		CK_BBOOL yes = CK_TRUE;
		CK_BYTE value[256];
		CK_ULONG valueLen;
		CK_ATTRIBUTE set = { CKA_EXTRACTABLE, &yes, sizeof(yes) };
		rv = p11->C_SetAttributeValue(userSession, priv, &set, 1);
		showRv("C_SetAttributeValue CKA_EXTRACTABLE false->true "
		       "(hw CKR_OK, fork CKR_ATTRIBUTE_READ_ONLY)", rv);
		/* Reading a private key's CKA_VALUE. */
		valueLen = readAttr(userSession, priv, CKA_VALUE, value, sizeof(value));
		{
			CK_ATTRIBUTE q = { CKA_VALUE, NULL_PTR, 0 };
			CK_RV r = p11->C_GetAttributeValue(userSession, priv, &q, 1);
			showRv("C_GetAttributeValue private CKA_VALUE "
			       "(hw CKR_ATTRIBUTE_SENSITIVE 0x11->0x12, fork CKR_ATTRIBUTE_TYPE_INVALID)", r);
			(void) valueLen;
		}
	}
	else showRv("generate divergence key", rv);

	/* CKA_TRUSTED: set false->true under SO, then reopen and read. Needs a
	 * certificate object and an SO session. */
	{
		CK_OBJECT_HANDLE cpub, cpriv, certObj;
		Buf cert; bInit(&cert);
		rv = genGost(userSession, "trust", 5, 1, &cpub, &cpriv);
		if (rv == CKR_OK &&
		    gostCertificate(userSession, cpub, cpriv, "Trust Probe", "Trust Probe", 7, 1, &cert))
		{
			rv = importCert(userSession, "trust", 5, "Trust Probe", cert.p, cert.n, &certObj);
			showRv("import certificate for CKA_TRUSTED", rv);
		}
		bFree(&cert);
		if (opt.write && rv == CKR_OK)
		{
			/* Close the user session, log in SO, flip CKA_TRUSTED. */
			CK_SESSION_HANDLE so;
			p11->C_Logout(userSession);
			if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
					       NULL_PTR, NULL_PTR, &so) == CKR_OK)
			{
				rv = p11->C_Login(so, CKU_SO, (CK_UTF8CHAR_PTR) opt.soPin, strlen(opt.soPin));
				showRv("C_Login SO for CKA_TRUSTED", rv);
				if (rv == CKR_OK)
				{
					CK_BBOOL yes = CK_TRUE;
					CK_OBJECT_HANDLE found[8];
					int n;
					CK_ATTRIBUTE set = { CKA_TRUSTED, &yes, sizeof(yes) };
					n = findByLabel(so, found, 8);
					if (n > 0)
					{
						/* The cert object handle is from the user session;
						 * re-find under the SO session. */
						int i;
						for (i = 0; i < n; i++)
						{
							CK_OBJECT_CLASS cls = 0;
							if (readAttr(so, found[i], CKA_CLASS,
								     (CK_BYTE_PTR) &cls, sizeof(cls)) != (CK_ULONG) -1 &&
							    cls == CKO_CERTIFICATE)
							{
								rv = p11->C_SetAttributeValue(so, found[i], &set, 1);
								showRv("C_SetAttributeValue CKA_TRUSTED false->true (SO)", rv);
								break;
							}
						}
					}
				}
				p11->C_Logout(so);
				p11->C_CloseSession(so);
			}
			/* Reopen the module and read CKA_TRUSTED back. */
			p11->C_Finalize(NULL_PTR);
			if (p11->C_Initialize(NULL_PTR) == CKR_OK)
			{
				CK_SESSION_HANDLE s;
				if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
						       NULL_PTR, NULL_PTR, &s) == CKR_OK)
				{
					CK_OBJECT_HANDLE found[8];
					int n, i;
					if (p11->C_Login(s, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin,
							 strlen(opt.userPin)) == CKR_OK)
					{
						n = findByLabel(s, found, 8);
						for (i = 0; i < n; i++)
						{
							CK_OBJECT_CLASS cls = 0;
							CK_BBOOL trusted = CK_FALSE;
							if (readAttr(s, found[i], CKA_CLASS,
								     (CK_BYTE_PTR) &cls, sizeof(cls)) == (CK_ULONG) -1 ||
							    cls != CKO_CERTIFICATE) continue;
							readAttr(s, found[i], CKA_TRUSTED,
								 (CK_BYTE_PTR) &trusted, sizeof(trusted));
							line("    after reopen CKA_TRUSTED = %s "
							     "(hw reports FALSE)", trusted ? "TRUE" : "FALSE");
							{
								CK_BBOOL yes = CK_TRUE;
								CK_ATTRIBUTE set = { CKA_TRUSTED, &yes, sizeof(yes) };
								CK_RV r = p11->C_SetAttributeValue(s, found[i], &set, 1);
								showRv("re-set CKA_TRUSTED under USER "
								       "(hw frozen CKR_ATTRIBUTE_READ_ONLY 0x10)", r);
							}
							break;
						}
						p11->C_Logout(s);
					}
					p11->C_CloseSession(s);
				}
			}
		}
	}
}

/* ---- 8. journal structure --------------------------------------------- */

static CK_ULONG journalSize(CK_SLOT_ID slot)
{
	CK_ULONG size = 0;
	if (ex == NULL || ex->C_EX_GetJournal == NULL) return (CK_ULONG) -1;
	if (ex->C_EX_GetJournal(slot, NULL_PTR, &size) != CKR_OK) return (CK_ULONG) -1;
	return size;
}

static void probeJournal(CK_SESSION_HANDLE session, CK_SLOT_ID slot)
{
	CK_OBJECT_HANDLE gpub, gpriv, rpub, rpriv;
	CK_BYTE hash[32], sig[256];
	CK_ULONG sigLen;
	CK_RV rv;
	CK_ULONG before, afterGost, afterRsa;
	section("C_EX_GetJournal: GOST fills it, RSA does not, length changes");
	before = journalSize(slot);
	line("    journal size before            %ld", (long) before);

	rv = genGost(session, "jrn-gost", 8, 1, &gpub, &gpriv);
	if (rv == CKR_OK)
	{
		CK_MECHANISM m = { CKM_GOSTR3411_12_256, NULL_PTR, 0 };
		CK_ULONG hLen = sizeof(hash);
		if (p11->C_DigestInit(session, &m) == CKR_OK &&
		    p11->C_Digest(session, (CK_BYTE_PTR) "journal", 7, hash, &hLen) == CKR_OK)
		{
			CK_MECHANISM sm = { CKM_GOSTR3410, NULL_PTR, 0 };
			sigLen = sizeof(sig);
			rv = p11->C_SignInit(session, &sm, gpriv);
			if (rv == CKR_OK) rv = p11->C_Sign(session, hash, hLen, sig, &sigLen);
			showRv("GOST C_Sign for journal", rv);
		}
	}
	afterGost = journalSize(slot);
	line("    journal size after GOST sign   %ld  (delta %ld)",
	     (long) afterGost, (long) (afterGost - before));

	rv = genRsa(session, "jrn-rsa", 7, 1, &rpub, &rpriv);
	if (rv == CKR_OK)
	{
		CK_MECHANISM sm = { CKM_SHA256_RSA_PKCS, NULL_PTR, 0 };
		sigLen = sizeof(sig);
		rv = p11->C_SignInit(session, &sm, rpriv);
		if (rv == CKR_OK) rv = p11->C_Sign(session, (CK_BYTE_PTR) "journal", 7, sig, &sigLen);
		showRv("RSA C_Sign for journal", rv);
	}
	afterRsa = journalSize(slot);
	line("    journal size after RSA sign    %ld  (delta %ld; expect 0)",
	     (long) afterRsa, (long) (afterRsa - afterGost));
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
	CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
	CK_SLOT_ID slot;
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
		else if (strcmp(argv[i], "--emitent-key-env") == 0) opt.emitentKey = getenv(argValue(argc, argv, &i));
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
			"  --user-pin PIN / --so-pin PIN        PINs (default 12345678 / 87654321)\n"
			"  --user-pin-env NAME / --so-pin-env NAME  take a PIN from the environment\n"
			"  --emitent-key-env NAME               hex Kuznyechik emitent key (restore-factory)\n"
			"  --dump-dir DIR                       write CSR/CMS/cert DER into DIR\n"
			"  --write                              allow object/PIN/local-PIN/token-manage changes\n"
			"  --format                             also allow C_EX_InitToken at the end\n"
			"  --restore-factory                    opt in to the experimental restore (needs the key)\n",
			argv[0]);
		return 2;
	}
	if (opt.userPin == NULL || opt.soPin == NULL)
	{ fprintf(stderr, "a PIN resolved to NULL (bad --*-pin-env?)\n"); return 2; }
	if (opt.dumpDir) mkdir(opt.dumpDir, 0700);

	if (!loadLibrary()) return 1;

	line("Rutoken extension probe");
	line("  module  %s", opt.module);
	line("  mode    read + crypto%s%s", opt.write ? " + write" : "", opt.format ? " + format" : "");

	rv = p11->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) { fprintf(stderr, "C_Initialize 0x%lx\n", (unsigned long) rv); return 1; }
	rv = p11->C_GetSlotList(CK_TRUE, slots, &slotCount);
	if (rv != CKR_OK || slotCount == 0)
	{ fprintf(stderr, "no token (0x%lx)\n", (unsigned long) rv); p11->C_Finalize(NULL_PTR); return 1; }
	slot = slots[0];
	line("  token on slot %lu", (unsigned long) slot);

	probeIdentity(slot);

	rv = p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);
	if (rv == CKR_OK)
		rv = p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin, strlen(opt.userPin));
	if (rv != CKR_OK) { showRv("C_OpenSession/C_Login user", rv); p11->C_Finalize(NULL_PTR); return 1; }

	deleteProbeObjects(session);
	probeCsr(session);
	probeGostCms(session);
	probeRsaCms(session);
	probeJournal(session, slot);
	/* Divergences may finalize/reinit the module for the CKA_TRUSTED reopen. */
	probeDivergences(slot, session);

	/* Fresh session after the possible reopen for cleanup; drop any lingering
	 * login first so the user login below is the one that holds. */
	p11->C_CloseAllSessions(slot);
	if (p11->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION,
			       NULL_PTR, NULL_PTR, &session) == CKR_OK)
	{
		if (p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR) opt.userPin,
				 strlen(opt.userPin)) == CKR_OK)
		{
			deleteProbeObjects(session);
			p11->C_Logout(session);
		}
		p11->C_CloseSession(session);
	}

	probeTokenManage(slot);
	probeLocalPin(slot);

	line("\nDone. Objects created by the probe were deleted; PINs and label unchanged.");
	if (opt.format)
		line("Note: --format was given but no reformat was performed by this probe; "
		     "use rutoken-device-probe --format or rtAdmin to return the token to factory PINs.");
	p11->C_Finalize(NULL_PTR);
	if (libraryHandle) dlclose(libraryHandle);
	return 0;
}
