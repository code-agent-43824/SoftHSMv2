/*
 * Rutoken PKCS #11 extension ABI.
 *
 * Aktiv Co.'s Rutoken PKCS #11 library exports a second function table
 * alongside the standard one, reached through C_EX_GetFunctionListExtended.
 * Applications written against a Rutoken routinely probe for that symbol and
 * treat its absence as "this is not a Rutoken", so the compatibility profile
 * has to answer it.
 *
 * This file declares the binary interface those applications expect: the
 * layout of CK_FUNCTION_LIST_EXTENDED, the order of its members, and the
 * structures and constants the entry points take. It is written from the
 * published Rutoken SDK v.2026 headers (`sdk/pkcs11/include/rtpkcs11f.h`
 * SHA-256 e9014f78682f68685148689a0d99f1dc11a8cf23b65fcbf19a9c04edf055d368,
 * `rtpkcs11t.h` SHA-256
 * 69e7924219c370aa8c785617583b29153f06369637d4a9424c657be153979fdd) rather
 * than copied from them: callers keep including Aktiv's headers, and this
 * declaration only has to agree with them field for field.
 *
 * Types that only appear in entry points we do not implement are declared far
 * enough to make the signature exact; they are not modelled further.
 *
 * See docs/RUTOKEN-EXTENSIONS.md for what each function does and what
 * implementing it would take.
 */

#ifndef _SOFTHSM_V2_RUTOKEN_H
#define _SOFTHSM_V2_RUTOKEN_H

#include "cryptoki.h"

#ifdef _WIN32
#pragma pack(push, rutoken, 1)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Extended token information, filled by C_EX_GetTokenInfoExtended. */
typedef struct CK_TOKEN_INFO_EXTENDED {
	CK_ULONG ulSizeofThisStructure;	/* [in] caller's size, [out] filled size */
	CK_ULONG ulTokenType;		/* deprecated; TOKEN_TYPE_* */
	CK_ULONG ulProtocolNumber;	/* exchange protocol number */
	CK_ULONG ulMicrocodeNumber;	/* microcode number */
	CK_ULONG ulOrderNumber;		/* order number */
	CK_FLAGS flags;			/* TOKEN_FLAGS_* */
	CK_ULONG ulMaxAdminPinLen;
	CK_ULONG ulMinAdminPinLen;
	CK_ULONG ulMaxUserPinLen;
	CK_ULONG ulMinUserPinLen;
	CK_ULONG ulMaxAdminRetryCount;
	CK_ULONG ulAdminRetryCountLeft;	/* 0 means the SO PIN is blocked */
	CK_ULONG ulMaxUserRetryCount;
	CK_ULONG ulUserRetryCountLeft;	/* 0 means the user PIN is blocked */
	CK_BYTE  serialNumber[8];	/* big endian */
	CK_ULONG ulTotalMemory;		/* bytes */
	CK_ULONG ulFreeMemory;		/* bytes */
	CK_BYTE  ATR[64];
	CK_ULONG ulATRLen;
	CK_ULONG ulTokenClass;		/* TOKEN_CLASS_* */
	CK_ULONG ulBatteryVoltage;	/* millivolts; 0 on bus-powered tokens */
	CK_ULONG ulBodyColor;		/* TOKEN_BODY_COLOR_* */
	CK_ULONG ulFirmwareChecksum;
	CK_ULONG ulBatteryPercentage;
	CK_ULONG ulBatteryFlags;
} CK_TOKEN_INFO_EXTENDED;

typedef CK_TOKEN_INFO_EXTENDED CK_PTR CK_TOKEN_INFO_EXTENDED_PTR;

/* Token types, "ulTokenType". Deprecated by the vendor in favour of the
   CKH_VENDOR_TOKEN_INFO hardware feature, but still read by applications. */
#define TOKEN_TYPE_UNKNOWN			0xFFUL
#define TOKEN_TYPE_RUTOKEN_ECP			0x01UL
#define TOKEN_TYPE_RUTOKEN_LITE			0x02UL
#define TOKEN_TYPE_RUTOKEN			0x03UL
#define TOKEN_TYPE_RUTOKEN_PINPAD_FAMILY	0x04UL
#define TOKEN_TYPE_RUTOKEN_MIKRON		0x05UL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_USB		0x09UL
#define TOKEN_TYPE_RUTOKEN_WEB			0x23UL
#define TOKEN_TYPE_RUTOKEN_SC_JC		0x41UL
#define TOKEN_TYPE_RUTOKEN_LITE_SC_JC		0x42UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SC		0x45UL
#define TOKEN_TYPE_RUTOKEN_SCDUAL		0x49UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL	0x4DUL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_BT		0x69UL
#define TOKEN_TYPE_RUTOKEN_ECP_SD		0x81UL
#define TOKEN_TYPE_RUTOKEN_LITE_SD		0x82UL
#define TOKEN_TYPE_RUTOKEN_ECPDUAL_UART		0xA9UL
#define TOKEN_TYPE_RUTOKEN_ECP_NFC		0xC1UL
#define TOKEN_TYPE_RUTOKEN_SCDUAL_NFC		0xC9UL
#define TOKEN_TYPE_RUTOKEN_MIKRON_SCDUAL_NFC	0xCDUL

/* Token flags, "flags", shared with CK_RUTOKEN_INIT_PARAM::ChangeUserPINPolicy. */
#define TOKEN_FLAGS_ADMIN_CHANGE_USER_PIN	0x00000001UL
#define TOKEN_FLAGS_USER_CHANGE_USER_PIN	0x00000002UL
#define TOKEN_FLAGS_ADMIN_PIN_NOT_DEFAULT	0x00000004UL
#define TOKEN_FLAGS_USER_PIN_NOT_DEFAULT	0x00000008UL
#define TOKEN_FLAGS_SUPPORT_FKN			0x00000010UL
#define TOKEN_FLAGS_SUPPORT_FKC			TOKEN_FLAGS_SUPPORT_FKN
#define TOKEN_FLAGS_SUPPORT_SM			0x00000040UL /* deprecated */
#define TOKEN_FLAGS_HAS_FLASH_DRIVE		0x00000080UL
#define TOKEN_FLAGS_CAN_CHANGE_SM_MODE		0x00000100UL /* deprecated */
#define TOKEN_FLAGS_SUPPORT_SECURE_MESSAGING	0x00000100UL
#define TOKEN_FLAGS_HAS_BUTTON			0x00000200UL
#define TOKEN_FLAGS_SUPPORT_JOURNAL		0x00000400UL
#define TOKEN_FLAGS_USER_PIN_UTF8		0x00000800UL
#define TOKEN_FLAGS_ADMIN_PIN_UTF8		0x00001000UL
#define TOKEN_FLAGS_FW_CHECKSUM_UNAVAILIBLE	0x40000000UL
#define TOKEN_FLAGS_FW_CHECKSUM_INVALID		0x80000000UL

/* Token class, "ulTokenClass". */
#define TOKEN_CLASS_UNKNOWN	0xFFFFFFFFUL
#define TOKEN_CLASS_S		0x00UL
#define TOKEN_CLASS_ECP		0x01UL
#define TOKEN_CLASS_LITE	0x02UL
#define TOKEN_CLASS_WEB		0x03UL /* deprecated */
#define TOKEN_CLASS_PINPAD	0x04UL
#define TOKEN_CLASS_ECPDUAL	0x09UL
#define TOKEN_CLASS_ECP_BT	TOKEN_CLASS_ECPDUAL

/* Body colour, "ulBodyColor". */
#define TOKEN_BODY_COLOR_UNKNOWN	0UL
#define TOKEN_BODY_COLOR_WHITE		1UL
#define TOKEN_BODY_COLOR_BLACK		2UL

/* Vendor return values the extension can produce. */
#define CKR_CORRUPTED_MAPFILE		(CKR_VENDOR_DEFINED + 1UL)
#define CKR_WRONG_VERSION_FIELD		(CKR_VENDOR_DEFINED + 2UL)
#define CKR_WRONG_PKCS1_ENCODING	(CKR_VENDOR_DEFINED + 3UL)
#define CKR_RTPKCS11_DATA_CORRUPTED	(CKR_VENDOR_DEFINED + 4UL)
#define CKR_RTPKCS11_RSF_DATA_CORRUPTED	(CKR_VENDOR_DEFINED + 5UL)
#define CKR_SM_PASSWORD_INVALID		(CKR_VENDOR_DEFINED + 6UL)
#define CKR_LICENSE_READ_ONLY		(CKR_VENDOR_DEFINED + 7UL)
#define CKR_VENDOR_EMITENT_KEY_BLOCKED	(CKR_VENDOR_DEFINED + 8UL)
#define CKR_CERT_CHAIN_NOT_VERIFIED	(CKR_VENDOR_DEFINED + 9UL)
#define CKR_INAPPROPRIATE_PIN		(CKR_VENDOR_DEFINED + 10UL)
#define CKR_PIN_IN_HISTORY		(CKR_VENDOR_DEFINED + 11UL)

/* Vendor hardware-feature object. Rutoken-aware software looks for an object
   of class CKO_HW_FEATURE whose CKA_HW_FEATURE_TYPE is CKH_VENDOR_TOKEN_INFO
   and reads the capability attributes below from it. Every one of them is read
   with a buffer already sized by the caller, so the lengths are part of the
   contract: eight bytes for the CK_ULONG-valued ones, one for the booleans. */
#define CKH_VENDOR_TOKEN_INFO			(CKH_VENDOR_DEFINED | 0x00000001UL)

#define CKA_VENDOR_SECURE_MESSAGING_AVAILABLE	(CKA_VENDOR_DEFINED | 0x00003000UL)
#define CKA_VENDOR_CURRENT_SECURE_MESSAGING_MODE (CKA_VENDOR_DEFINED | 0x00003001UL)
#define CKA_VENDOR_CURRENT_TOKEN_INTERFACE	(CKA_VENDOR_DEFINED | 0x00003003UL)
#define CKA_VENDOR_SUPPORTED_TOKEN_INTERFACE	(CKA_VENDOR_DEFINED | 0x00003004UL)
#define CKA_VENDOR_EXTERNAL_AUTHENTICATION	(CKA_VENDOR_DEFINED | 0x00003005UL)
#define CKA_VENDOR_BIOMETRIC_AUTHENTICATION	(CKA_VENDOR_DEFINED | 0x00003006UL)
#define CKA_VENDOR_SUPPORT_CUSTOM_PIN		(CKA_VENDOR_DEFINED | 0x00003007UL)
#define CKA_VENDOR_CUSTOM_ADMIN_PIN		(CKA_VENDOR_DEFINED | 0x00003008UL)
#define CKA_VENDOR_CUSTOM_USER_PIN		(CKA_VENDOR_DEFINED | 0x00003009UL)
#define CKA_VENDOR_SUPPORT_FKC2			(CKA_VENDOR_DEFINED | 0x0000300BUL)
/* Read by Rutoken Plugin together with the block above; absent from the
   published Aktiv headers 2.19 and 2.21, so the name is ours. */
#define CKA_VENDOR_UNDOCUMENTED_800D		(CKA_VENDOR_DEFINED | 0x0000800DUL)

/* Per-key vendor attributes. Rutoken Plugin puts CKA_VENDOR_KEY_JOURNAL in
   every C_GenerateKeyPair template, so a module that rejects unknown
   attributes cannot generate a key for it. */
#define CKA_VENDOR_KEY_PIN_ENTER		(CKA_VENDOR_DEFINED | 0x00002000UL)
#define CKA_VENDOR_KEY_CONFIRM_OP		(CKA_VENDOR_DEFINED | 0x00002001UL)
#define CKA_VENDOR_KEY_JOURNAL			(CKA_VENDOR_DEFINED | 0x00002002UL)
#define CKA_VENDOR_CONFIRM_BY_TOUCH		(CKA_VENDOR_DEFINED | 0x00002003UL)

/* Read from a certificate by isLoginBioRequired(). */
#define CKA_VENDOR_FINGERPRINT_CONVOLUTIONS_ID	(CKA_VENDOR_DEFINED | 0x00003304UL)

/* Token interface, the value of CKA_VENDOR_*_TOKEN_INTERFACE. */
#define TOKEN_INTERFACE_USB			0x01UL
#define TOKEN_INTERFACE_NFC			0x02UL
#define TOKEN_INTERFACE_BLUETOOTH		0x04UL
#define TOKEN_INTERFACE_ISO			0x08UL

/* CKA_VENDOR_CURRENT_SECURE_MESSAGING_MODE when the token has no SM. */
#define SECURE_MESSAGING_MODE_UNSUPPORTED	0xFFUL

/* Full-format parameters for C_EX_InitToken. */
typedef struct CK_RUTOKEN_INIT_PARAM {
	CK_ULONG    ulSizeofThisStructure;
	CK_ULONG    UseRepairMode;
	CK_BYTE_PTR pNewAdminPin;
	CK_ULONG    ulNewAdminPinLen;
	CK_BYTE_PTR pNewUserPin;
	CK_ULONG    ulNewUserPinLen;
	CK_FLAGS    ChangeUserPINPolicy;
	CK_ULONG    ulMinAdminPinLen;
	CK_ULONG    ulMinUserPinLen;
	CK_ULONG    ulMaxAdminRetryCount;
	CK_ULONG    ulMaxUserRetryCount;
	CK_BYTE_PTR pTokenLabel;
	CK_ULONG    ulLabelLen;
	CK_ULONG    ulSmMode;
} CK_RUTOKEN_INIT_PARAM;

typedef CK_RUTOKEN_INIT_PARAM CK_PTR CK_RUTOKEN_INIT_PARAM_PTR;

/* Flash volumes. */
typedef CK_ULONG CK_VOLUME_ID_EXTENDED;
typedef CK_ULONG CK_ACCESS_MODE_EXTENDED;
typedef CK_ULONG CK_OWNER_EXTENDED;

#define ACCESS_MODE_HIDDEN	0x00UL
#define ACCESS_MODE_RO		0x01UL
#define ACCESS_MODE_RW		0x03UL
#define ACCESS_MODE_CD		0x05UL

typedef struct CK_VOLUME_INFO_EXTENDED {
	CK_VOLUME_ID_EXTENDED   idVolume;
	CK_ULONG                ulVolumeSize;
	CK_ACCESS_MODE_EXTENDED accessMode;
	CK_OWNER_EXTENDED       volumeOwner;
	CK_FLAGS                flags;
} CK_VOLUME_INFO_EXTENDED;

typedef struct CK_VOLUME_FORMAT_INFO_EXTENDED {
	CK_ULONG                ulVolumeSize;
	CK_ACCESS_MODE_EXTENDED accessMode;
	CK_OWNER_EXTENDED       volumeOwner;
	CK_FLAGS                flags;
} CK_VOLUME_FORMAT_INFO_EXTENDED;

typedef CK_VOLUME_INFO_EXTENDED CK_PTR CK_VOLUME_INFO_EXTENDED_PTR;
typedef CK_VOLUME_FORMAT_INFO_EXTENDED CK_PTR CK_VOLUME_FORMAT_INFO_EXTENDED_PTR;

/* Local PIN information, returned by C_EX_SlotManage. */
typedef struct CK_LOCAL_PIN_INFO {
	CK_ULONG ulPinID;
	CK_ULONG ulMinSize;
	CK_ULONG ulMaxSize;
	CK_ULONG ulMaxRetryCount;
	CK_ULONG ulCurrentRetryCount;
	CK_FLAGS flags;
} CK_LOCAL_PIN_INFO;

typedef CK_LOCAL_PIN_INFO CK_PTR CK_LOCAL_PIN_INFO_PTR;

#define LOCAL_PIN_FLAGS_NOT_DEFAULT	0x00000001UL
#define LOCAL_PIN_FLAGS_FROM_SCREEN	0x00000002UL
#define LOCAL_PIN_FLAGS_IS_UTF8		0x00000004UL

/* C_EX_SlotManage and C_EX_TokenManage modes. */
#define MODE_SET_BLUETOOTH_POWEROFF_TIMEOUT	0x01UL
#define MODE_SET_CHANNEL_TYPE			0x02UL
#define MODE_RESET_CUSTOM_PIN_TO_STANDARD	0x03UL
#define MODE_RESET_PIN_TO_DEFAULT		0x04UL
#define MODE_GET_IMIT				0x04UL
#define MODE_CHANGE_DEFAULT_PIN			0x05UL
#define MODE_GET_LOCAL_PIN_INFO			0x05UL
#define MODE_FORCE_USER_TO_CHANGE_PIN		0x06UL
#define MODE_RESTORE_FACTORY_DEFAULTS		0x06UL
#define MODE_GET_PIN_SET_TO_BE_CHANGED		0x07UL

/* PKCS #7 signing options for C_EX_PKCS7Sign. */
#define PKCS7_DETACHED_SIGNATURE	0x01UL
#define USE_HARDWARE_HASH		0x02UL

/* Certificate store and verification options for the C_EX_PKCS7Verify family. */
typedef struct CK_VENDOR_BUFFER {
	CK_BYTE_PTR pData;
	CK_ULONG    ulSize;
} CK_VENDOR_BUFFER;

typedef CK_VENDOR_BUFFER CK_PTR CK_VENDOR_BUFFER_PTR;
typedef CK_VENDOR_BUFFER_PTR CK_PTR CK_VENDOR_BUFFER_PTR_PTR;

typedef CK_ULONG CK_VENDOR_CRL_MODE;

typedef struct CK_VENDOR_X509_STORE {
	CK_VENDOR_BUFFER_PTR pTrustedCertificates;
	CK_ULONG             ulTrustedCertificateCount;
	CK_VENDOR_BUFFER_PTR pCertificates;
	CK_ULONG             ulCertificateCount;
	CK_VENDOR_BUFFER_PTR pCrls;
	CK_ULONG             ulCrlCount;
} CK_VENDOR_X509_STORE;

typedef CK_VENDOR_X509_STORE CK_PTR CK_VENDOR_X509_STORE_PTR;

#ifndef CK_BYTE_PTR_PTR_DEFINED
#define CK_BYTE_PTR_PTR_DEFINED
typedef CK_BYTE_PTR CK_PTR CK_BYTE_PTR_PTR;
#endif

#define CKF_VENDOR_DO_NOT_USE_INTERNAL_CMS_CERTS	0x01UL
#define CKF_VENDOR_ALLOW_PARTIAL_CHAINS			0x02UL
#define CKF_VENDOR_CHECK_SIGNATURE_ONLY			0x04UL
#define CKF_VENDOR_USE_TRUSTED_CERTS_FROM_TOKEN		0x08UL

#define OPTIONAL_CRL_CHECK	0UL
#define LEAF_CRL_CHECK		1UL
#define ALL_CRL_CHECK		2UL

/* The extended function table. Member order is part of the ABI: applications
   index it by field, so entries may only be appended, never reordered. */
typedef struct CK_FUNCTION_LIST_EXTENDED CK_FUNCTION_LIST_EXTENDED;
typedef CK_FUNCTION_LIST_EXTENDED CK_PTR CK_FUNCTION_LIST_EXTENDED_PTR;
typedef CK_FUNCTION_LIST_EXTENDED_PTR CK_PTR CK_FUNCTION_LIST_EXTENDED_PTR_PTR;

/* Each entry declares both the exported function and the CK_C_EX_* pointer
   type the table is built from. This mirrors pkcs11.h's own
   _CK_DECLARE_FUNCTION, which cannot be reused here: that macro is written in
   terms of ck_rv_t, a name pkcs11.h removes again before it ends. */
#define _CK_DECLARE_EX_FUNCTION(name, args)	\
typedef CK_RV (*CK_ ## name) args;		\
CK_RV CK_SPEC name args

_CK_DECLARE_EX_FUNCTION (C_EX_GetFunctionListExtended,
		      (CK_FUNCTION_LIST_EXTENDED_PTR_PTR ppFunctionList));
_CK_DECLARE_EX_FUNCTION (C_EX_InitToken,
		      (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin,
		       CK_ULONG ulPinLen, CK_RUTOKEN_INIT_PARAM_PTR pInitInfo));
_CK_DECLARE_EX_FUNCTION (C_EX_GetTokenInfoExtended,
		      (CK_SLOT_ID slotID, CK_TOKEN_INFO_EXTENDED_PTR pInfo));
_CK_DECLARE_EX_FUNCTION (C_EX_UnblockUserPIN,
		      (CK_SESSION_HANDLE hSession));
_CK_DECLARE_EX_FUNCTION (C_EX_SetTokenName,
		      (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pLabel,
		       CK_ULONG ulLabelLen));
_CK_DECLARE_EX_FUNCTION (C_EX_SetLicense,
		      (CK_SESSION_HANDLE hSession, CK_ULONG ulLicenseNum,
		       CK_BYTE_PTR pLicense, CK_ULONG ulLicenseLen));
_CK_DECLARE_EX_FUNCTION (C_EX_GetLicense,
		      (CK_SESSION_HANDLE hSession, CK_ULONG ulLicenseNum,
		       CK_BYTE_PTR pLicense, CK_ULONG_PTR pulLicenseLen));
_CK_DECLARE_EX_FUNCTION (C_EX_GetCertificateInfoText,
		      (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hCert,
		       CK_CHAR_PTR* pInfo, CK_ULONG_PTR pulInfoLen));
_CK_DECLARE_EX_FUNCTION (C_EX_PKCS7Sign,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		       CK_ULONG ulDataLen, CK_OBJECT_HANDLE hCert,
		       CK_BYTE_PTR* ppEnvelope, CK_ULONG_PTR pEnvelopeLen,
		       CK_OBJECT_HANDLE hPrivKey,
		       CK_OBJECT_HANDLE_PTR phCertificates,
		       CK_ULONG ulCertificatesLen, CK_ULONG flags));
_CK_DECLARE_EX_FUNCTION (C_EX_CreateCSR,
		      (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey,
		       CK_CHAR_PTR* dn, CK_ULONG dnLength, CK_BYTE_PTR* pCsr,
		       CK_ULONG_PTR pulCsrLength, CK_OBJECT_HANDLE hPrivKey,
		       CK_CHAR_PTR* pAttributes, CK_ULONG ulAttributesLength,
		       CK_CHAR_PTR* pExtensions, CK_ULONG ulExtensionsLength));
_CK_DECLARE_EX_FUNCTION (C_EX_FreeBuffer,
		      (CK_BYTE_PTR pBuffer));
_CK_DECLARE_EX_FUNCTION (C_EX_GetTokenName,
		      (CK_SESSION_HANDLE hSession, CK_CHAR_PTR pLabel,
		       CK_ULONG_PTR pulLabelLen));
_CK_DECLARE_EX_FUNCTION (C_EX_SetLocalPIN,
		      (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pUserPin,
		       CK_ULONG ulUserPinLen, CK_UTF8CHAR_PTR pNewLocalPin,
		       CK_ULONG ulNewLocalPinLen, CK_ULONG ulLocalID));
_CK_DECLARE_EX_FUNCTION (C_EX_LoadActivationKey,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR key,
		       CK_ULONG keySize));
_CK_DECLARE_EX_FUNCTION (C_EX_SetActivationPassword,
		      (CK_SLOT_ID slotID, CK_UTF8CHAR_PTR password));
_CK_DECLARE_EX_FUNCTION (C_EX_GetVolumesInfo,
		      (CK_SLOT_ID slotID, CK_VOLUME_INFO_EXTENDED_PTR pInfo,
		       CK_ULONG_PTR pulInfoCount));
_CK_DECLARE_EX_FUNCTION (C_EX_GetDriveSize,
		      (CK_SLOT_ID slotID, CK_ULONG_PTR pulDriveSize));
_CK_DECLARE_EX_FUNCTION (C_EX_ChangeVolumeAttributes,
		      (CK_SLOT_ID slotID, CK_USER_TYPE userType,
		       CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		       CK_VOLUME_ID_EXTENDED idVolume,
		       CK_ACCESS_MODE_EXTENDED newAccessMode,
		       CK_BBOOL bPermanent));
_CK_DECLARE_EX_FUNCTION (C_EX_FormatDrive,
		      (CK_SLOT_ID slotID, CK_USER_TYPE userType,
		       CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		       CK_VOLUME_FORMAT_INFO_EXTENDED_PTR pInitParams,
		       CK_ULONG ulInitParamsCount));
_CK_DECLARE_EX_FUNCTION (C_EX_TokenManage,
		      (CK_SESSION_HANDLE hSession, CK_ULONG ulMode,
		       CK_VOID_PTR pValue));
_CK_DECLARE_EX_FUNCTION (C_EX_GenerateActivationPassword,
		      (CK_SESSION_HANDLE hSession, CK_ULONG ulPasswordNumber,
		       CK_UTF8CHAR_PTR pPassword, CK_ULONG_PTR pulPasswordSize,
		       CK_ULONG ulPasswordCharacterSet));
_CK_DECLARE_EX_FUNCTION (C_EX_GetJournal,
		      (CK_SLOT_ID slotID, CK_BYTE_PTR pJournal,
		       CK_ULONG_PTR pulJournalSize));
_CK_DECLARE_EX_FUNCTION (C_EX_SignInvisibleInit,
		      (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		       CK_OBJECT_HANDLE hKey));
_CK_DECLARE_EX_FUNCTION (C_EX_SignInvisible,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		       CK_ULONG_PTR pulSignatureLen));
_CK_DECLARE_EX_FUNCTION (C_EX_SlotManage,
		      (CK_SLOT_ID slotID, CK_ULONG ulMode, CK_VOID_PTR pValue));
_CK_DECLARE_EX_FUNCTION (C_EX_WrapKey,
		      (CK_SESSION_HANDLE hSession,
		       CK_MECHANISM_PTR pGenerationMechanism,
		       CK_ATTRIBUTE_PTR pKeyTemplate,
		       CK_ULONG ulKeyAttributeCount,
		       CK_MECHANISM_PTR pDerivationMechanism,
		       CK_OBJECT_HANDLE hBaseKey,
		       CK_MECHANISM_PTR pWrappingMechanism,
		       CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen,
		       CK_OBJECT_HANDLE_PTR phKey));
_CK_DECLARE_EX_FUNCTION (C_EX_UnwrapKey,
		      (CK_SESSION_HANDLE hSession,
		       CK_MECHANISM_PTR pDerivationMechanism,
		       CK_OBJECT_HANDLE hBaseKey,
		       CK_MECHANISM_PTR pUnwrappingMechanism,
		       CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen,
		       CK_ATTRIBUTE_PTR pKeyTemplate,
		       CK_ULONG ulKeyAttributeCount,
		       CK_OBJECT_HANDLE_PTR phKey));
_CK_DECLARE_EX_FUNCTION (C_EX_PKCS7VerifyInit,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pCms,
		       CK_ULONG ulCmsSize, CK_VENDOR_X509_STORE_PTR pStore,
		       CK_VENDOR_CRL_MODE ckMode, CK_FLAGS flags));
_CK_DECLARE_EX_FUNCTION (C_EX_PKCS7Verify,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR_PTR ppData,
		       CK_ULONG_PTR pulDataSize,
		       CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		       CK_ULONG_PTR pulSignerCertificatesCount));
_CK_DECLARE_EX_FUNCTION (C_EX_PKCS7VerifyUpdate,
		      (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		       CK_ULONG ulDataSize));
_CK_DECLARE_EX_FUNCTION (C_EX_PKCS7VerifyFinal,
		      (CK_SESSION_HANDLE hSession,
		       CK_VENDOR_BUFFER_PTR_PTR ppSignerCertificates,
		       CK_ULONG_PTR pulSignerCertificatesCount));
_CK_DECLARE_EX_FUNCTION (C_EX_Authenticate,
		      (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hAuthObject,
		       CK_BYTE_PTR pData, CK_ULONG ulDataSize));
_CK_DECLARE_EX_FUNCTION (C_EX_Deauthenticate,
		      (CK_SESSION_HANDLE hSession,
		       CK_OBJECT_HANDLE hAuthObject));
_CK_DECLARE_EX_FUNCTION (C_EX_UnblockAuthenticator,
		      (CK_SESSION_HANDLE hSession,
		       CK_OBJECT_HANDLE hAuthObject));

#undef _CK_DECLARE_EX_FUNCTION

struct CK_FUNCTION_LIST_EXTENDED {
	CK_VERSION version;

	CK_C_EX_GetFunctionListExtended		C_EX_GetFunctionListExtended;
	CK_C_EX_InitToken			C_EX_InitToken;
	CK_C_EX_GetTokenInfoExtended		C_EX_GetTokenInfoExtended;
	CK_C_EX_UnblockUserPIN			C_EX_UnblockUserPIN;
	CK_C_EX_SetTokenName			C_EX_SetTokenName;
	CK_C_EX_SetLicense			C_EX_SetLicense;
	CK_C_EX_GetLicense			C_EX_GetLicense;
	CK_C_EX_GetCertificateInfoText		C_EX_GetCertificateInfoText;
	CK_C_EX_PKCS7Sign			C_EX_PKCS7Sign;
	CK_C_EX_CreateCSR			C_EX_CreateCSR;
	CK_C_EX_FreeBuffer			C_EX_FreeBuffer;
	CK_C_EX_GetTokenName			C_EX_GetTokenName;
	CK_C_EX_SetLocalPIN			C_EX_SetLocalPIN;
	CK_C_EX_LoadActivationKey		C_EX_LoadActivationKey;
	CK_C_EX_SetActivationPassword		C_EX_SetActivationPassword;
	CK_C_EX_GetVolumesInfo			C_EX_GetVolumesInfo;
	CK_C_EX_GetDriveSize			C_EX_GetDriveSize;
	CK_C_EX_ChangeVolumeAttributes		C_EX_ChangeVolumeAttributes;
	CK_C_EX_FormatDrive			C_EX_FormatDrive;
	CK_C_EX_TokenManage			C_EX_TokenManage;
	CK_C_EX_GenerateActivationPassword	C_EX_GenerateActivationPassword;
	CK_C_EX_GetJournal			C_EX_GetJournal;
	CK_C_EX_SignInvisibleInit		C_EX_SignInvisibleInit;
	CK_C_EX_SignInvisible			C_EX_SignInvisible;
	CK_C_EX_SlotManage			C_EX_SlotManage;
	CK_C_EX_WrapKey				C_EX_WrapKey;
	CK_C_EX_UnwrapKey			C_EX_UnwrapKey;
	CK_C_EX_PKCS7VerifyInit			C_EX_PKCS7VerifyInit;
	CK_C_EX_PKCS7Verify			C_EX_PKCS7Verify;
	CK_C_EX_PKCS7VerifyUpdate		C_EX_PKCS7VerifyUpdate;
	CK_C_EX_PKCS7VerifyFinal		C_EX_PKCS7VerifyFinal;
	CK_C_EX_Authenticate			C_EX_Authenticate;
	CK_C_EX_Deauthenticate			C_EX_Deauthenticate;
	CK_C_EX_UnblockAuthenticator		C_EX_UnblockAuthenticator;
};

#ifdef __cplusplus
}
#endif

#ifdef _WIN32
#pragma pack(pop, rutoken)
#endif

#endif /* !_SOFTHSM_V2_RUTOKEN_H */
