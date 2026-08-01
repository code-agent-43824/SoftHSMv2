# Portable PKCS #11 integration test

`portable-token-e2e.cpp` is a dependency-light PKCS #11 consumer. It loads a
module through the operating-system loader, obtains `CK_FUNCTION_LIST` through
`C_GetFunctionList`, and uses only standard Cryptoki calls, mechanisms, object
classes, and attributes. It has no SoftHSM or OpenSSL link dependency.

Every PKCS #11 call logs its input parameters, mechanism, templates, returned
`CK_RV`, output lengths, object/session handles, and public output bytes. PIN
values are always redacted; only their byte lengths are logged. The shell and
PowerShell launchers likewise log every compiler, test-client, OpenSSL, and
content-comparison command.

The implementation was audited against the OASIS PKCS #11 Specification 3.1:
https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html

The generic runner deliberately does not read `softhsm.conf`, call
`softhsm2-util`, assume a SoftHSM slot number, or use a SoftHSM extension. It
requires these standard capabilities from the selected token:

- writable serial sessions and normal SO/user login;
- `CKM_RSA_PKCS_KEY_PAIR_GEN` with 2048-bit keys;
- `CKM_SHA256_RSA_PKCS` signing;
- `CKM_SHA256` digesting;
- persistent RSA key and X.509 certificate objects.

The runner queries and logs `C_GetMechanismInfo` before using each capability.
A standards-compliant token that does not implement one of these optional
mechanisms fails with an explicit capability error; PKCS #11 compliance alone
does not require every token to implement RSA or SHA-256.

Rutoken's published matrices list all functions used here, plus
`CKM_RSA_PKCS_KEY_PAIR_GEN`, `CKM_SHA256_RSA_PKCS`, and `CKM_SHA256`, for
`rtpkcs11ecp` with Rutoken ECP 2.0/3.0-class devices. Rutoken Lite under that
library does not expose the required mechanisms, so it will stop at the
capability check rather than use a vendor workaround:

- https://dev.rutoken.ru/pages/viewpage.action?pageId=3178534
- https://dev.rutoken.ru/pages/viewpage.action?pageId=3178538

The RSA signing-key templates also use the standard attributes recommended by
Rutoken: matching unique `CKA_ID` values, `CKA_ENCRYPT=CK_FALSE` and
`CKA_DECRYPT=CK_FALSE`, and `CK_CERTIFICATE_CATEGORY_TOKEN_USER` for the
certificate. No `CKA_VENDOR_DEFINED` attribute or vendor function is used.

## Running against another vendor module

On Linux or macOS:

```sh
export P11_TEST_INITIALIZE_TOKEN=NO
export P11_TEST_USER_PIN='user-pin'
export P11_TEST_SLOT_ID='12345'             # recommended when several slots exist
export P11_TEST_TOKEN_LABEL='existing-label' # optional exact selector
tests/portable/run-pkcs11-integration.sh \
  /absolute/path/to/vendor-pkcs11.so "$(command -v openssl)"
```

On Windows, set the same environment variables and run:

```powershell
tests/portable/run-pkcs11-integration.ps1 `
  C:\absolute\path\to\vendor-pkcs11.dll C:\absolute\path\to\openssl.exe
```

`P11_TEST_KEY_LABEL` and `P11_TEST_OBJECT_ID_HEX` can be changed to avoid
colliding with existing objects.

Token initialization is disabled by default. Setting
`P11_TEST_INITIALIZE_TOKEN=YES` enables `C_InitToken`, SO login, and
`C_InitPIN`; this is destructive and can erase all objects on the selected
hardware token. `P11_TEST_SO_PIN` is required in that mode. If multiple tokens
match, the test stops and requires an explicit `P11_TEST_SLOT_ID` instead of
guessing.

The `run-fresh-integration.*` wrappers are CI adapters. They unpack a portable
SoftHSM ZIP, explicitly enable initialization for that disposable token, call
the same generic runner, and then perform the additional product-specific
check that the portable module created `tokens` beside itself.
