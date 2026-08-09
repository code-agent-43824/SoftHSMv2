# Portable PKCS #11 integration test

`portable-token-e2e.cpp` is a dependency-light PKCS #11 consumer. It loads a
module through the operating-system loader and obtains `CK_FUNCTION_LIST`
through `C_GetFunctionList`. It uses standard Cryptoki calls, object classes,
and attributes plus the published TC26 mechanism identifiers for GOST 2012.
It has no SoftHSM, Botan, or OpenSSL link dependency.

Every PKCS #11 call logs its input parameters, mechanism, templates, returned
`CK_RV`, output lengths, object/session handles, and public output bytes. PIN
values and imported/exported private key components are always redacted; their
attribute types and byte lengths remain in the trace. The shell and
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
- `CKM_GOSTR3411_2012_256` (TC26 `0xD4321012`) digesting;
- `CKM_GOSTR3410_KEY_PAIR_GEN` with 256-bit GOST keys;
- raw `CKM_GOSTR3410` and combined TC26
  `CKM_GOSTR3410_WITH_GOSTR3411_2012_256` signing;
- RSA and GOST public/private key import with two standard `C_CreateObject`
  calls, and private-component export through `C_GetAttributeValue` when
  `CKA_SENSITIVE=CK_FALSE` and `CKA_EXTRACTABLE=CK_TRUE`;
- persistent RSA key and X.509 certificate objects.

The runner queries and logs `C_GetMechanismInfo` before using each capability.
A standards-compliant token that does not implement one of these optional
mechanisms fails with an explicit capability error; PKCS #11 compliance alone
does not require every token to implement RSA, SHA-256, or the TC26 extension.

The GOST scenario generates a persistent 2012/256 key pair, signs a
precomputed Streebog-256 digest, signs and hashes the same message in one-shot
and multipart forms, and checks all three randomized signatures with a small
independent implementation of the GOST verification equation in the C++ test.
It also generates exportable RSA and GOST pairs, reads every private component,
imports each pair as separate public and private objects with `C_CreateObject`,
reads the imported values back, and proves the imported private keys by signing.
Negative checks confirm that private components of the normal non-extractable
RSA and GOST keys return `CKR_ATTRIBUTE_SENSITIVE` and
`CK_UNAVAILABLE_INFORMATION`.

PKCS #11 has no single "create key pair" object call: `C_CreateObject` imports
the public and private objects separately. The standard exportability control
is `CKA_EXTRACTABLE`; private values are revealable only when the key is also
non-sensitive (`CKA_SENSITIVE=CK_FALSE`). Public-key material is public and is
readable independently of the private key's extraction policy.

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
export P11_TEST_EXCLUDE_FUNCTIONS='C_InitToken,C_InitPIN,C_SetPIN'
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

`P11_TEST_KEY_LABEL` and `P11_TEST_OBJECT_ID_HEX` configure the persistent RSA
key pair and can be changed to avoid colliding with existing objects. The GOST
pair always uses the separate label `portable-ci-gost2012-256` and a separate
ID derived by appending byte `47` (ASCII `G`) to the configured RSA ID. Searches
also include `CKA_KEY_TYPE`, so RSA and GOST objects cannot be selected for one
another.

The trace contains explicit `BEGIN GOST`/`END GOST`, `BEGIN RSA PREPARE`/
`END RSA PREPARE`, and `BEGIN RSA FINISH`/`END RSA FINISH` boundaries. The
functional test does not request `CKA_KEY_GEN_MECHANISM`; it verifies generated
keys through their type, public material, parameters, persistence, and actual
signing behavior instead.

Token initialization is disabled by default. Setting
`P11_TEST_INITIALIZE_TOKEN=YES` enables `C_InitToken`, SO login, and
`C_InitPIN`; this is destructive and can erase all objects on the selected
hardware token. `P11_TEST_SO_PIN` is required in that mode. If multiple tokens
match, the test stops and requires an explicit `P11_TEST_SLOT_ID` instead of
guessing. `P11_TEST_EXCLUDE_FUNCTIONS` accepts comma-separated exact `C_*`
names and blocks matching calls before the module receives them.

The `run-fresh-integration.*` wrappers are test-kit adapters. They copy the
selected library and configuration into a disposable directory, preserve the
settings selected by `testkit.conf`, call the same generic runner, and then
perform the additional product-specific `tokens`-directory check only for the
module bundled in the kit.

## Downloadable test kits

Every portable release publishes a separate self-contained test kit for each
product platform:

- `softhsm-testkit-linux-x64.zip`;
- `softhsm-testkit-linux-arm64.zip`;
- `softhsm-testkit-windows-x64.zip`;
- `softhsm-testkit-windows-arm64.zip`;
- `softhsm-testkit-macos-universal.zip`.

Each verification job downloads the separately built product artifact, bundles
its module and configuration into the kit, extracts the resulting ZIP, and
executes that exact packaged environment. Only a successful kit is uploaded to
Actions and made eligible for the release aggregation job.

The kit includes the matching portable SoftHSM module and configuration, the
precompiled C++ client, a pinned statically linked OpenSSL CLI, all runtime
launchers, the test source and PKCS #11 headers, licenses, and `ENVIRONMENT.txt`
with the runner and tool versions. No compiler, SDK, Java, Botan, or separately
installed OpenSSL is needed to run it. Normal platform system libraries remain
required.

The downloadable GitHub Actions artifacts contain their files directly; there
is no ZIP nested inside the artifact ZIP. Release assets remain ordinary ZIPs.

After downloading a matching test-kit ZIP, extract it and run the launcher with
no arguments. It automatically selects the bundled SoftHSM library:

```sh
unzip softhsm-testkit-linux-x64.zip -d softhsm-testkit-linux-x64
bash softhsm-testkit-linux-x64/run-test.sh
```

On Windows:

```bat
powershell -NoProfile -Command "Expand-Archive softhsm-testkit-windows-x64.zip softhsm-testkit-windows-x64"
softhsm-testkit-windows-x64\run-test.cmd
```

To test a different library, provide its path as the only argument:

```bat
softhsm-testkit-windows-x64\run-test.cmd C:\path\to\alternative\softhsm2.dll
```

The root `testkit.conf` controls the standalone launcher:

```ini
INITIALIZE_TOKEN=AUTO
EXCLUDED_FUNCTIONS=
USER_PIN=12345678
SO_PIN=12345678
SLOT_ID=
TOKEN_LABEL=
KEY_LABEL=portable-ci-rsa
OBJECT_ID_HEX=504f525441424c45
```

`AUTO` enables initialization only for the module bundled in the kit. Supplying
an alternate library automatically selects existing-token mode. `YES` permits
destructive `C_InitToken` and `C_InitPIN`; `NO` skips them and automatically
adds `C_InitToken,C_InitPIN,C_SetPIN` to the exclusion list. Additional exact
PKCS #11 entry-point names can be placed in `EXCLUDED_FUNCTIONS`, separated by
commas. An excluded function is blocked before the module receives the call;
if the selected scenario requires it, the test stops with an explicit safety
error rather than silently weakening the result.

`USER_PIN` is required. `SO_PIN` is required only when initialization is `YES`.
PIN values are never printed, but this file stores them as plain text; keep a
customized copy containing real credentials private. Use `SLOT_ID` or
`TOKEN_LABEL` when several initialized tokens are visible.

The launcher creates a disposable copy and retains the temporary evidence
directory printed at the end. Existing-token mode still generates test keys and
certificate objects on the selected token; review the scenario before pointing
it at hardware containing valuable objects.
