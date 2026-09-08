SoftHSM portable PKCS #11 module
================================

No installer is required. Extract every file from this archive into one
directory and configure your application to load the module from that exact
path. Always name the module by an absolute path: a relative path given to the
Windows loader is appended to every directory of the DLL search list, and the
system directory is searched ahead of the current one, so a stray copy of
softhsm2.dll elsewhere on the machine would be loaded instead of this one.

  Linux:   libsofthsm2.so
  Windows: softhsm2.dll
  macOS:   libsofthsm2.dylib

The archive also contains two command-line tools:

  softhsm2-util     token initialization, inspection, and import;
  softhsm2-export   forced RSA/ECDSA/GOST private-key export as PKCS#8 PEM or DER.

On Windows both names have the .exe suffix. In a product archive the tools
find the module beside themselves automatically. In a test kit they find it in
the parent directory. softhsm2-util still accepts --module to select another
PKCS #11 library explicitly. All three portable programs use the same fixed
per-user configuration described below.

softhsm2-export is deliberately a debug escape hatch for this software token.
After login it exports a matching RSA, EC, or GOST private key even when the object
has CKA_SENSITIVE=true, CKA_EXTRACTABLE=false, or CKA_NEVER_EXTRACTABLE=true.
It does not modify those attributes and does not weaken C_GetAttributeValue or
C_WrapKey. Select exactly one key with --slot/--serial/--token, --id, --type,
and optionally --label. For example:

  softhsm2-export --token portable-ci-token --id 01 --type rsa \
    --output private-key.pem

The output is unencrypted PKCS#8 PEM by default; use --format der for DER.
The PIN is prompted once unless --pin is supplied. Treat this utility and every exported file as secret-bearing
test material, not as an HSM security boundary.

The module uses one standard configuration per operating-system user:

  Windows:  %USERPROFILE%\softhsm\softhsm.conf
  Linux:    ~/softhsm/softhsm.conf
  macOS:    ~/softhsm/softhsm.conf

On first use the module creates a safe default user configuration if that exact
file does not exist, and creates the token directory the configuration names.
Every later load uses only that user file, so modules extracted into different
directories and 32/64-bit processes see the same token store. The default
relative directories.tokendir = tokens puts the token directory beside the user
configuration; no token directory is copied from or created beside the module.
Relative paths are resolved from the active configuration file, not from the
application's working directory.

softhsm2-util and softhsm2-export create it as well. Until this release only
the module did, so on a machine where the module had never been loaded the two
utilities failed with "Failed to enumerate object store" and needed the
directory made by hand. Nothing has to be created by hand now.

The portable module deliberately ignores SOFTHSM2_CONF, adjacent configuration
files, the process working directory, and system configuration paths. Editing
the one file above changes the mode for every portable module copy used by that
operating-system account.

Each token appears on its own slot. The profile shows fifteen readers, as the
reference device does. Initialized tokens occupy the first of them, one each,
oldest first by the moment the token was created; the spare uninitialized token
SoftHSM always keeps takes the slot after them, so softhsm2-util --init-token
--free works through the profile; the rest are empty readers. The order is the
same on every run, and adding a token does not move the ones already placed.
Removing a token from the middle does shift the ones after it - a slot is held
by the order, not by a stored token-to-slot map - so an application that pins
itself to slot 0 rather than enumerating slots can end up on a different token.
Tokens created by releases before this one carry no creation time, are not
given one, and sort ahead of the rest.

Rutoken ECP compatibility profile
---------------------------------

Set the following in the standard user configuration and restart the process
which loads the PKCS #11 module:

  FAKE_RUTOKEN_ECP = true

The module then reports the Rutoken ECP 2.19 library identity, a 15-slot reader
topology with the token in slot 0, Aktiv/Rutoken token metadata, hardware
version 60.1 and firmware version 30.2, a stable eight-decimal-digit
device-style serial number, and the advertised 6..249 PIN range. A token whose
own label is blank is reported as "Rutoken ECP <no label>", exactly as the
device does; a token that carries a label reports that label as the standard
requires. Session operations addressed to facade slot 0 are routed to the
stored SoftHSM token without exposing its internal slot ID. The profile does
not reset or rewrite objects and does not alter key, import/export,
cryptographic, or actual PIN semantics.

The mechanism list is the reference device's own list of 70 mechanisms, in its
order and with its key sizes and flags, including mechanisms this build does
not implement yet. Advertising them is deliberate: applications routinely
decide compatibility from the list alone, and the remaining algorithms are
planned. An operation asked for with an unimplemented mechanism fails with
CKR_MECHANISM_INVALID rather than producing a wrong result, and a mechanism
absent from the reference device is rejected the same way. Because the list
also gates which mechanisms may be used, the profile makes anything outside
the device's list unavailable while it is enabled. This mode is intended for
application compatibility tests; it does not turn software cryptography into
certified hardware and cannot emulate USB insertion, firmware defects, timing,
or every vendor extension. Set the option to false for normal SoftHSM identity
and behavior.

One vendor mechanism from that list is implemented independently of the
facade: CKM_GOST_KEG derives a 64-byte CKK_MAGMA_TWIN_KEY from a GOST
R 34.10-2012/256 private key, the peer's 64-byte public point and a 32-byte
synchronization value. It accepts the CK_ECDH1_DERIVE_PARAMS call shape used
by Rutoken Plugin. Key unwrap and symmetric encrypt/decrypt operations are not
implemented yet.

While the profile is enabled the module also answers a search for a
CKO_HW_FEATURE object whose CKA_HW_FEATURE_TYPE is the vendor value
CKH_VENDOR_TOKEN_INFO, and reports from it the twenty vendor capability
attributes the reference device carries, with that device's own values and
lengths. Rutoken-aware software reads the device model and its capabilities
from that object and asks for many of the attributes in a single call, where
one it does not get fails the whole call, so a module without the object
cannot answer at all. Addresses the device itself does not carry are refused
here too, 0x80003010 among them: reporting one would be a departure from the
device rather than better compatibility. The object describes hardware rather
than stored data: it needs no login to read, it is not written to the token
store, and it can be neither modified nor destroyed.

The module also exports the Rutoken extended function table through
C_EX_GetFunctionListExtended, because applications written for a Rutoken often
treat the absence of that symbol as proof that the module is not a Rutoken.
Like C_GetFunctionList it answers at any time, including before C_Initialize,
and returning it claims nothing on its own. Of the 34 entries in that table
only C_EX_GetTokenInfoExtended and C_EX_GetTokenName report anything, and only
while the profile is enabled; every other entry returns
CKR_FUNCTION_NOT_SUPPORTED. C_EX_GetTokenName returns the token's label with
its padding removed, in the usual two passes: a null buffer asks for the
length, a short one is refused with CKR_BUFFER_TOO_SMALL. It reports the same
name C_GetTokenInfo does, placeholder included. The functions are described in
docs/RUTOKEN-EXTENSIONS.md.

Two things outside the profile changed as well, and apply whether it is enabled
or not.

C_WaitForSlotEvent now supports its blocking form. Applications that watch for
a device being plugged in or pulled out keep a thread in that call, and a
module which refuses it looks incomplete to them. SoftHSM always keeps one
spare slot holding an uninitialized token; initializing that token is the one
event this library has, and it is reported once, to one waiting caller.
C_Finalize releases a waiting caller with CKR_CRYPTOKI_NOT_INITIALIZED, and a
second concurrent blocking caller is refused with CKR_FUNCTION_FAILED, both as
the standard requires.

CKA_START_DATE and CKA_END_DATE can now be read back from private objects.
Attributes of a private object are stored encrypted; these two were written in
the clear, so any later read of them failed with CKR_GENERAL_ERROR, which broke
every caller that enumerates keys and reads their validity period. Tokens
written by an earlier build keep working: a stored value the size of a CK_DATE
is recognized as one of those and read as it is, and no ciphertext is ever that
short. Dates written from now on are encrypted like every other attribute of a
private object.

The module statically includes OpenSSL and minimized Botan Streebog and GOST
34.10 components. Linux and Windows builds also statically include their C/C++ runtime;
macOS uses the operating system's libc++. There are no non-system runtime
dependencies. Platform system libraries and the operating system loader remain
required.

GOST R 34.11-2012/256 is available through the TC26
CKM_GOSTR3411_2012_256 mechanism for one-shot and multipart PKCS #11 digest
operations. That mechanism accepts the DER object identifier of its parameter
set, 1.2.643.7.1.1.2.2, as the mechanism parameter, because Rutoken-aware
software always sends it; no parameter at all is equally accepted, and any
other parameter is refused with CKR_MECHANISM_PARAM_INVALID. GOST R
34.10-2012/256 key pairs can be generated with CKM_GOSTR3410_KEY_PAIR_GEN and
an explicit CKA_GOSTR3410_PARAMS attribute; CKA_GOSTR3411_PARAMS may be given
but defaults to 1.2.643.7.1.1.2.2 when it is not, which is the only value the
mechanism accepts anyway. The Rutoken per-key vendor attributes 0x80002000 to
0x80002003 are accepted in key templates and stored as booleans.

Those keys can sign a precomputed 32-byte digest with CKM_GOSTR3410, or hash
and sign one-shot or multipart input with the TC26
CKM_GOSTR3410_WITH_GOSTR3411_2012_256 mechanism. That mechanism accepts the
same parameter-set OID the digest mechanism does, since Rutoken-aware software
sends it to both; until this release it refused every parameter, which put
GOST signing out of reach of such software. GOST verification,
MAC, key agreement, CMS construction, and other GOST mechanisms are not enabled.

The 512-bit variants work the same way. GOST R 34.11-2012/512 is available
through CKM_GOSTR3411_12_512, one-shot and multipart, and takes its own
parameter set 1.2.643.7.1.1.2.3 - each mechanism accepts only its own, because
the two OIDs differ in one byte and a mix-up would hash with the wrong
function. GOST R 34.10-2012/512 key pairs are generated with
CKM_GOSTR3410_512_KEY_PAIR_GEN on paramSetA, 1.2.643.7.1.2.1.2.1: the public
CKA_VALUE is 128 bytes of little-endian X||Y and the private scalar is 64.
paramSetB and paramSetC are refused rather than quietly replaced by paramSetA,
because their domain parameters are not in this build. Those keys sign a
precomputed 64-byte digest with CKM_GOSTR3410_512, or hash and sign with
CKM_GOSTR3410_WITH_GOSTR3411_12_512, producing 128 bytes.

Signature verification is available for both key sizes, through C_VerifyInit
and C_Verify with the same mechanisms used to sign. Earlier releases could
produce a GOST signature and not check one.

CKM_MAGMA_CTR_ACPKM and CKM_KUZNECHIK_CTR_ACPKM take a mechanism parameter of
the section length followed by a half-block initialisation vector: four bytes
big-endian, then four bytes for Magma or eight for Kuznechik. The section
length is a number of BITS, which is how the reference device reads it - given
512 it changes the key after 64 bytes, not 512. Releases before this one read
that field as bytes, so their ciphertext parted from the device at byte 65;
anything encrypted by an earlier release with a non-zero section length has to
be decrypted by that release, or by passing eight times the value here. Zero
still means the key is never changed, and any other value must be a whole
number of blocks in bits - 64 for Magma, 128 for Kuznechik.

softhsm2-export takes --type gost512 for the 512-bit private key, alongside
the existing rsa, ec and gost.

RSA and GOST public/private key objects can be imported separately with the
standard C_CreateObject function. Private RSA components and the GOST private
scalar can be returned by C_GetAttributeValue for keys that are not sensitive
and are extractable. Public key components are readable as required by the
PKCS #11 object model.

RUTOKEN_FORCE_SENSITIVE controls whether a generated key keeps its own
material to itself. With FAKE_RUTOKEN_ECP on it defaults to on, because that is
what the device does: C_GetAttributeValue for the private material answers
CKR_ATTRIBUTE_SENSITIVE. With the profile off it defaults to off and ordinary
SoftHSM behaviour is unchanged. Write it in the configuration file by name to
override either default.

While it is on, keys from C_GenerateKey and C_GenerateKeyPair get
CKA_SENSITIVE = CK_TRUE and CKA_EXTRACTABLE = CK_FALSE - but only where the
template did not say. Whatever the template states is kept, either way round,
and asking for a readable key is not an error. The two attributes are handled
separately, so a template that names only CKA_SENSITIVE = CK_FALSE keeps that
and still gets CKA_EXTRACTABLE = CK_FALSE, which is enough on its own to keep
the value in; name both to get a readable key. CKA_ALWAYS_SENSITIVE and
CKA_NEVER_EXTRACTABLE follow the values that end up on the key. Keys imported
with C_CreateObject are not affected, and softhsm2-export still exports a
sensitive key, since that is what it is for.

Read this next paragraph before storing anything you care about.

A key whose template says nothing about CKA_SENSITIVE or CKA_EXTRACTABLE is
readable: this build defaults CKA_SENSITIVE to false and CKA_EXTRACTABLE to
true, so its private material can be read back with C_GetAttributeValue and it
can be wrapped. Upstream SoftHSM defaults CKA_EXTRACTABLE to false, and a
physical token would not surrender private key material at all. The default was
changed deliberately, because software written for a Rutoken derives a session
key with a template naming only its class, type and lifetime and then reads the
value straight back, and the earlier default made that fail. It applies to
every key, private keys included, and whether or not the Rutoken compatibility
profile is enabled.

A template that asks for CKA_SENSITIVE=CK_TRUE or CKA_EXTRACTABLE=CK_FALSE
still gets exactly that, and neither can be turned back afterwards, so any
caller that needs unreadable keys can have them by saying so. Only silence has
changed meaning. If you need silence to keep meaning "unreadable", this build
is not for you.

A separately downloadable `softhsm-testkit-<platform>.zip` on the same release
page contains this module and configuration together with the exact precompiled
C++/OpenSSL/OpenSC environment used by the fresh verification runner. Extract that kit
and start `run-test.sh` or `run-test.cmd` with no arguments to reproduce the
complete test. The final independent gate runs the packaged `pkcs11-tool -I`
and `pkcs11-tool -T`; no separate OpenSC installation is needed. A path to
another library may be supplied as the only argument.
The included `testkit.conf` controls initialization, excluded C_* functions,
PINs, slot, and labels. It also carries both command-line tools and verifies
autonomous softhsm2-util discovery plus forced RSA, ECDSA, and GOST PKCS#8 export.
