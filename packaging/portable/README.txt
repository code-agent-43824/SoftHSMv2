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

The module uses one standard configuration per operating-system user:

  Windows:  %USERPROFILE%\softhsm\softhsm.conf
  Linux:    ~/softhsm/softhsm.conf
  macOS:    ~/softhsm/softhsm.conf

On first use the module creates a safe default user configuration if that exact
file does not exist. Every later load uses only that user file, so modules
extracted into different directories and 32/64-bit processes see the same token
store. The default relative
directories.tokendir = tokens creates the token directory beside the user
configuration; no token directory is copied from or created beside the module.
Relative paths are resolved from the active configuration file, not from the
application's working directory.

The portable module deliberately ignores SOFTHSM2_CONF, adjacent configuration
files, the process working directory, and system configuration paths. Editing
the one file above changes the mode for every portable module copy used by that
operating-system account.

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

The module also exports the Rutoken extended function table through
C_EX_GetFunctionListExtended, because applications written for a Rutoken often
treat the absence of that symbol as proof that the module is not a Rutoken.
Like C_GetFunctionList it answers at any time, including before C_Initialize,
and returning it claims nothing on its own. Of the 34 entries in that table
only C_EX_GetTokenInfoExtended reports anything, and only while the profile is
enabled; every other entry returns CKR_FUNCTION_NOT_SUPPORTED. The functions
are described in docs/RUTOKEN-EXTENSIONS.md.

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
CKM_GOSTR3410_WITH_GOSTR3411_2012_256 mechanism. GOST verification,
MAC, key agreement, CMS construction, and other GOST mechanisms are not enabled.

RSA and GOST public/private key objects can be imported separately with the
standard C_CreateObject function. Private RSA components and the GOST private
scalar can be returned by C_GetAttributeValue only for keys created with
CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE. Non-extractable or
sensitive private key material remains unavailable. Public key components are
readable as required by the PKCS #11 object model.

A separately downloadable `softhsm-testkit-<platform>.zip` on the same release
page contains this module and configuration together with the exact precompiled
C++/OpenSSL/OpenSC environment used by the fresh verification runner. Extract that kit
and start `run-test.sh` or `run-test.cmd` with no arguments to reproduce the
complete test. The final independent gate runs the packaged `pkcs11-tool -I`
and `pkcs11-tool -T`; no separate OpenSC installation is needed. A path to
another library may be supplied as the only argument.
The included `testkit.conf` controls initialization, excluded C_* functions,
PINs, slot, and labels.
