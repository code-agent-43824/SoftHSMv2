SoftHSM portable PKCS #11 module
================================

No installer is required. Extract every file from this archive into one
directory and configure your application to load the module from that exact
path:

  Linux:   libsofthsm2.so
  Windows: softhsm2.dll
  macOS:   libsofthsm2.dylib

The module automatically reads softhsm.conf from its own directory. The
included configuration stores tokens in a tokens directory beside the module;
that directory is created on first use. Relative paths in softhsm.conf are
resolved from the configuration file, not from the application's working
directory.

SOFTHSM2_CONF can still override the adjacent configuration file when a custom
location is needed.

The module statically includes OpenSSL and minimized Botan Streebog and GOST
34.10 components. Linux and Windows builds also statically include their C/C++ runtime;
macOS uses the operating system's libc++. There are no non-system runtime
dependencies. Platform system libraries and the operating system loader remain
required.

GOST R 34.11-2012/256 is available through the TC26
CKM_GOSTR3411_2012_256 mechanism for one-shot and multipart PKCS #11 digest
operations. GOST R 34.10-2012/256 key pairs can be generated with
CKM_GOSTR3410_KEY_PAIR_GEN and explicit CKA_GOSTR3410_PARAMS and
CKA_GOSTR3411_PARAMS attributes. Those keys can sign a precomputed 32-byte
digest with CKM_GOSTR3410, or hash and sign one-shot or multipart input with
the TC26 CKM_GOSTR3410_WITH_GOSTR3411_2012_256 mechanism. GOST verification,
MAC, key agreement, CMS construction, and other GOST mechanisms are not enabled.

RSA and GOST public/private key objects can be imported separately with the
standard C_CreateObject function. Private RSA components and the GOST private
scalar can be returned by C_GetAttributeValue only for keys created with
CKA_SENSITIVE=CK_FALSE and CKA_EXTRACTABLE=CK_TRUE. Non-extractable or
sensitive private key material remains unavailable. Public key components are
readable as required by the PKCS #11 object model.

A separately downloadable `softhsm-testkit-<platform>.zip` on the same release
page contains this module and configuration together with the exact precompiled
C++/OpenSSL environment used by the fresh verification runner. Extract that kit
and start `run-test.sh` or `run-test.cmd` with no arguments to reproduce the
complete test. A path to another library may be supplied as the only argument.
The included `testkit.conf` controls initialization, excluded C_* functions,
PINs, slot, and labels.
