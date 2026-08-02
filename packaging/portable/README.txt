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

The module statically includes OpenSSL and the minimized Botan Streebog
component. Linux and Windows builds also statically include their C/C++ runtime;
macOS uses the operating system's libc++. There are no non-system runtime
dependencies. Platform system libraries and the operating system loader remain
required.

GOST R 34.11-2012/256 is available through the TC26
CKM_GOSTR3411_2012_256 mechanism for one-shot and multipart PKCS #11 digest
operations. GOST R 34.10-2012/256 key pairs can be generated with
CKM_GOSTR3410_KEY_PAIR_GEN and explicit CKA_GOSTR3410_PARAMS and
CKA_GOSTR3411_PARAMS attributes. No GOST signing, MAC, key agreement, or other
GOST mechanism is enabled.
