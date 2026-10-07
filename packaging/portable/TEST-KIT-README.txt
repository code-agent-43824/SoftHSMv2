Rutoken ECP emulator integration test kit
=====================================

This archive is the exact precompiled test environment produced and executed
by a fresh GitHub Actions verification runner. It is separate from the product
archive so either file can be downloaded independently.

For copyable OpenSSL commands (GOST digests, keys, signatures, ciphers,
RSA/X.509/CMS) on Linux, macOS and Windows, see OPENSSL-GUIDE.md in this
directory. The guide is in Russian and covers the bundled provider setup.

The kit contains:
- the matching portable SoftHSM module;
- a precompiled dependency-light C++ PKCS #11 client;
- a pinned OpenSSL CLI, its private shared libraries, GOST provider and GOST
  ENGINE for legacy CMS/PKCS#7 (the SoftHSM module remains self-contained);
- the latest portable pkcs11-tool and pkcs11-spy from the
  code-agent-43824/OpenSC fork at build time (release and ZIP SHA-256 in
  OPENSC-SOURCE.txt); no operating-system OpenSC package is copied;
- the portable softhsm2-util and softhsm2-export debug tools;
- shell or PowerShell launchers;
- the C++ source and PKCS #11 headers for audit/rebuilding;
- the exact environment/tool versions in ENVIRONMENT.txt;
- applicable license texts.

To run the bundled SoftHSM module, keep the test-kit directory intact and start
the launcher with no arguments. To test another SoftHSM/PKCS #11 module, pass
the path to that library as the only argument. An explicitly supplied library
is loaded directly from that path and is not copied. The bundled module is also
loaded in place. Test evidence is written only to test-output inside the
extracted test-kit directory.

Isolation and profile: this test kit includes softhsm.conf beside its SoftHSM
library. It selects directories.tokendir = ./tokens, objectstore.backend =
file, and FAKE_RUTOKEN_ECP = true. The bundled token identifies as Rutoken
ECP (manufacturer Aktiv Co., model Rutoken ECP) by default.
The relative token path resolves from that configuration file. With no
SOFTHSM2_CONF, the bundled module, softhsm2-util, pkcs11-tool and pkcs11-spy
use the kit's tokens directory, not ~/softhsm (or %USERPROFILE%\softhsm on
Windows). The launcher creates tokens on first use and reuses the same store
on later runs. Case-specific scratch stores and evidence stay in test-output.
The embedded softhsm2-export utility has a matching bin/softhsm.conf with
../tokens and the same Rutoken profile, so it reaches the same store without
a shell variable.
The standalone product ZIP does not include this configuration.

A readable SOFTHSM2_CONF still has first priority. The launcher preserves it,
but AUTO refuses to choose whether to initialize that explicit store: set
INITIALIZE_TOKEN=YES or NO deliberately. For a different module with its own
adjacent config, AUTO also requires YES or NO. The portable module checks an
adjacent softhsm.conf or softhsm2.conf before the per-user fallback when no
readable explicit override exists; see the product README.

Edit testkit.conf to select token handling and PINs. INITIALIZE_TOKEN=AUTO
initializes the selected SoftHSM when its selected store is empty: the kit's
adjacent store for the bundled module (with or without an explicit path to
that same module), or the per-user fallback for an alternate module without
an override or adjacent config. Otherwise AUTO reuses the selected store.
Successful initialization leaves
a fully initialized token with a working user PIN and persistent test objects.
Later runs reuse the token and replace only objects with the configured test
IDs. YES enables destructive C_InitToken and C_InitPIN. NO disables them and automatically blocks
C_InitToken, C_InitPIN, and C_SetPIN before invocation. EXCLUDED_FUNCTIONS can
block additional C_* entry points. USER_PIN and SO_PIN are stored as plain text
in this local file, so do not publish a customized copy containing real secrets.

The isolated battery checks Rutoken License slots and the persistent GOST
signature journal through the extended function table. The journal is a
software emulation: its 0xB6 TLV contains the operation signature, not a
separate hardware-journal signature. One explicit no-profile GOST 28147 case
remains as a negative comparison; normal test-kit operation uses the Rutoken
profile.

The trace runs GOST and RSA as explicitly separated scenarios. Persistent GOST
and RSA pairs use different labels and IDs, and every persistent-key search
also specifies the key type. CKA_KEY_GEN_MECHANISM is not queried because the
functional result is established by key attributes, persistence, and signing.
PKCS #11 digests, signatures and Kuznechik/Magma CTR-ACPKM output are also
checked against the bundled OpenSSL GOST provider. The external check includes
changed messages and truncated signatures; mechanism-only cases remain tested
with reference vectors where OpenSSL has no matching interface.
The GOST CMS self-check signs and verifies S/MIME and CMS DER envelopes with
the kit-local ENGINE config. scripts/verify-rutoken-cms-cross.sh and .ps1
compare OpenSSL and a physical Rutoken in both directions when the token and
its CA certificate are available; the software-only release matrix does not
claim these hardware checks.
For the bundled module only, the launcher then runs softhsm2-util without a
--module argument, force-exports the persistent sensitive/non-extractable RSA
key, imports a P-256 EC fixture with softhsm2-util, force-exports it, validates
both PKCS#8 files with the bundled OpenSSL, and compares their public keys to
independent references. It also force-exports the persistent sensitive/non-
extractable GOST R 34.10-2012/256 key, validates its PKCS#8 structure and
algorithm, curve, and digest OIDs, then signs and verifies with the bundled
OpenSSL provider. Every run also checks Streebog-256/512 reference vectors,
GOST-2012 256/512 signatures and tamper rejection, and Kuznyechik/Magma CTR
and CTR-ACPKM encryption round trips. These checks do not claim that all
SoftHSM mechanisms have one-to-one OpenSSL provider equivalents.

Linux or macOS:
  bash run-test.sh
  bash run-test.sh /path/to/alternative/libsofthsm2.so

Windows:
  run-test.cmd
  run-test.cmd C:\path\to\alternative\softhsm2.dll

After the complete test, the launcher runs the packaged pkcs11-tool with -I
and -T against the selected module and confirms that the bundled token reports
RUTOKEN_ECP. It also creates a separate disposable Rutoken ECP token, checks --rutoken-info,
--rutoken-name, --rutoken-set-name and --rutoken-set-local-pin, then repeats
the read-only calls through pkcs11-spy and checks its C_EX_* log. Evidence is
saved under test-output. The spy library and its commented configuration
template are in lib/.
The same tool can be used manually without installing OpenSC:

Linux:
  bin/pkcs11-tool --module ./libsofthsm2.so -I
  bin/pkcs11-tool --module ./libsofthsm2.so -T

macOS:
  bin/pkcs11-tool --module ./libsofthsm2.dylib -I
  bin/pkcs11-tool --module ./libsofthsm2.dylib -T

Windows:
  bin\pkcs11-tool.exe --module .\softhsm2.dll -I
  bin\pkcs11-tool.exe --module .\softhsm2.dll -T

No compiler, SDK, Java, Botan, separately installed OpenSSL, or separately
installed OpenSC is required at runtime. Normal operating-system libraries are
still required.
For manual GOST OpenSSL commands, set OPENSSL_CONF to config/openssl-gost.cnf
and OPENSSL_MODULES to bin in the extracted kit. Do not apply that config
globally to SoftHSM utilities: they use their own statically linked OpenSSL.
The launcher scopes it to independent CLI checks. The bundled libraries must
stay next to bin/openssl.
The shell launcher restores executable permissions if the ZIP extractor did
not preserve them.
