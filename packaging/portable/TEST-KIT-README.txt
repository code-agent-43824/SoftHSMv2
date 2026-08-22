SoftHSM portable integration test kit
=====================================

This archive is the exact precompiled test environment produced and executed
by a fresh GitHub Actions verification runner. It is separate from the product
archive so either file can be downloaded independently.

The kit contains:
- the matching portable SoftHSM module;
- a precompiled dependency-light C++ PKCS #11 client;
- a pinned, statically linked OpenSSL CLI used as the independent reference;
- a prebuilt OpenSC pkcs11-tool plus its non-system runtime dependencies;
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
extracted test-kit directory. Portable SoftHSM copies always use
~/softhsm/softhsm.conf and ~/softhsm/tokens (under %USERPROFILE% on Windows).

Edit testkit.conf to select token handling and PINs. INITIALIZE_TOKEN=AUTO
initializes the selected SoftHSM when its canonical token store is empty,
whether the bundled module or an explicitly supplied module is used. It leaves
a fully initialized token with a working user PIN and persistent test objects.
Later runs reuse the token and replace only objects with the configured test
IDs. YES enables destructive C_InitToken and C_InitPIN. NO disables them and automatically blocks
C_InitToken, C_InitPIN, and C_SetPIN before invocation. EXCLUDED_FUNCTIONS can
block additional C_* entry points. USER_PIN and SO_PIN are stored as plain text
in this local file, so do not publish a customized copy containing real secrets.

The trace runs GOST and RSA as explicitly separated scenarios. Persistent GOST
and RSA pairs use different labels and IDs, and every persistent-key search
also specifies the key type. CKA_KEY_GEN_MECHANISM is not queried because the
functional result is established by key attributes, persistence, and signing.
For the bundled module only, the launcher then runs softhsm2-util without a
--module argument, force-exports the persistent sensitive/non-extractable RSA
key, imports a P-256 EC fixture with softhsm2-util, force-exports it, validates
both PKCS#8 files with the bundled OpenSSL, and compares their public keys to
independent references. GOST export is intentionally outside this test.

Linux or macOS:
  bash run-test.sh
  bash run-test.sh /path/to/alternative/libsofthsm2.so

Windows:
  run-test.cmd
  run-test.cmd C:\path\to\alternative\softhsm2.dll

After the complete test, the launcher runs the packaged pkcs11-tool with -I
and -T against the selected module. Their output is saved under test-output.
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
The shell launcher restores executable permissions if the ZIP extractor did
not preserve them.
