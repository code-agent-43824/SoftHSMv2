SoftHSM portable integration test kit
=====================================

This archive is the exact precompiled test environment produced and executed
by a fresh GitHub Actions verification runner. It is separate from the product
archive so either file can be downloaded independently.

The kit contains:
- the matching portable SoftHSM module;
- a precompiled dependency-light C++ PKCS #11 client;
- a pinned, statically linked OpenSSL CLI used as the independent reference;
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
initializes the bundled SoftHSM when its canonical token store is empty, leaving
a fully initialized token with a working user PIN and persistent test objects.
Later runs reuse the token and replace only objects with the configured test
IDs. An explicitly
supplied library always uses existing-token mode under AUTO. YES enables
destructive C_InitToken and C_InitPIN. NO disables them and automatically blocks
C_InitToken, C_InitPIN, and C_SetPIN before invocation. EXCLUDED_FUNCTIONS can
block additional C_* entry points. USER_PIN and SO_PIN are stored as plain text
in this local file, so do not publish a customized copy containing real secrets.

The trace runs GOST and RSA as explicitly separated scenarios. Persistent GOST
and RSA pairs use different labels and IDs, and every persistent-key search
also specifies the key type. CKA_KEY_GEN_MECHANISM is not queried because the
functional result is established by key attributes, persistence, and signing.

Linux or macOS:
  bash run-test.sh
  bash run-test.sh /path/to/alternative/libsofthsm2.so

Windows:
  run-test.cmd
  run-test.cmd C:\path\to\alternative\softhsm2.dll

No compiler, SDK, Java, Botan, or separately installed OpenSSL is required at
runtime. Normal operating-system libraries are still required.
The shell launcher restores executable permissions if the ZIP extractor did
not preserve them.
