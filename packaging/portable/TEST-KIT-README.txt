SoftHSM portable integration test kit
=====================================

This archive is the exact precompiled test environment produced and executed
by a fresh GitHub Actions verification runner. It is separate from the product
archive so either file can be downloaded independently.

The kit contains:
- a precompiled dependency-light C++ PKCS #11 client;
- a pinned, statically linked OpenSSL CLI used as the independent reference;
- shell or PowerShell launchers;
- the C++ source and PKCS #11 headers for audit/rebuilding;
- the exact environment/tool versions in ENVIRONMENT.txt;
- applicable license texts.

To run, keep the test-kit directory intact and pass either the matching product
ZIP or a directory containing the extracted product files. You may extract the
product directly into the test-kit directory and pass `.`.
The test initializes a disposable token and therefore must not be pointed at a
real token unless you have reviewed the P11_TEST_* settings and explicitly want
that destructive operation.

Linux or macOS:
  bash run-test.sh ../softhsm-portable-<platform>.zip

Windows:
  run-test.cmd ..\softhsm-portable-windows-<architecture>.zip
  run-test.cmd .

An optional second argument selects the directory in which test evidence is
retained. No compiler, SDK, Java, Botan, or separately installed OpenSSL is
required at runtime. Normal operating-system libraries are still required.
The shell launcher restores executable permissions if the ZIP extractor did
not preserve them.
