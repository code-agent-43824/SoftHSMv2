TLS with the key in the Rutoken ECP emulator
============================================

This folder checks the way an application uses a Rutoken through OpenSSL 3:
tls-client opens a TLS connection whose client key lives in the kit's SoftHSM
module under the Rutoken profile (FAKE_RUTOKEN_ECP = true), and OpenSSL
reaches that key through pkcs11-provider.

Run it from the kit directory:

  bash tls/run.sh

run-test.sh runs it as well. Evidence goes to test-output/tls.

What it does, on a fresh token store of its own:
- initializes a token with the Rutoken factory PINs (user 12345678,
  administrator 87654321);
- generates an RSA-2048 and an EC P-256 key pair on it with the kit's
  pkcs11-tool;
- for each key makes a certificate request with `openssl req` through
  pkcs11-provider and signs it with a throwaway CA;
- starts `openssl s_server` on 127.0.0.1 (ports 48443 and 48444, or
  P11_TLS_PORT and the next one), which requires a client certificate from
  that CA and sends every line back reversed;
- runs tls-client with the key's pkcs11: URI and expects its line back.
Every OpenSSL process has to exit with status 0.

Contents:
- bin/tls-client and tls-client.c - the client and its source; it uses only
  the OpenSSL 3.0 API and the system's libssl.so.3 and libcrypto.so.3;
- provider/ - pkcs11-provider from github.com/code-agent-43824/pkcs11-provider,
  the pinned dev release (BUILD-INFO.txt, licenses in COPYING and LICENSES);
- run.sh - checks that the system can run the block and calls run-tls.sh;
- run-tls.sh - the scenario itself, usable with other paths.

Requirements on Linux: OpenSSL 3 from the distribution - Ubuntu 24.04 or newer,
since the provider is built for Ubuntu 24.04. Where it is missing run.sh says
SKIP and why and exits 0; with P11_TLS_REQUIRED=1 it fails instead.
