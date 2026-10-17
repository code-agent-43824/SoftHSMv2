#!/usr/bin/env bash
# The test kit's TLS block (tls/run.sh in the kit): run-tls.sh against the
# kit's own module, utilities and pkcs11-provider, with the system's OpenSSL 3.
# Test evidence goes to test-output/tls.
#
# On Linux the provider and tls-client need OpenSSL 3 from the distribution
# (Ubuntu 24.04 or newer: the provider build targets Ubuntu 24.04). Where that
# is missing the block says SKIP and why, and exits 0 - unless
# P11_TLS_REQUIRED=1, as in CI, which turns the skip into a failure.
set -euo pipefail

tls_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
kit_dir=$(cd "$tls_dir/.." && pwd)
unset LD_LIBRARY_PATH OPENSSL_CONF OPENSSL_MODULES

skip() {
  if [[ ${P11_TLS_REQUIRED:-0} == 1 ]]; then
    printf '[TLS] FAIL: %s\n' "$1" >&2
    exit 1
  fi
  printf '[TLS] SKIP: %s\n' "$1"
  exit 0
}

case $(uname -s) in
  Linux)
    module="$kit_dir/libsofthsm2.so"
    provider="$tls_dir/provider/lib/ossl-modules/pkcs11.so"
    command -v openssl >/dev/null 2>&1 ||
      skip 'no openssl command; install OpenSSL 3 (apt install openssl)'
    version=$(openssl version)
    [[ $version == 'OpenSSL 3.'* ]] ||
      skip "the system OpenSSL is \"$version\"; the TLS block needs OpenSSL 3 (Ubuntu 24.04 or newer)"
    for binary in "$tls_dir/bin/tls-client" "$provider"; do
      missing=$(ldd "$binary" 2>&1 | grep -E 'not found' || true)
      [[ -z $missing ]] ||
        skip "$(basename "$binary") cannot load here (Ubuntu 24.04 or newer is needed): $(echo "$missing" | head -1 | sed 's/^[[:space:]]*//')"
    done
    ;;
  *)
    skip "the TLS block is not built for $(uname -s) yet"
    ;;
esac

bash "$tls_dir/run-tls.sh" "$module" "$kit_dir/bin/softhsm2-util" "$kit_dir/bin/pkcs11-tool" \
  "$provider" "$tls_dir/bin/tls-client" "$kit_dir/test-output/tls"
