#!/usr/bin/env bash
# GOST CMS between a PKCS #11 module - the physical Rutoken through the
# vendor's library, or this fork - and the kit's independent OpenSSL, both
# ways, in one run. Non-interactive: it never reads the terminal. Needs only
# an initialized token: no format, no SO PIN, no certificate prepared in
# advance. The user PIN comes from P11_TEST_USER_PIN or, when that is not set,
# is the factory 12345678 - used only if the token reports its user PIN
# unchanged; otherwise B is skipped without a login attempt.
#   A: OpenSSL envelopes (S/MIME and CMS, CryptoPro-A and TC26-A) verified by
#      C_EX_PKCS7Verify on the token with OpenSSL's CA trusted;
#   B: C_EX_PKCS7Sign envelopes (attached and detached) under a root and a
#      signer the token makes itself, verified by OpenSSL smime and cms.
# Everything goes to test-output/cms-cross-<time> and one .tar.gz to send.
set -uo pipefail

if [[ $# != 2 ]]; then
  echo 'usage: rutoken-cms-cross-probe.sh <kit-dir> <module>' >&2
  exit 2
fi
kit=$(cd "$1" && pwd)
module=$2

stamp=$(date -u +%Y%m%dT%H%M%SZ)
name="cms-cross-$stamp"
out="$kit/test-output/$name"
mkdir -p "$out"
exec > >(tee "$out/probe.log") 2>&1

openssl="$kit/bin/openssl"
export OPENSSL_CONF="$kit/config/openssl-gost-engine.cnf"
export OPENSSL_ENGINES="$kit/bin"
export OPENSSL_MODULES="$kit/bin"
failures=0
pass() { echo "[CMS-CROSS] PASS: $*"; }
failed() { echo "[CMS-CROSS] FAIL: $*"; failures=$((failures + 1)); }

echo "[CMS-CROSS] $(date -u +%Y-%m-%dT%H:%M:%SZ), module $module"
uname -a
"$openssl" version

if ! bash "$kit/scripts/verify-gost-cms.sh" "$kit" < /dev/null > "$out/openssl-self-test.log" 2>&1; then
  cat "$out/openssl-self-test.log"
  echo '[CMS-CROSS] FAIL: the kit OpenSSL could not make its envelopes; nothing sent to the token'
  exit 1
fi
cp -R "$kit/test-output/gost-cms" "$out/openssl"
pass 'kit OpenSSL made S/MIME and CMS envelopes on CryptoPro-A and TC26-A'

"$kit/bin/portable-token-e2e" cms-cross "$module" "$out/openssl" \
  < /dev/null > "$out/token.log" 2>&1
token_rc=$?
grep -F '[CMS-CROSS]' "$out/token.log"
if [[ $token_rc != 0 ]]; then
  grep -vF '[CMS-CROSS]' "$out/token.log" | tail -n 20
  failed "token side exited with $token_rc (full trace in token.log)"
fi
failures=$((failures + $(grep -c '^\[CMS-CROSS\] FAIL' "$out/token.log")))

t="$out/openssl/rutoken"
if [[ -s $t/attached.der && -s $t/detached.der ]]; then
  "$openssl" x509 -inform DER -in "$t/root.der" -out "$t/root.pem"
  "$openssl" asn1parse -inform DER -in "$t/attached.der" > "$t/attached-asn1.txt"
  for mode in smime cms; do
    if "$openssl" "$mode" -verify -binary -inform DER -in "$t/attached.der" \
         -CAfile "$t/root.pem" -out "$t/$mode-attached.bin" 2> "$t/$mode-attached.err" &&
       cmp -s "$t/content.bin" "$t/$mode-attached.bin"; then
      pass "B: token attached envelope verified by OpenSSL $mode"
    else
      cat "$t/$mode-attached.err"
      failed "B: token attached envelope rejected by OpenSSL $mode"
    fi
    if "$openssl" "$mode" -verify -binary -inform DER -in "$t/detached.der" \
         -content "$t/content.bin" -CAfile "$t/root.pem" \
         -out "$t/$mode-detached.bin" 2> "$t/$mode-detached.err"; then
      pass "B: token detached envelope verified by OpenSSL $mode"
    else
      cat "$t/$mode-detached.err"
      failed "B: token detached envelope rejected by OpenSSL $mode"
    fi
  done
else
  failed 'B: the token made no envelopes'
fi

(cd "$kit/test-output" && tar -czf "$name.tar.gz" "$name")
if [[ $failures == 0 ]]; then
  echo '[CMS-CROSS] PASS: OpenSSL and the token accept each other'"'"'s GOST CMS'
else
  echo "[CMS-CROSS] $failures check(s) failed"
fi
echo "[CMS-CROSS] results: $kit/test-output/$name.tar.gz"
[[ $failures == 0 ]]
