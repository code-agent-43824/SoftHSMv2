#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: run-pkcs11-integration.sh <pkcs11-module> <openssl> [scenario-directory]" >&2
  echo "PINs and token selection are supplied through the P11_TEST_* environment variables documented in README.md." >&2
  exit 2
fi

log() {
  printf '[SCRIPT] %s\n' "$*"
}

run() {
  printf '[COMMAND]'
  printf ' %q' "$@"
  printf '\n'
  "$@"
}

module=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
openssl=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ $# -eq 3 ]]; then
  scenario_dir=$(mkdir -p "$3" && cd "$3" && pwd)
else
  scenario_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/pkcs11-integration.XXXXXX")
fi
build_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/pkcs11-client-build.XXXXXX")
tester="$build_dir/portable-token-e2e"

log "module=$module"
log "OpenSSL CLI=$openssl"
log "scenario directory=$scenario_dir"
log "P11_TEST_INITIALIZE_TOKEN=${P11_TEST_INITIALIZE_TOKEN:-NO}"
log "P11_TEST_SLOT_ID=${P11_TEST_SLOT_ID:-<automatic; exactly one matching token is required>}"
log "P11_TEST_TOKEN_LABEL=${P11_TEST_TOKEN_LABEL:-portable-ci-token}"
log "P11_TEST_KEY_LABEL=${P11_TEST_KEY_LABEL:-portable-ci-rsa}"
log "P11_TEST_OBJECT_ID_HEX=${P11_TEST_OBJECT_ID_HEX:-504f525441424c45}"
so_pin_value=${P11_TEST_SO_PIN:-}
user_pin_value=${P11_TEST_USER_PIN:-}
log "P11_TEST_SO_PIN=<redacted,length=${#so_pin_value}>"
log "P11_TEST_USER_PIN=<redacted,length=${#user_pin_value}>"

test -f "$module"
test -x "$openssl"
cxx=${CXX:-c++}
if [[ $(uname -s) == Linux ]]; then
  run "$cxx" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$root_dir/src/lib/pkcs11" \
    "$root_dir/tests/portable/portable-token-e2e.cpp" -ldl -o "$tester"
else
  run "$cxx" -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$root_dir/src/lib/pkcs11" \
    "$root_dir/tests/portable/portable-token-e2e.cpp" -o "$tester"
fi

log "PKCS #11 prepare phase: select token, optionally initialize it, log in, generate RSA-2048, create CSR"
(cd /tmp && run "$tester" prepare "$module" "$scenario_dir")

log "independently verify the token-signed PKCS#10 request"
run "$openssl" req -in "$scenario_dir/request.pem" -verify -noout

log "create an external one-day RSA test CA"
run "$openssl" req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=Portable PKCS11 Test CA" \
  -keyout "$scenario_dir/ca.key" -out "$scenario_dir/ca.pem"

log "issue and verify a leaf certificate for the token-generated public key"
run "$openssl" x509 -req -in "$scenario_dir/request.pem" \
  -CA "$scenario_dir/ca.pem" -CAkey "$scenario_dir/ca.key" -CAcreateserial \
  -days 1 -sha256 -out "$scenario_dir/issued.pem"
run "$openssl" verify -CAfile "$scenario_dir/ca.pem" "$scenario_dir/issued.pem"
run "$openssl" x509 -in "$scenario_dir/issued.pem" -outform DER -out "$scenario_dir/issued.der"
run "$openssl" x509 -in "$scenario_dir/ca.pem" -outform DER -out "$scenario_dir/ca.der"

log "write the detached-CMS test payload"
printf 'portable PKCS11 detached CMS payload\n' > "$scenario_dir/payload.bin"

log "PKCS #11 finish phase: reopen key, import X.509 certificate, digest and sign CMS attributes"
(cd /tmp && run "$tester" finish "$module" "$scenario_dir" \
  "$scenario_dir/issued.der" "$scenario_dir/ca.der" \
  "$scenario_dir/payload.bin" "$scenario_dir/signature.p7s")

log "independently verify detached CMS and its recovered content"
run "$openssl" cms -verify -binary -inform DER \
  -in "$scenario_dir/signature.p7s" -content "$scenario_dir/payload.bin" \
  -CAfile "$scenario_dir/ca.pem" -purpose any -out "$scenario_dir/verified.bin"
run cmp "$scenario_dir/payload.bin" "$scenario_dir/verified.bin"

log "PASS: standard direct PKCS #11 and external OpenSSL integration test completed"
log "evidence retained in $scenario_dir"
