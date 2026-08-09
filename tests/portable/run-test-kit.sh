#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: run-test.sh [path-to-alternative-pkcs11-library]" >&2
  exit 2
fi

kit_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
module_name=$(sed -n 's/^MODULE_NAME=//p' "$kit_dir/testkit.env")
test -n "$module_name"
if [[ $# -eq 1 ]]; then
  module=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
else
  module="$kit_dir/$module_name"
fi
if [[ ! -f "$module" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module" >&2
  exit 2
fi
if [[ -f "$(dirname "$module")/softhsm.conf" ]]; then
  config="$(dirname "$module")/softhsm.conf"
else
  config="$kit_dir/softhsm.conf"
fi
# ZIP extraction does not restore executable bits consistently across tools.
# Running this launcher as `bash run-test.sh ...` repairs the bundled tools.
chmod +x "$kit_dir/bin/portable-token-e2e" "$kit_dir/bin/openssl" \
  "$kit_dir/scripts/"*.sh
test -x "$kit_dir/bin/portable-token-e2e"
test -x "$kit_dir/bin/openssl"

export P11_TEST_CLIENT="$kit_dir/bin/portable-token-e2e"
export OPENSSL_CONF="$kit_dir/config/openssl.cnf"
printf '[TEST-KIT] platform=%s\n' "$(sed -n 's/^PLATFORM=//p' "$kit_dir/testkit.env")"
printf '[TEST-KIT] PKCS #11 library=%s\n' "$module"
printf '[TEST-KIT] SoftHSM config=%s\n' "$config"
printf '[TEST-KIT] precompiled client=%s\n' "$P11_TEST_CLIENT"
printf '[TEST-KIT] bundled OpenSSL=%s\n' "$kit_dir/bin/openssl"

"$kit_dir/scripts/run-fresh-integration.sh" "$module" \
  "$kit_dir/bin/openssl" "$config"
