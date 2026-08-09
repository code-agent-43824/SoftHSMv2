#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: run-test.sh <product-package.zip-or-directory> [scenario-directory]" >&2
  exit 2
fi

kit_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
product=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
scenario=${2:-}
module_name=$(sed -n 's/^MODULE_NAME=//p' "$kit_dir/testkit.env")
test -n "$module_name"
# ZIP extraction does not restore executable bits consistently across tools.
# Running this launcher as `bash run-test.sh ...` repairs the bundled tools.
chmod +x "$kit_dir/bin/portable-token-e2e" "$kit_dir/bin/openssl" \
  "$kit_dir/scripts/"*.sh
test -x "$kit_dir/bin/portable-token-e2e"
test -x "$kit_dir/bin/openssl"

export P11_TEST_CLIENT="$kit_dir/bin/portable-token-e2e"
export OPENSSL_CONF="$kit_dir/config/openssl.cnf"
if [[ -n "$scenario" ]]; then
  scenario=$(mkdir -p "$scenario" && cd "$scenario" && pwd)
fi

printf '[TEST-KIT] platform=%s\n' "$(sed -n 's/^PLATFORM=//p' "$kit_dir/testkit.env")"
printf '[TEST-KIT] product source=%s\n' "$product"
printf '[TEST-KIT] precompiled client=%s\n' "$P11_TEST_CLIENT"
printf '[TEST-KIT] bundled OpenSSL=%s\n' "$kit_dir/bin/openssl"

if [[ -n "$scenario" ]]; then
  "$kit_dir/scripts/run-fresh-integration.sh" "$product" "$module_name" \
    "$kit_dir/bin/openssl" "$scenario"
else
  "$kit_dir/scripts/run-fresh-integration.sh" "$product" "$module_name" \
    "$kit_dir/bin/openssl"
fi
