#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run-fresh-integration.sh <pkcs11-library> <openssl> <softhsm.conf>" >&2
  exit 2
fi

module_source=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
openssl=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
config_source=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
work_root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/softhsm-fresh-test.XXXXXX")
package_dir="$work_root/package"
scenario_dir="$work_root/scenario"

mkdir -p "$package_dir" "$scenario_dir"
if [[ ! -f "$module_source" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module_source" >&2
  exit 2
fi
if [[ ! -f "$config_source" ]]; then
  printf 'softhsm.conf is not a file: %s\n' "$config_source" >&2
  exit 2
fi
module="$package_dir/$(basename "$module_source")"
printf '[SCRIPT] copying PKCS #11 library %q into disposable package %q\n' \
  "$module_source" "$package_dir"
cp "$module_source" "$module"
cp "$config_source" "$package_dir/softhsm.conf"

unset SOFTHSM2_CONF
export P11_TEST_INITIALIZE_TOKEN=YES
export P11_TEST_SO_PIN=12345678
export P11_TEST_USER_PIN=12345678
export P11_TEST_TOKEN_LABEL=portable-ci-token
export P11_TEST_KEY_LABEL=portable-ci-rsa
export P11_TEST_OBJECT_ID_HEX=504f525441424c45

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$module" "$openssl" "$scenario_dir"

test -d "$package_dir/tokens"
printf '[SCRIPT] verified portable-only behavior: tokens directory exists beside tested module\n'
