#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: run-fresh-integration.sh <pkcs11-library> <openssl> <softhsm.conf> <expect-portable-token-dir>" >&2
  exit 2
fi

module_source=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
openssl=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
config_source=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
expect_portable_token_dir=$4
[[ "$expect_portable_token_dir" == YES || "$expect_portable_token_dir" == NO ]] || {
  echo 'expect-portable-token-dir must be YES or NO' >&2
  exit 2
}
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
if [[ -z ${P11_TEST_USER_PIN:-} ]]; then
  echo 'USER_PIN is missing from testkit.conf' >&2
  exit 2
fi

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$module" "$openssl" "$scenario_dir"

if [[ "$expect_portable_token_dir" == YES ]]; then
  test -d "$package_dir/tokens"
  printf '[SCRIPT] verified portable-only behavior: tokens directory exists beside tested module\n'
fi
