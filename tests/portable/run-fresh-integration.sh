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

mkdir -p "$scenario_dir"
if [[ ! -f "$module_source" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module_source" >&2
  exit 2
fi
if [[ "$expect_portable_token_dir" == YES ]]; then
  if [[ ! -f "$config_source" ]]; then
    printf 'softhsm.conf is not a file: %s\n' "$config_source" >&2
    exit 2
  fi
  mkdir -p "$package_dir"
  module="$package_dir/$(basename "$module_source")"
  printf '[SCRIPT] copying bundled PKCS #11 library %q into disposable package %q\n' \
    "$module_source" "$package_dir"
  cp "$module_source" "$module"
  cp "$config_source" "$package_dir/softhsm.conf"
  unset SOFTHSM2_CONF
else
  module="$module_source"
  printf '[SCRIPT] using alternate PKCS #11 library directly in its original directory: %q\n' \
    "$module"
  if [[ -n ${SOFTHSM2_CONF:-} ]]; then
    printf '[SCRIPT] preserving caller-provided SOFTHSM2_CONF=%q\n' "$SOFTHSM2_CONF"
  fi
fi
if [[ -z ${P11_TEST_USER_PIN:-} ]]; then
  echo 'USER_PIN is missing from testkit.conf' >&2
  exit 2
fi
if [[ -z ${P11_TEST_REQUIRE_GOST_IMPORT_EXPORT:-} ]]; then
  export P11_TEST_REQUIRE_GOST_IMPORT_EXPORT=$expect_portable_token_dir
fi
if [[ -z ${P11_TEST_REQUIRE_RSA_IMPORT_EXPORT:-} ]]; then
  export P11_TEST_REQUIRE_RSA_IMPORT_EXPORT=$expect_portable_token_dir
fi

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$module" "$openssl" "$scenario_dir"

if [[ "$expect_portable_token_dir" == YES ]]; then
  test -d "$package_dir/tokens"
  printf '[SCRIPT] verified portable-only behavior: tokens directory exists beside tested module\n'
fi
