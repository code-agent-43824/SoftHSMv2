#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run-fresh-integration.sh <pkcs11-library> <openssl> <bundled-mode>" >&2
  exit 2
fi

module_source=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
openssl=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
bundled_mode=$3
[[ "$bundled_mode" == YES || "$bundled_mode" == NO ]] || {
  echo 'bundled-mode must be YES or NO' >&2
  exit 2
}
kit_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scenario_dir="$kit_dir/test-output"
user_config="${HOME:?HOME is required}/softhsm/softhsm.conf"
user_config_preexisting=NO
[[ -e "$user_config" ]] && user_config_preexisting=YES

mkdir -p "$scenario_dir"
if [[ ! -f "$module_source" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module_source" >&2
  exit 2
fi
if [[ "$bundled_mode" == YES ]]; then
  module="$module_source"
  printf '[SCRIPT] using bundled PKCS #11 library directly inside test kit: %q\n' "$module"
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
  export P11_TEST_REQUIRE_GOST_IMPORT_EXPORT=$bundled_mode
fi
if [[ -z ${P11_TEST_REQUIRE_GOST_SYMMETRIC:-} ]]; then
  export P11_TEST_REQUIRE_GOST_SYMMETRIC=$bundled_mode
fi
if [[ -z ${P11_TEST_REQUIRE_RSA_IMPORT_EXPORT:-} ]]; then
  export P11_TEST_REQUIRE_RSA_IMPORT_EXPORT=$bundled_mode
fi

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$module" "$openssl" "$scenario_dir"

if [[ "$bundled_mode" == YES ]]; then
  if [[ -r "$(dirname "$module")/softhsm.conf" &&
        ! ( -n ${SOFTHSM2_CONF:-} && -r "$SOFTHSM2_CONF" ) ]]; then
    test -d "$(dirname "$module")/tokens"
    [[ "$user_config_preexisting" == YES || ! -e "$user_config" ]]
    printf '[SCRIPT] verified adjacent test-kit token storage: %q\n' \
      "$(dirname "$module")/tokens"
  else
    printf '[SCRIPT] bundled module uses explicit override or legacy fallback\n'
  fi
fi
