#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: run-fresh-integration.sh <pkcs11-library> <openssl> <softhsm.conf> <bundled-mode>" >&2
  exit 2
fi

module_source=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
openssl=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
config_source=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
bundled_mode=$4
[[ "$bundled_mode" == YES || "$bundled_mode" == NO ]] || {
  echo 'bundled-mode must be YES or NO' >&2
  exit 2
}
work_root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/softhsm-fresh-test.XXXXXX")
package_dir="$work_root/package"
scenario_dir="$work_root/scenario"
user_config="${HOME:?HOME is required}/.config/softhsm2/softhsm2.conf"
user_config_preexisting=NO
[[ -e "$user_config" ]] && user_config_preexisting=YES

mkdir -p "$scenario_dir"
if [[ ! -f "$module_source" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module_source" >&2
  exit 2
fi
if [[ "$bundled_mode" == YES ]]; then
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
  export P11_TEST_REQUIRE_GOST_IMPORT_EXPORT=$bundled_mode
fi
if [[ -z ${P11_TEST_REQUIRE_RSA_IMPORT_EXPORT:-} ]]; then
  export P11_TEST_REQUIRE_RSA_IMPORT_EXPORT=$bundled_mode
fi

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$module" "$openssl" "$scenario_dir"

if [[ "$bundled_mode" == YES ]]; then
  test -f "$user_config"
  test ! -e "$package_dir/tokens"
  if [[ "$user_config_preexisting" == NO ]]; then
    cmp "$config_source" "$user_config"
    test -d "$(dirname "$user_config")/tokens"
    printf '[SCRIPT] verified first-use config copy and token storage in canonical user directory: %q\n' \
      "$(dirname "$user_config")"
  else
    printf '[SCRIPT] verified reuse of pre-existing canonical user config: %q\n' "$user_config"
  fi
  printf '[SCRIPT] verified no token storage was created beside the tested module\n'
fi
