#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: run-fresh-integration.sh <package.zip> <module-name> <openssl> [scenario-directory]" >&2
  exit 2
fi

archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
module_name=$2
openssl=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
work_root=$(mktemp -d "${RUNNER_TEMP:-/tmp}/softhsm-fresh-test.XXXXXX")
package_dir="$work_root/package"
if [[ $# -eq 4 ]]; then
  scenario_dir=$(mkdir -p "$4" && cd "$4" && pwd)
else
  scenario_dir="$work_root/scenario"
fi

mkdir -p "$package_dir" "$scenario_dir"
printf '[SCRIPT] extracting downloaded package %q into %q\n' "$archive" "$package_dir"
unzip -q "$archive" -d "$package_dir"
test -f "$package_dir/$module_name"
test -f "$package_dir/softhsm.conf"

unset SOFTHSM2_CONF
export P11_TEST_INITIALIZE_TOKEN=YES
export P11_TEST_SO_PIN=12345678
export P11_TEST_USER_PIN=12345678
export P11_TEST_TOKEN_LABEL=portable-ci-token
export P11_TEST_KEY_LABEL=portable-ci-rsa
export P11_TEST_OBJECT_ID_HEX=504f525441424c45

"$(dirname "${BASH_SOURCE[0]}")/run-pkcs11-integration.sh" \
  "$package_dir/$module_name" "$openssl" "$scenario_dir"

test -d "$package_dir/tokens"
printf '[SCRIPT] verified portable-only behavior: tokens directory exists beside downloaded module\n'
