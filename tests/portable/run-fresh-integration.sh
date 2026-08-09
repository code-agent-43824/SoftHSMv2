#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
  echo "usage: run-fresh-integration.sh <package.zip-or-directory> <module-name> <openssl> [scenario-directory]" >&2
  exit 2
fi

product=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
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
if [[ -d "$product" ]]; then
  printf '[SCRIPT] copying product directory %q into %q\n' "$product" "$package_dir"
  cp -R "$product"/. "$package_dir"/
elif [[ "$product" == *.zip ]]; then
  printf '[SCRIPT] extracting downloaded package %q into %q\n' "$product" "$package_dir"
  unzip -q "$product" -d "$package_dir"
else
  printf 'product source must be a ZIP archive or directory: %s\n' "$product" >&2
  exit 2
fi
if [[ ! -f "$package_dir/$module_name" ]]; then
  printf '%s is missing; a product directory must contain the extracted product files\n' \
    "$module_name" >&2
  exit 2
fi
if [[ ! -f "$package_dir/softhsm.conf" ]]; then
  echo 'softhsm.conf is missing from the product source' >&2
  exit 2
fi

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
