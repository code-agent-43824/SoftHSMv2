#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: run-fresh-integration.sh <package.zip> <module-name> <openssl>" >&2
  exit 2
fi

archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
module_name=$2
openssl=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_root="${RUNNER_TEMP:-$(mktemp -d)}/softhsm-fresh-test"
package_dir="$work_root/package"
scenario_dir="$work_root/scenario"
tester="$work_root/portable-token-e2e"

mkdir -p "$package_dir" "$scenario_dir"
unzip -q "$archive" -d "$package_dir"
test -f "$package_dir/$module_name"
test -f "$package_dir/softhsm.conf"

cxx=${CXX:-c++}
link_flags=()
if [[ $(uname -s) == Linux ]]; then link_flags+=(-ldl); fi
"$cxx" -std=c++17 -O2 -Wall -Wextra -Werror \
  -I"$root_dir/src/lib/pkcs11" \
  "$root_dir/tests/portable/portable-token-e2e.cpp" \
  "${link_flags[@]}" -o "$tester"

unset SOFTHSM2_CONF
(cd /tmp && "$tester" prepare "$package_dir/$module_name" "$scenario_dir" 12345678 12345678)
test -d "$package_dir/tokens"

"$openssl" req -in "$scenario_dir/request.pem" -verify -noout
"$openssl" req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -subj "/CN=SoftHSM Portable Test CA" \
  -keyout "$scenario_dir/ca.key" -out "$scenario_dir/ca.pem"
"$openssl" x509 -req -in "$scenario_dir/request.pem" \
  -CA "$scenario_dir/ca.pem" -CAkey "$scenario_dir/ca.key" -CAcreateserial \
  -days 1 -sha256 -out "$scenario_dir/issued.pem"
"$openssl" verify -CAfile "$scenario_dir/ca.pem" "$scenario_dir/issued.pem"
"$openssl" x509 -in "$scenario_dir/issued.pem" -outform DER -out "$scenario_dir/issued.der"
"$openssl" x509 -in "$scenario_dir/ca.pem" -outform DER -out "$scenario_dir/ca.der"

printf 'portable PKCS11 detached CMS payload\n' > "$scenario_dir/payload.bin"
(cd /tmp && "$tester" finish "$package_dir/$module_name" "$scenario_dir" 12345678 \
  "$scenario_dir/issued.der" "$scenario_dir/ca.der" "$scenario_dir/payload.bin" "$scenario_dir/signature.p7s")

"$openssl" cms -verify -binary -inform DER \
  -in "$scenario_dir/signature.p7s" -content "$scenario_dir/payload.bin" \
  -CAfile "$scenario_dir/ca.pem" -purpose any -out "$scenario_dir/verified.bin"
cmp "$scenario_dir/payload.bin" "$scenario_dir/verified.bin"

echo "Fresh-runner direct PKCS #11 and OpenSSL integration test passed"
