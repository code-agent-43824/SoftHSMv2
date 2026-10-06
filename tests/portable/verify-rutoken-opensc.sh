#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo 'usage: verify-rutoken-opensc.sh <module> <pkcs11-tool> <pkcs11-spy> <softhsm2-util> <output-dir>' >&2
  exit 2
fi

module=$1
cli=$2
spy=$3
util=$4
output_dir=$5
case_dir=$(mktemp -d "$output_dir/rutoken-cli.XXXXXX")
mkdir -p "$case_dir/tokens"
printf 'directories.tokendir = tokens\nobjectstore.backend = file\nlog.level = ERROR\nFAKE_RUTOKEN_ECP = true\n' \
  > "$case_dir/softhsm2.conf"
export SOFTHSM2_CONF="$case_dir/softhsm2.conf"

# Fixed PINs belong only to this disposable, isolated test token.
export TEST_RUTOKEN_USER_PIN=12345678
export TEST_RUTOKEN_LOCAL_PIN=local444
export TEST_RUTOKEN_LOCAL_PIN_NEXT=local555
"$util" --module "$module" --init-token --slot 0 --label 'Rutoken ECP' \
  --so-pin "$TEST_RUTOKEN_USER_PIN" --pin "$TEST_RUTOKEN_USER_PIN" \
  > "$case_dir/init.log" 2>&1
"$cli" --module "$module" --rutoken-info --rutoken-name --rutoken-json \
  > "$case_dir/info.json" 2> "$case_dir/info.err"
python3 - "$case_dir/info.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as source:
    result = json.load(source)
assert result['info']['token_type_name'] == 'RUTOKEN_ECP', result
assert result['info']['user_retries_left'] == 10, result
assert result['name']['label'] == 'Rutoken ECP', result
PY

"$cli" --module "$module" --rutoken-set-name 'Fork Rutoken CLI' \
  --login --pin "$TEST_RUTOKEN_USER_PIN" > "$case_dir/set-name.log" 2>&1
"$cli" --module "$module" --rutoken-set-local-pin 4 \
  --rutoken-auth-pin env:TEST_RUTOKEN_USER_PIN \
  --new-pin env:TEST_RUTOKEN_LOCAL_PIN > "$case_dir/set-local.log" 2>&1
"$cli" --module "$module" --rutoken-set-local-pin 4 \
  --rutoken-auth-pin env:TEST_RUTOKEN_LOCAL_PIN \
  --new-pin env:TEST_RUTOKEN_LOCAL_PIN_NEXT > "$case_dir/change-local.log" 2>&1

export PKCS11SPY="$module"
export PKCS11SPY_OUTPUT="$case_dir/pkcs11-spy.log"
"$cli" --module "$spy" --rutoken-info --rutoken-name --rutoken-json \
  > "$case_dir/spy-info.json" 2> "$case_dir/spy-info.err"
python3 - "$case_dir/spy-info.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as source:
    result = json.load(source)
assert result['name']['label'] == 'Fork Rutoken CLI', result
assert result['info']['token_type_name'] == 'RUTOKEN_ECP', result
PY
for function in C_EX_GetFunctionListExtended C_EX_GetTokenInfoExtended C_EX_GetTokenName; do
  grep -Fq "$function" "$PKCS11SPY_OUTPUT"
done
printf '[RUTOKEN-OPENSC] PASS: fork CLI info/name/local PIN and spy on isolated fake token\n'
