#!/usr/bin/env bash
set -euo pipefail

if [[ $# -gt 1 ]]; then
  echo "usage: run-test.sh [path-to-alternative-pkcs11-library]" >&2
  exit 2
fi

kit_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
module_name=$(sed -n 's/^MODULE_NAME=//p' "$kit_dir/testkit.env")
test -n "$module_name"
config_file="$kit_dir/testkit.conf"
test -f "$config_file"
user_config="${HOME:?HOME is required}/softhsm/softhsm.conf"

cfg_initialize=AUTO
cfg_excluded=
cfg_user_pin=
cfg_so_pin=
cfg_slot_id=
cfg_token_label=
cfg_key_label=
cfg_object_id=
while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  trimmed=${line#"${line%%[![:space:]]*}"}
  [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
  if [[ "$line" != *=* ]]; then
    printf 'invalid testkit.conf line: %s\n' "$line" >&2
    exit 2
  fi
  key=${line%%=*}
  key=${key//[[:space:]]/}
  value=${line#*=}
  case "$key" in
    INITIALIZE_TOKEN) cfg_initialize=$value ;;
    EXCLUDED_FUNCTIONS) cfg_excluded=$value ;;
    USER_PIN) cfg_user_pin=$value ;;
    SO_PIN) cfg_so_pin=$value ;;
    SLOT_ID) cfg_slot_id=$value ;;
    TOKEN_LABEL) cfg_token_label=$value ;;
    KEY_LABEL) cfg_key_label=$value ;;
    OBJECT_ID_HEX) cfg_object_id=$value ;;
    *) printf 'unknown testkit.conf setting: %s\n' "$key" >&2; exit 2 ;;
  esac
done < "$config_file"

initialize_setting=${P11_TEST_INITIALIZE_TOKEN:-$cfg_initialize}
initialize_setting=$(printf '%s' "$initialize_setting" | tr '[:lower:]' '[:upper:]')
case "$initialize_setting" in
  AUTO)
    token_dir=$(dirname "$user_config")/tokens
    if ! find "$token_dir" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null | grep -q .; then
      initialize=YES
    else
      initialize=NO
    fi
    ;;
  YES|NO) initialize=$initialize_setting ;;
  *) echo 'INITIALIZE_TOKEN must be AUTO, YES, or NO' >&2; exit 2 ;;
esac

excluded=${P11_TEST_EXCLUDE_FUNCTIONS:-$cfg_excluded}
add_excluded() {
  local function_name=$1
  [[ "$function_name" =~ ^C_[A-Za-z0-9_]+$ ]] || {
    printf 'invalid excluded PKCS #11 function: %s\n' "$function_name" >&2
    exit 2
  }
  case ",$excluded," in
    *",$function_name,"*) ;;
    *) excluded=${excluded:+$excluded,}$function_name ;;
  esac
}
normalized=${excluded//;/,}
normalized=${normalized// /,}
excluded=
while IFS= read -r function_name; do
  [[ -n "$function_name" ]] && add_excluded "$function_name"
done < <(printf '%s' "$normalized" | tr ',' '\n')
if [[ "$initialize" == NO ]]; then
  add_excluded C_InitToken
  add_excluded C_InitPIN
  add_excluded C_SetPIN
fi

export P11_TEST_INITIALIZE_TOKEN=$initialize
export P11_TEST_USER_PIN=${P11_TEST_USER_PIN:-$cfg_user_pin}
export P11_TEST_SO_PIN=${P11_TEST_SO_PIN:-$cfg_so_pin}
export P11_TEST_EXCLUDE_FUNCTIONS=$excluded
[[ -n ${P11_TEST_USER_PIN:-} ]] || { echo 'USER_PIN must be set in testkit.conf' >&2; exit 2; }
[[ "$initialize" == NO || -n ${P11_TEST_SO_PIN:-} ]] || {
  echo 'SO_PIN must be set when INITIALIZE_TOKEN=YES' >&2
  exit 2
}
set_optional() {
  local name=$1 value=$2
  if [[ -n "$value" ]]; then export "$name=$value"; else unset "$name"; fi
}
set_optional P11_TEST_SLOT_ID "${P11_TEST_SLOT_ID:-$cfg_slot_id}"
set_optional P11_TEST_TOKEN_LABEL "${P11_TEST_TOKEN_LABEL:-$cfg_token_label}"
set_optional P11_TEST_KEY_LABEL "${P11_TEST_KEY_LABEL:-$cfg_key_label}"
set_optional P11_TEST_OBJECT_ID_HEX "${P11_TEST_OBJECT_ID_HEX:-$cfg_object_id}"

if [[ $# -eq 1 ]]; then
  module=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
  bundled_mode=NO
else
  module="$kit_dir/$module_name"
  bundled_mode=YES
fi
if [[ ! -f "$module" ]]; then
  printf 'PKCS #11 library is not a file: %s\n' "$module" >&2
  exit 2
fi
# ZIP extraction does not restore executable bits consistently across tools.
# Running this launcher as `bash run-test.sh ...` repairs the bundled tools.
chmod +x "$kit_dir/bin/portable-token-e2e" "$kit_dir/bin/openssl" \
  "$kit_dir/scripts/"*.sh
test -x "$kit_dir/bin/portable-token-e2e"
test -x "$kit_dir/bin/openssl"

export P11_TEST_CLIENT="$kit_dir/bin/portable-token-e2e"
export OPENSSL_CONF="$kit_dir/config/openssl.cnf"
printf '[TEST-KIT] platform=%s\n' "$(sed -n 's/^PLATFORM=//p' "$kit_dir/testkit.env")"
printf '[TEST-KIT] settings=%s\n' "$config_file"
printf '[TEST-KIT] PKCS #11 library=%s\n' "$module"
printf '[TEST-KIT] canonical user config=%s\n' "$user_config"
printf '[TEST-KIT] initialize token=%s\n' "$initialize"
printf '[TEST-KIT] excluded functions=%s\n' "${excluded:-<none>}"
printf '[TEST-KIT] precompiled client=%s\n' "$P11_TEST_CLIENT"
printf '[TEST-KIT] bundled OpenSSL=%s\n' "$kit_dir/bin/openssl"
printf '[TEST-KIT] all test evidence remains under=%s\n' "$kit_dir/test-output"

"$kit_dir/scripts/run-fresh-integration.sh" "$module" \
  "$kit_dir/bin/openssl" "$bundled_mode"
