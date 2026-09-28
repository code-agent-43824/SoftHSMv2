#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo 'usage: verify-config-override.sh <module> <client> <softhsm2-util> <evidence-dir>' >&2
  exit 2
fi
module=$1
client=$2
util=$3
mkdir -p "$4"
case_dir=$(mktemp -d "$4/config-override.XXXXXX")
mkdir -p "$case_dir/bundle" "$case_dir/with-user/softhsm" "$case_dir/fresh-home"
cat > "$case_dir/bundle/softhsm.conf" <<'CONF'
directories.tokendir = tokens
objectstore.backend = file
log.level = ERROR
CONF
printf 'directories.tokendir = user-tokens\n' > "$case_dir/with-user/softhsm/softhsm.conf"

HOME="$case_dir/with-user" SOFTHSM2_CONF="$case_dir/bundle/softhsm.conf" \
  "$client" first-run "$module" "$case_dir/bundle/tokens"
test ! -e "$case_dir/with-user/softhsm/user-tokens"
test "$(cat "$case_dir/with-user/softhsm/softhsm.conf")" = \
  'directories.tokendir = user-tokens'

HOME="$case_dir/fresh-home" SOFTHSM2_CONF="$case_dir/bundle/softhsm.conf" \
  "$client" probe "$module"
HOME="$case_dir/fresh-home" SOFTHSM2_CONF="$case_dir/bundle/softhsm.conf" \
  "$util" --show-slots > "$case_dir/utility-slots.txt"
test ! -e "$case_dir/fresh-home/softhsm"

mkdir -p "$case_dir/missing-home"
HOME="$case_dir/missing-home" SOFTHSM2_CONF="$case_dir/missing.conf" \
  "$client" first-run "$module" "$case_dir/missing-home/softhsm/tokens"
grep -Fx 'directories.tokendir = tokens' \
  "$case_dir/missing-home/softhsm/softhsm.conf" >/dev/null

mkdir -p "$case_dir/directory-home"
HOME="$case_dir/directory-home" SOFTHSM2_CONF="$case_dir/bundle" \
  "$client" first-run "$module" "$case_dir/directory-home/softhsm/tokens"

module_name=$(basename "$module")
mkdir -p "$case_dir/adjacent/tools/bin" "$case_dir/adjacent-home" "$case_dir/elsewhere"
cp "$module" "$case_dir/adjacent/$module_name"
cp "$util" "$case_dir/adjacent/tools/bin/softhsm2-util"
cat > "$case_dir/adjacent/softhsm.conf" <<'CONF'
directories.tokendir = tokens
objectstore.backend = file
FAKE_RUTOKEN_ECP = true
log.level = ERROR
CONF
printf 'directories.tokendir = alias-tokens\n' > "$case_dir/adjacent/softhsm2.conf"
printf 'invalid config in process working directory\n' > "$case_dir/elsewhere/softhsm.conf"
(
  cd "$case_dir/elsewhere"
  test "$(realpath "$(HOME="$case_dir/adjacent-home" env -u SOFTHSM2_CONF \
    "$case_dir/adjacent/tools/bin/softhsm2-util" --show-config default-pkcs11-lib)")" = \
    "$(realpath "$case_dir/adjacent/$module_name")"
  HOME="$case_dir/adjacent-home" env -u SOFTHSM2_CONF \
    "$case_dir/adjacent/tools/bin/softhsm2-util" --show-slots \
    > "$case_dir/adjacent-slots.txt"
  grep -F 'Slot 14' "$case_dir/adjacent-slots.txt" >/dev/null
  HOME="$case_dir/adjacent-home" env -u SOFTHSM2_CONF \
    "$client" probe "$case_dir/adjacent/$module_name"
  HOME="$case_dir/adjacent-home" SOFTHSM2_CONF="$case_dir/missing.conf" \
    "$client" probe "$case_dir/adjacent/$module_name"
)
test -d "$case_dir/adjacent/tokens"
test ! -e "$case_dir/adjacent/alias-tokens"
test ! -e "$case_dir/adjacent-home/softhsm"

mkdir -p "$case_dir/override-module" "$case_dir/override-store" "$case_dir/override-home"
cp "$module" "$case_dir/override-module/$module_name"
printf 'directories.tokendir = tokens\n' > "$case_dir/override-module/softhsm.conf"
printf 'directories.tokendir = tokens\n' > "$case_dir/override-store/softhsm.conf"
HOME="$case_dir/override-home" SOFTHSM2_CONF="$case_dir/override-store/softhsm.conf" \
  "$client" first-run "$case_dir/override-module/$module_name" "$case_dir/override-store/tokens"
test ! -e "$case_dir/override-module/tokens"
test ! -e "$case_dir/override-home/softhsm"

mkdir -p "$case_dir/alias-module" "$case_dir/alias-home"
cp "$module" "$case_dir/alias-module/$module_name"
printf 'directories.tokendir = tokens\n' > "$case_dir/alias-module/softhsm2.conf"
HOME="$case_dir/alias-home" env -u SOFTHSM2_CONF \
  "$client" first-run "$case_dir/alias-module/$module_name" "$case_dir/alias-module/tokens"
test ! -e "$case_dir/alias-home/softhsm"

mkdir -p "$case_dir/plain-module/tools/bin" "$case_dir/plain-home"
cp "$module" "$case_dir/plain-module/$module_name"
cp "$util" "$case_dir/plain-module/tools/bin/softhsm2-util"
HOME="$case_dir/plain-home" env -u SOFTHSM2_CONF \
  "$client" first-run "$case_dir/plain-module/$module_name" "$case_dir/plain-home/softhsm/tokens"
HOME="$case_dir/plain-home" env -u SOFTHSM2_CONF \
  "$case_dir/plain-module/tools/bin/softhsm2-util" --show-slots \
  > "$case_dir/plain-slots.txt"
test ! -e "$case_dir/plain-module/tokens"
echo '[CONFIG] PASS: override > adjacent module config > per-user; utility and foreign CWD agree'
