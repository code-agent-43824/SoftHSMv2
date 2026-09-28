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
echo '[CONFIG] PASS: readable override isolates the store; invalid override falls back'
