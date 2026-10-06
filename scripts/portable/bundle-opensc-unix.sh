#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo 'usage: bundle-opensc-unix.sh <linux-x64|linux-arm64|macos-universal> <stage-dir>' >&2
  exit 2
fi

platform=$1
stage_dir=$(cd "$2" && pwd)
case "$platform" in
  linux-x64|linux-arm64) spy_name=pkcs11-spy.so ;;
  macos-universal) spy_name=pkcs11-spy.dylib ;;
  *) echo "unsupported OpenSC platform: $platform" >&2; exit 2 ;;
esac

# Resolve Latest once for this build. The ZIP and manifest must come from the
# same release, and their GitHub-published digests are checked before use.
work_dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/opensc-fork.XXXXXX")
api_url=https://api.github.com/repos/code-agent-43824/OpenSC/releases/latest
api_headers=(-H 'Accept: application/vnd.github+json')
if [[ -n ${OPENSC_GITHUB_TOKEN:-} ]]; then
  api_headers+=(-H "Authorization: Bearer $OPENSC_GITHUB_TOKEN")
fi
curl --fail --silent --show-error --location --retry 5 \
  "${api_headers[@]}" -o "$work_dir/release.json" "$api_url"
python3 - "$platform" "$work_dir/release.json" > "$work_dir/release.meta" <<'PY'
import json
import re
import sys

platform, path = sys.argv[1:]
with open(path, encoding='utf-8') as source:
    release = json.load(source)
tag = release['tag_name']
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-portable\.[0-9]+', tag):
    raise SystemExit(f'unexpected OpenSC Latest tag: {tag}')
assets = {asset['name']: asset for asset in release['assets']}
for name in ('SHA256SUMS', f'opensc-portable-{platform}.zip'):
    asset = assets[name]
    digest = asset.get('digest', '')
    url = asset['browser_download_url']
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
        raise SystemExit(f'missing SHA-256 digest for {name}')
    if url != f'https://github.com/code-agent-43824/OpenSC/releases/download/{tag}/{name}':
        raise SystemExit(f'unexpected OpenSC asset URL: {url}')
    print(name, digest[7:], url, sep='\t')
print(tag)
PY

manifest_line=$(sed -n '1p' "$work_dir/release.meta")
archive_line=$(sed -n '2p' "$work_dir/release.meta")
opensc_version=$(sed -n '3p' "$work_dir/release.meta")
IFS=$'\t' read -r manifest_name manifest_sha manifest_url <<< "$manifest_line"
IFS=$'\t' read -r archive_name archive_sha archive_url <<< "$archive_line"
curl --fail --silent --show-error --location --retry 5 \
  -o "$work_dir/$manifest_name" "$manifest_url"
curl --fail --silent --show-error --location --retry 5 \
  -o "$work_dir/$archive_name" "$archive_url"
if [[ $(uname -s) == Darwin ]]; then
  printf '%s  %s\n' "$manifest_sha" "$work_dir/$manifest_name" | shasum -a 256 --check
  printf '%s  %s\n' "$archive_sha" "$work_dir/$archive_name" | shasum -a 256 --check
else
  printf '%s  %s\n' "$manifest_sha" "$work_dir/$manifest_name" | sha256sum --check
  printf '%s  %s\n' "$archive_sha" "$work_dir/$archive_name" | sha256sum --check
fi
listed_sha=$(awk -v name="$archive_name" '$2 == name { print $1 }' "$work_dir/$manifest_name")
[[ "$listed_sha" == "$archive_sha" ]] || {
  echo "OpenSC manifest disagrees with release digest for $archive_name" >&2; exit 1;
}

/usr/bin/unzip -tq "$work_dir/$archive_name" >/dev/null
mkdir -p "$work_dir/extracted" "$stage_dir/bin" "$stage_dir/lib"
/usr/bin/unzip -q "$work_dir/$archive_name" -d "$work_dir/extracted"
for required in bin/pkcs11-tool "lib/$spy_name" lib/pkcs11-spy.conf LICENSE-OpenSC.txt; do
  [[ -f "$work_dir/extracted/$required" ]] || {
    echo "OpenSC release is missing $required" >&2; exit 1;
  }
done
cp "$work_dir/extracted/bin/pkcs11-tool" "$stage_dir/bin/pkcs11-tool"
cp "$work_dir/extracted/lib/$spy_name" "$stage_dir/lib/$spy_name"
cp "$work_dir/extracted/lib/pkcs11-spy.conf" "$stage_dir/lib/pkcs11-spy.conf"
cp "$work_dir/extracted/LICENSE-OpenSC.txt" "$stage_dir/LICENSE-OpenSC.txt"
chmod +x "$stage_dir/bin/pkcs11-tool"
printf '%s\n' "$opensc_version" > "$stage_dir/OPENSC-VERSION.txt"
printf 'release=%s\narchive=%s\nsha256=%s\n' \
  "$opensc_version" "$archive_name" "$archive_sha" > "$stage_dir/OPENSC-SOURCE.txt"
