#!/usr/bin/env bash
# OpenSSL for the macOS test kit's TLS block: the conda-forge package pinned in
# conda-openssl.lock - the build the owner's pkcs11-provider fork is compiled
# against - checked against its SHA-256 and unpacked into the given directory,
# with its licence as LICENSE-OpenSSL.txt.
#
#   fetch-conda-openssl.sh <osx-arm64|osx-64> <directory>
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: fetch-conda-openssl.sh <osx-arm64|osx-64> <directory>" >&2
  exit 2
fi
subdir=$1
destination=$2
lock="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/conda-openssl.lock"
entry=$(awk -v subdir="$subdir" 'index($2, subdir "/") == 1 { print $1, $2 }' "$lock")
sha=${entry%% *}
path=${entry#* }
[[ -n $entry && $sha != "$path" ]] || { echo "no pinned conda-forge OpenSSL for $subdir" >&2; exit 1; }
name=${path#*/}

download=$(mktemp -d)
trap 'rm -rf "$download"' EXIT
curl --fail --silent --show-error --location --retry 5 --output "$download/$name" \
  "https://conda.anaconda.org/conda-forge/$path"
if command -v sha256sum >/dev/null 2>&1; then
  printf '%s  %s\n' "$sha" "$download/$name" | sha256sum --check
else
  printf '%s  %s\n' "$sha" "$download/$name" | shasum -a 256 --check
fi
payload=$(unzip -Z1 "$download/$name" | sed -n '/^pkg-.*\.tar\.zst$/p')
info=$(unzip -Z1 "$download/$name" | sed -n '/^info-.*\.tar\.zst$/p')
[[ -n $payload && -n $info ]] || { echo "unexpected conda package layout: $name" >&2; exit 1; }
mkdir -p "$destination" "$download/info"
unzip -p "$download/$name" "$payload" | zstd -dc | tar -xf - -C "$destination"
unzip -p "$download/$name" "$info" | zstd -dc | tar -xf - -C "$download/info"
cp "$download/info/info/licenses/LICENSE.txt" "$destination/LICENSE-OpenSSL.txt"
for file in lib/libcrypto.3.dylib lib/libssl.3.dylib bin/openssl include/openssl/ssl.h; do
  test -s "$destination/$file" || { echo "the conda package holds no $file" >&2; exit 1; }
done
printf 'conda-forge %s %s\n' "$path" "$sha" | tee "$destination/PACKAGE-SOURCE.txt"
