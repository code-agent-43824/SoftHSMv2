#!/usr/bin/env bash
# The owner's pkcs11-provider fork (code-agent-43824/pkcs11-provider), one
# platform's dev archive from the release pinned in pkcs11-provider.lock,
# checked against its SHA-256 and unpacked into the given directory.
#
#   fetch-pkcs11-provider.sh <target> <directory>
#
# <target> is the archive's platform, e.g. linux-x86_64-ubuntu24.04.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: fetch-pkcs11-provider.sh <target> <directory>" >&2
  exit 2
fi
target=$1
destination=$2
lock="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pkcs11-provider.lock"
tag=$(awk '$1 == "tag" { print $2 }' "$lock")
name="pkcs11-provider-dev-$target.tar.gz"
sha=$(awk -v name="$name" '$2 == name { print $1 }' "$lock")
[[ -n $tag && -n $sha ]] || { echo "no pinned pkcs11-provider archive for $target" >&2; exit 1; }

download=$(mktemp -d)
trap 'rm -rf "$download"' EXIT
curl --fail --silent --show-error --location --retry 5 --output "$download/$name" \
  "https://github.com/code-agent-43824/pkcs11-provider/releases/download/$tag/$name"
# By system, not by what is installed: macOS may have a BSD sha256sum
# without --check.
if [[ $(uname -s) == Darwin ]]; then
  printf '%s  %s\n' "$sha" "$download/$name" | shasum -a 256 --check
else
  printf '%s  %s\n' "$sha" "$download/$name" | sha256sum --check
fi
mkdir -p "$destination"
tar -xzf "$download/$name" -C "$destination" --strip-components 1
test -f "$destination/lib/ossl-modules/pkcs11.so" || test -f "$destination/lib/ossl-modules/pkcs11.dll" ||
  test -f "$destination/lib/ossl-modules/pkcs11.dylib" ||
  { echo "the pkcs11-provider archive holds no provider module" >&2; exit 1; }
printf 'pkcs11-provider %s %s\n' "$tag" "$name"
sed -n '1,4p' "$destination/BUILD-INFO.txt"
