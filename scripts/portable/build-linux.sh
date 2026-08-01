#!/usr/bin/env bash
set -euo pipefail

: "${PORTABLE_ARCH:?PORTABLE_ARCH is required}"
: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/linux-$PORTABLE_ARCH"
openssl_archive="$work_dir/openssl.tar.gz"
openssl_source="$work_dir/openssl-$OPENSSL_VERSION"
openssl_prefix="$work_dir/openssl-install"
build_dir="$work_dir/softhsm-build"
stage_dir="$work_dir/stage"
output_dir="$root_dir/dist"
archive_name="softhsm-portable-linux-$PORTABLE_ARCH.zip"

mkdir -p "$work_dir" "$output_dir"
curl --fail --location --retry 5 --output "$openssl_archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
printf '%s  %s\n' "$OPENSSL_SHA256" "$openssl_archive" | sha256sum --check
tar -xzf "$openssl_archive" -C "$work_dir"

pushd "$openssl_source"
./Configure no-shared no-module no-tests --prefix="$openssl_prefix" --libdir=lib
make -j"$(getconf _NPROCESSORS_ONLN)"
make install_sw install_ssldirs
popd

cmake -S "$root_dir" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_PORTABLE=ON \
  -DENABLE_STATIC=OFF \
  -DENABLE_P11_KIT=OFF \
  -DBUILD_TESTS=OFF \
  -DWITH_OBJECTSTORE_BACKEND_DB=OFF \
  -DWITH_CRYPTO_BACKEND=openssl \
  -DOPENSSL_ROOT_DIR="$openssl_prefix"
cmake --build "$build_dir" --parallel "$(getconf _NPROCESSORS_ONLN)"

mkdir -p "$stage_dir"
cp "$build_dir/src/lib/libsofthsm2.so" "$stage_dir/libsofthsm2.so"
strip --strip-unneeded "$stage_dir/libsofthsm2.so"
cp "$root_dir/packaging/portable/softhsm.conf" "$stage_dir/softhsm.conf"
cp "$root_dir/packaging/portable/README.txt" "$stage_dir/README.txt"
cp "$root_dir/LICENSE" "$stage_dir/LICENSE-SoftHSM.txt"
cp "$openssl_source/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"

if ldd "$stage_dir/libsofthsm2.so" | grep -Eq 'lib(ssl|crypto|stdc\+\+|gcc_s)'; then
  echo "portable module has an unexpected non-system runtime dependency" >&2
  ldd "$stage_dir/libsofthsm2.so" >&2
  exit 1
fi
unexpected_exports=$(nm -D --defined-only "$stage_dir/libsofthsm2.so" | awk '{print $3}' | grep -Ev '^(C_|SOFTHSM2_PORTABLE$)' || true)
if [[ -n "$unexpected_exports" ]]; then
  echo "portable module exports internal symbols:" >&2
  printf '%s\n' "$unexpected_exports" >&2
  exit 1
fi

rm -f "$output_dir/$archive_name"
(cd "$stage_dir" && zip -X -9 -j "$output_dir/$archive_name" ./*)
sha256sum "$output_dir/$archive_name"
