#!/usr/bin/env bash
set -euo pipefail

: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/macos-universal"
openssl_archive="$work_dir/openssl.tar.gz"
openssl_source="$work_dir/openssl-$OPENSSL_VERSION"
stage_dir="$work_dir/stage"
output_dir="$root_dir/dist"
archive_name="softhsm-portable-macos-universal.zip"
deployment_target=11.0
export MACOSX_DEPLOYMENT_TARGET="$deployment_target"

mkdir -p "$work_dir" "$output_dir"
curl --fail --location --retry 5 --output "$openssl_archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
printf '%s  %s\n' "$OPENSSL_SHA256" "$openssl_archive" | shasum -a 256 --check
tar -xzf "$openssl_archive" -C "$work_dir"

for arch in arm64 x86_64; do
  source_copy="$work_dir/openssl-$arch"
  prefix="$work_dir/openssl-install-$arch"
  cp -R "$openssl_source" "$source_copy"
  pushd "$source_copy"
  if [[ "$arch" == arm64 ]]; then
    target=darwin64-arm64-cc
  else
    target=darwin64-x86_64-cc
  fi
  ./Configure "$target" \
    no-shared no-module no-tests --prefix="$prefix" --libdir=lib
  make -j"$(sysctl -n hw.logicalcpu)"
  make install_sw install_ssldirs
  popd
done

for arch in arm64 x86_64; do
  build_dir="$work_dir/softhsm-build-$arch"
  cmake -S "$root_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="$arch" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$deployment_target" \
    -DENABLE_PORTABLE=ON \
    -DENABLE_STATIC=OFF \
    -DENABLE_P11_KIT=OFF \
    -DBUILD_TESTS=OFF \
    -DWITH_OBJECTSTORE_BACKEND_DB=OFF \
    -DWITH_CRYPTO_BACKEND=openssl \
    -DOPENSSL_ROOT_DIR="$work_dir/openssl-install-$arch"
  cmake --build "$build_dir" --target softhsm2 softhsm2-util --parallel "$(sysctl -n hw.logicalcpu)"
done

arm_module=$(find "$work_dir/softhsm-build-arm64" -name libsofthsm2.dylib -type f -print -quit)
x64_module=$(find "$work_dir/softhsm-build-x86_64" -name libsofthsm2.dylib -type f -print -quit)
test -n "$arm_module"
test -n "$x64_module"
mkdir -p "$stage_dir"
lipo -create "$arm_module" "$x64_module" -output "$stage_dir/libsofthsm2.dylib"
strip -x "$stage_dir/libsofthsm2.dylib"
codesign --force --sign - "$stage_dir/libsofthsm2.dylib"
cp "$root_dir/packaging/portable/softhsm.conf" "$stage_dir/softhsm.conf"
cp "$root_dir/packaging/portable/README.txt" "$stage_dir/README.txt"
cp "$root_dir/LICENSE" "$stage_dir/LICENSE-SoftHSM.txt"
cp "$openssl_source/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"

cc "$root_dir/scripts/portable/smoke.c" -o "$work_dir/portable-smoke"
(cd /tmp && env -u SOFTHSM2_CONF "$work_dir/portable-smoke" "$stage_dir/libsofthsm2.dylib")
test -d "$stage_dir/tokens"

host_arch=$(uname -m)
if [[ "$host_arch" == x86_64 ]]; then
  native_arch=x86_64
elif [[ "$host_arch" == arm64 ]]; then
  native_arch=arm64
else
  echo "unsupported macOS runner architecture: $host_arch" >&2
  exit 1
fi
native_utility=$(find "$work_dir/softhsm-build-$native_arch" -name softhsm2-util -type f -print -quit)
test -n "$native_utility"
"$root_dir/tests/portable/run-integration.sh" \
  "$stage_dir/libsofthsm2.dylib" \
  "$native_utility" \
  "$work_dir/openssl-install-$native_arch/bin/openssl" \
  "$stage_dir/softhsm.conf" \
  "$work_dir/integration"
rm -rf "$stage_dir/tokens"

lipo "$stage_dir/libsofthsm2.dylib" -verify_arch arm64 x86_64
if otool -L "$stage_dir/libsofthsm2.dylib" | grep -Eq 'lib(ssl|crypto)'; then
  echo "portable module has an unexpected non-system runtime dependency" >&2
  otool -L "$stage_dir/libsofthsm2.dylib" >&2
  exit 1
fi

rm -f "$output_dir/$archive_name"
(cd "$stage_dir" && /usr/bin/zip -X -9 -j "$output_dir/$archive_name" ./*)
shasum -a 256 "$output_dir/$archive_name"
