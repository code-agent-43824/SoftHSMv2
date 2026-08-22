#!/usr/bin/env bash
set -euo pipefail

: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"
: "${BOTAN_VERSION:?BOTAN_VERSION is required}"
: "${BOTAN_SHA256:?BOTAN_SHA256 is required}"

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/macos-universal"
openssl_archive="$work_dir/openssl.tar.gz"
openssl_source="$work_dir/openssl-$OPENSSL_VERSION"
botan_archive="$work_dir/botan.tar.xz"
botan_source="$work_dir/Botan-$BOTAN_VERSION"
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

curl --fail --location --retry 5 --output "$botan_archive" \
  "https://botan.randombit.net/releases/Botan-$BOTAN_VERSION.tar.xz"
printf '%s  %s\n' "$BOTAN_SHA256" "$botan_archive" | shasum -a 256 --check
tar -xJf "$botan_archive" -C "$work_dir"

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
  botan_build="$work_dir/botan-build-$arch"
  python3 "$botan_source/configure.py" \
    --cc=clang --os=darwin --cpu="$arch" \
    --cc-abi-flags="-arch $arch -mmacosx-version-min=$deployment_target" \
    --disable-shared --minimized-build --enable-modules=streebog,gost_3410,emsa_raw \
    --without-documentation --with-build-dir="$botan_build"
  make -C "$botan_build" -j"$(sysctl -n hw.logicalcpu)" libs
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
    -DENABLE_GOST_3411_2012=ON \
    -DENABLE_GOST_3410_2012_256=ON \
    -DBOTAN_GOST_INCLUDE_DIR="$work_dir/botan-build-$arch/build/include" \
    -DBOTAN_GOST_LIBRARY="$work_dir/botan-build-$arch/libbotan-2.a" \
    -DOPENSSL_ROOT_DIR="$work_dir/openssl-install-$arch"
  cmake --build "$build_dir" --target softhsm2 softhsm2-util softhsm2-export \
    --parallel "$(sysctl -n hw.logicalcpu)"
done

arm_module=$(find "$work_dir/softhsm-build-arm64" -name libsofthsm2.dylib -type f -print -quit)
x64_module=$(find "$work_dir/softhsm-build-x86_64" -name libsofthsm2.dylib -type f -print -quit)
arm_util=$(find "$work_dir/softhsm-build-arm64" -name softhsm2-util -type f -print -quit)
x64_util=$(find "$work_dir/softhsm-build-x86_64" -name softhsm2-util -type f -print -quit)
arm_export=$(find "$work_dir/softhsm-build-arm64" -name softhsm2-export -type f -print -quit)
x64_export=$(find "$work_dir/softhsm-build-x86_64" -name softhsm2-export -type f -print -quit)
test -n "$arm_module"
test -n "$x64_module"
test -n "$arm_util"
test -n "$x64_util"
test -n "$arm_export"
test -n "$x64_export"
mkdir -p "$stage_dir"
lipo -create "$arm_module" "$x64_module" -output "$stage_dir/libsofthsm2.dylib"
lipo -create "$arm_util" "$x64_util" -output "$stage_dir/softhsm2-util"
lipo -create "$arm_export" "$x64_export" -output "$stage_dir/softhsm2-export"
strip -x "$stage_dir/libsofthsm2.dylib"
strip -x "$stage_dir/softhsm2-util" "$stage_dir/softhsm2-export"
for binary in libsofthsm2.dylib softhsm2-util softhsm2-export; do
  codesign --force --sign - "$stage_dir/$binary"
done
cp "$root_dir/packaging/portable/README.txt" "$stage_dir/README.txt"
cp "$root_dir/LICENSE" "$stage_dir/LICENSE-SoftHSM.txt"
cp "$openssl_source/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"
cp "$botan_source/license.txt" "$stage_dir/LICENSE-Botan.txt"

lipo "$stage_dir/libsofthsm2.dylib" -verify_arch arm64 x86_64
for binary in libsofthsm2.dylib softhsm2-util softhsm2-export; do
  lipo "$stage_dir/$binary" -verify_arch arm64 x86_64
  if otool -L "$stage_dir/$binary" | grep -Eq 'lib(ssl|crypto|botan)'; then
    echo "portable $binary has an unexpected non-system runtime dependency" >&2
    otool -L "$stage_dir/$binary" >&2
    exit 1
  fi
done
"$stage_dir/softhsm2-util" --version
"$stage_dir/softhsm2-export" --version

rm -f "$output_dir/$archive_name"
(cd "$stage_dir" && /usr/bin/zip -X -9 -j "$output_dir/$archive_name" ./*)
shasum -a 256 "$output_dir/$archive_name"
