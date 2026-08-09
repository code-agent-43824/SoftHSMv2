#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build-test-kit-unix.sh <linux-x64|linux-arm64|macos-universal>" >&2
  exit 2
fi
: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"
: "${PORTABLE_PRODUCT_DIR:?PORTABLE_PRODUCT_DIR is required}"

platform=$1
case "$platform" in
  linux-x64) module_name=libsofthsm2.so ;;
  linux-arm64) module_name=libsofthsm2.so ;;
  macos-universal) module_name=libsofthsm2.dylib ;;
  *) echo "unsupported test-kit platform: $platform" >&2; exit 2 ;;
esac

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
product_dir=$(cd "$PORTABLE_PRODUCT_DIR" && pwd)
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/testkit-$platform"
archive="$work_dir/openssl.tar.gz"
source_dir="$work_dir/openssl-$OPENSSL_VERSION"
stage_dir="$work_dir/stage"
output_dir="$root_dir/dist"
archive_name="softhsm-testkit-$platform.zip"
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu)

mkdir -p "$work_dir" "$stage_dir/bin" "$stage_dir/config" "$stage_dir/scripts" \
  "$stage_dir/src/pkcs11" "$output_dir"
curl --fail --location --retry 5 --output "$archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
if [[ $(uname -s) == Darwin ]]; then
  printf '%s  %s\n' "$OPENSSL_SHA256" "$archive" | shasum -a 256 --check
else
  printf '%s  %s\n' "$OPENSSL_SHA256" "$archive" | sha256sum --check
fi
tar -xzf "$archive" -C "$work_dir"

if [[ "$platform" == macos-universal ]]; then
  export MACOSX_DEPLOYMENT_TARGET=11.0
  for arch in arm64 x86_64; do
    copy="$work_dir/openssl-$arch"
    prefix="$work_dir/install-$arch"
    cp -R "$source_dir" "$copy"
    pushd "$copy"
    target=darwin64-arm64-cc
    [[ "$arch" == x86_64 ]] && target=darwin64-x86_64-cc
    ./Configure "$target" no-shared no-module no-tests --prefix="$prefix" --libdir=lib
    make -j"$jobs" build_sw
    make install_sw
    popd
    clang++ -std=c++17 -O2 -Wall -Wextra -Werror -arch "$arch" \
      -mmacosx-version-min=11.0 -I"$root_dir/src/lib/pkcs11" \
      "$root_dir/tests/portable/portable-token-e2e.cpp" \
      -o "$work_dir/portable-token-e2e-$arch"
  done
  lipo -create "$work_dir/install-arm64/bin/openssl" "$work_dir/install-x86_64/bin/openssl" \
    -output "$stage_dir/bin/openssl"
  lipo -create "$work_dir/portable-token-e2e-arm64" "$work_dir/portable-token-e2e-x86_64" \
    -output "$stage_dir/bin/portable-token-e2e"
  lipo "$stage_dir/bin/openssl" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/portable-token-e2e" -verify_arch arm64 x86_64
  codesign --force --sign - "$stage_dir/bin/openssl"
  codesign --force --sign - "$stage_dir/bin/portable-token-e2e"
else
  prefix="$work_dir/install"
  pushd "$source_dir"
  ./Configure no-shared no-module no-tests --prefix="$prefix" --libdir=lib
  make -j"$jobs" build_sw
  make install_sw
  popd
  cp "$prefix/bin/openssl" "$stage_dir/bin/openssl"
  c++ -std=c++17 -O2 -Wall -Wextra -Werror -static-libstdc++ -static-libgcc \
    -I"$root_dir/src/lib/pkcs11" "$root_dir/tests/portable/portable-token-e2e.cpp" \
    -ldl -o "$stage_dir/bin/portable-token-e2e"
fi

cp "$source_dir/apps/openssl.cnf" "$stage_dir/config/openssl.cnf"
cp "$root_dir/tests/portable/run-test-kit.sh" "$stage_dir/run-test.sh"
cp "$root_dir/tests/portable/run-fresh-integration.sh" "$stage_dir/scripts/run-fresh-integration.sh"
cp "$root_dir/tests/portable/run-pkcs11-integration.sh" "$stage_dir/scripts/run-pkcs11-integration.sh"
cp "$root_dir/tests/portable/portable-token-e2e.cpp" "$stage_dir/src/portable-token-e2e.cpp"
cp "$root_dir/src/lib/pkcs11/"*.h "$stage_dir/src/pkcs11/"
cp "$root_dir/packaging/portable/TEST-KIT-README.txt" "$stage_dir/README.txt"
cp "$root_dir/LICENSE" "$stage_dir/LICENSE-TestClient.txt"
cp "$source_dir/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"
for required in "$module_name" softhsm.conf LICENSE-SoftHSM.txt LICENSE-Botan.txt; do
  if [[ ! -f "$product_dir/$required" ]]; then
    echo "required product file is missing: $product_dir/$required" >&2
    exit 1
  fi
done
cp "$product_dir/$module_name" "$stage_dir/$module_name"
cp "$product_dir/softhsm.conf" "$stage_dir/softhsm.conf"
cp "$product_dir/LICENSE-SoftHSM.txt" "$stage_dir/LICENSE-SoftHSM.txt"
cp "$product_dir/LICENSE-Botan.txt" "$stage_dir/LICENSE-Botan.txt"
if [[ -f "$product_dir/README.txt" ]]; then
  cp "$product_dir/README.txt" "$stage_dir/PRODUCT-README.txt"
fi
printf 'PLATFORM=%s\nMODULE_NAME=%s\nOPENSSL_VERSION=%s\n' \
  "$platform" "$module_name" "$OPENSSL_VERSION" > "$stage_dir/testkit.env"
{
  printf 'Platform: %s\n' "$platform"
  printf 'Built on fresh GitHub verification runner\n'
  printf 'Kernel: '; uname -a
  printf '\nC++ compiler:\n'; c++ --version 2>/dev/null || clang++ --version
  printf '\nBundled OpenSSL:\n'; "$stage_dir/bin/openssl" version -a
  printf '\nClient binary:\n'; file "$stage_dir/bin/portable-token-e2e"
  printf '\nOpenSSL binary:\n'; file "$stage_dir/bin/openssl"
} > "$stage_dir/ENVIRONMENT.txt"

chmod +x "$stage_dir/run-test.sh" "$stage_dir/bin/openssl" \
  "$stage_dir/bin/portable-token-e2e" "$stage_dir/scripts/"*.sh
if [[ $(uname -s) == Darwin ]]; then
  if otool -L "$stage_dir/bin/openssl" | grep -Eq 'lib(ssl|crypto)'; then
    echo "test-kit OpenSSL unexpectedly depends on external OpenSSL libraries" >&2
    exit 1
  fi
else
  if ldd "$stage_dir/bin/openssl" | grep -Eq 'lib(ssl|crypto)'; then
    echo "test-kit OpenSSL unexpectedly depends on external OpenSSL libraries" >&2
    exit 1
  fi
  if ldd "$stage_dir/bin/portable-token-e2e" | grep -Eq 'lib(stdc\+\+|gcc_s)'; then
    echo "test-kit client unexpectedly depends on C++ runtime libraries" >&2
    exit 1
  fi
fi

rm -f "$output_dir/$archive_name"
(cd "$stage_dir" && zip -X -9 -r "$output_dir/$archive_name" .)
if [[ $(uname -s) == Darwin ]]; then
  shasum -a 256 "$output_dir/$archive_name"
else
  sha256sum "$output_dir/$archive_name"
fi
