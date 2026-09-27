#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: build-test-kit-unix.sh <linux-x64|linux-arm64|macos-universal>" >&2
  exit 2
fi
: "${OPENSSL_VERSION:?OPENSSL_VERSION is required}"
: "${OPENSSL_SHA256:?OPENSSL_SHA256 is required}"
: "${GOST_ENGINE_COMMIT:?GOST_ENGINE_COMMIT is required}"
: "${GOST_ENGINE_SHA256:?GOST_ENGINE_SHA256 is required}"
: "${GOST_LIBPROV_COMMIT:?GOST_LIBPROV_COMMIT is required}"
: "${GOST_LIBPROV_SHA256:?GOST_LIBPROV_SHA256 is required}"
if [[ ${OPENSSL_GOST_BUNDLE_ONLY:-} != 1 ]]; then
  : "${PORTABLE_PRODUCT_DIR:?PORTABLE_PRODUCT_DIR is required}"
fi

platform=$1
case "$platform" in
  linux-x64) module_name=libsofthsm2.so ;;
  linux-arm64) module_name=libsofthsm2.so ;;
  macos-universal) module_name=libsofthsm2.dylib ;;
  *) echo "unsupported test-kit platform: $platform" >&2; exit 2 ;;
esac

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
if [[ ${OPENSSL_GOST_BUNDLE_ONLY:-} != 1 ]]; then
  product_dir=$(cd "$PORTABLE_PRODUCT_DIR" && pwd)
fi
work_dir="${RUNNER_TEMP:-$root_dir/.portable-work}/testkit-$platform"
archive="$work_dir/openssl.tar.gz"
source_dir="$work_dir/openssl-$OPENSSL_VERSION"
stage_dir="$work_dir/stage"
output_dir="$root_dir/dist"
archive_name="softhsm-testkit-$platform.zip"
jobs=${PORTABLE_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu)}
engine_archive="$work_dir/gost-engine.tar.gz"
libprov_archive="$work_dir/gost-libprov.tar.gz"
engine_dir="$work_dir/engine"

mkdir -p "$work_dir" "$stage_dir/bin" "$stage_dir/config" "$stage_dir/scripts" \
  "$stage_dir/src/pkcs11" "$output_dir"
if [[ ${OPENSSL_GOST_USE_BUNDLE:-0} == 1 ]]; then
  lock="$root_dir/scripts/portable/openssl-gost-bundle.lock"
  bundle_tag=$(awk '$1 == "tag" { print $2 }' "$lock")
  bundle_name="openssl-gost-$platform.zip"
  bundle_sha=$(awk -v name="$bundle_name" '$2 == name { print $1 }' "$lock")
  [[ -n $bundle_tag && -n $bundle_sha ]] || {
    echo "missing bundle tag or checksum for $platform" >&2; exit 1;
  }
  bundle_archive="$work_dir/$bundle_name"
  curl --fail --location --retry 5 --output "$bundle_archive" \
    "https://github.com/code-agent-43824/SoftHSMv2/releases/download/$bundle_tag/$bundle_name"
  if [[ $(uname -s) == Darwin ]]; then
    printf '%s  %s\n' "$bundle_sha" "$bundle_archive" | shasum -a 256 --check
  else
    printf '%s  %s\n' "$bundle_sha" "$bundle_archive" | sha256sum --check
  fi
  /usr/bin/unzip -q "$bundle_archive" -d "$stage_dir"
else
curl --fail --location --retry 5 --output "$archive" \
  "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
if [[ $(uname -s) == Darwin ]]; then
  printf '%s  %s\n' "$OPENSSL_SHA256" "$archive" | shasum -a 256 --check
else
  printf '%s  %s\n' "$OPENSSL_SHA256" "$archive" | sha256sum --check
fi
tar -xzf "$archive" -C "$work_dir"
curl --fail --location --retry 5 --output "$engine_archive" \
  "https://codeload.github.com/gost-engine/engine/tar.gz/$GOST_ENGINE_COMMIT"
curl --fail --location --retry 5 --output "$libprov_archive" \
  "https://codeload.github.com/provider-corner/libprov/tar.gz/$GOST_LIBPROV_COMMIT"
if [[ $(uname -s) == Darwin ]]; then
  printf '%s  %s\n' "$GOST_ENGINE_SHA256" "$engine_archive" | shasum -a 256 --check
  printf '%s  %s\n' "$GOST_LIBPROV_SHA256" "$libprov_archive" | shasum -a 256 --check
else
  printf '%s  %s\n' "$GOST_ENGINE_SHA256" "$engine_archive" | sha256sum --check
  printf '%s  %s\n' "$GOST_LIBPROV_SHA256" "$libprov_archive" | sha256sum --check
fi
mkdir -p "$engine_dir/libprov"
tar -xzf "$engine_archive" -C "$engine_dir" --strip-components=1
tar -xzf "$libprov_archive" -C "$engine_dir/libprov" --strip-components=1

build_provider() {
  local prefix=$1 build_dir=$2
  shift 2
  cmake -S "$engine_dir" -B "$build_dir" "$@" \
    -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR="$prefix" \
    -DOPENSSL_ENGINES_DIR=lib/engines-3 \
    -DGOST_BUILD_ENGINE=OFF -DGOST_BUILD_STATIC_ENGINE=OFF \
    -DGOST_BUILD_PROVIDER=ON
  cmake --build "$build_dir" --target gost_prov -j "$jobs"
}

if [[ "$platform" == macos-universal ]]; then
  export MACOSX_DEPLOYMENT_TARGET=11.0
  for arch in arm64 x86_64; do
    copy="$work_dir/openssl-$arch"
    prefix="$work_dir/install-$arch"
    cp -R "$source_dir" "$copy"
    pushd "$copy"
    target=darwin64-arm64-cc
    [[ "$arch" == x86_64 ]] && target=darwin64-x86_64-cc
    ./Configure "$target" shared no-tests --prefix="$prefix" --libdir=lib
    make -j"$jobs" build_sw
    make install_sw
    popd
    build_provider "$prefix" "$work_dir/gost-build-$arch" -DCMAKE_OSX_ARCHITECTURES="$arch" \
      -DCMAKE_OSX_DEPLOYMENT_TARGET=11.0
    patched="$work_dir/patched-$arch"
    mkdir -p "$patched"
    cp "$prefix/bin/openssl" "$patched/openssl"
    cp "$prefix/lib/libcrypto.3.dylib" "$prefix/lib/libssl.3.dylib" "$patched/"
    cp "$work_dir/gost-build-$arch/bin/gostprov.dylib" "$patched/"
    install_name_tool -change "$prefix/lib/libcrypto.3.dylib" \
      '@loader_path/libcrypto.3.dylib' "$patched/openssl"
    install_name_tool -change "$prefix/lib/libssl.3.dylib" \
      '@loader_path/libssl.3.dylib' "$patched/openssl"
    install_name_tool -change "$prefix/lib/libcrypto.3.dylib" \
      '@loader_path/libcrypto.3.dylib' "$patched/libssl.3.dylib"
    install_name_tool -change "$prefix/lib/libcrypto.3.dylib" \
      '@loader_path/libcrypto.3.dylib' "$patched/gostprov.dylib"
    for library in libcrypto.3.dylib libssl.3.dylib; do
      install_name_tool -id "@loader_path/$library" "$patched/$library"
    done
  done
  lipo -create "$work_dir/patched-arm64/openssl" "$work_dir/patched-x86_64/openssl" \
    -output "$stage_dir/bin/openssl"
  for library in libcrypto.3.dylib libssl.3.dylib; do
    lipo -create "$work_dir/patched-arm64/$library" \
      "$work_dir/patched-x86_64/$library" -output "$stage_dir/bin/$library"
  done
  lipo -create "$work_dir/patched-arm64/gostprov.dylib" \
    "$work_dir/patched-x86_64/gostprov.dylib" \
    -output "$stage_dir/bin/gostprov.dylib"
  lipo "$stage_dir/bin/openssl" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/gostprov.dylib" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/libcrypto.3.dylib" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/libssl.3.dylib" -verify_arch arm64 x86_64
  codesign --force --sign - "$stage_dir/bin/libcrypto.3.dylib"
  codesign --force --sign - "$stage_dir/bin/libssl.3.dylib"
  codesign --force --sign - "$stage_dir/bin/gostprov.dylib"
  codesign --force --sign - "$stage_dir/bin/openssl"
else
  prefix="$work_dir/install"
  pushd "$source_dir"
  ./Configure shared no-tests --prefix="$prefix" --libdir=lib
  make -j"$jobs" build_sw
  make install_sw
  popd
  cp "$prefix/bin/openssl" "$stage_dir/bin/openssl"
  cp -L "$prefix/lib/libcrypto.so.3" "$prefix/lib/libssl.so.3" "$stage_dir/bin/"
  build_provider "$prefix" "$work_dir/gost-build"
  cp "$work_dir/gost-build/bin/gostprov.so" "$stage_dir/bin/"
  for binary in openssl libssl.so.3 gostprov.so; do
    patchelf --set-rpath '$ORIGIN' "$stage_dir/bin/$binary"
  done
fi

cp "$source_dir/apps/openssl.cnf" "$stage_dir/config/openssl.cnf"
cp "$engine_dir/test/provider.cnf" "$stage_dir/config/openssl-gost.cnf"
if [[ ${OPENSSL_GOST_BUNDLE_ONLY:-} == 1 ]]; then
  cp "$source_dir/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"
  cp "$engine_dir/LICENSE" "$stage_dir/LICENSE-GOST-Provider.txt"
  cp "$engine_dir/libprov/LICENSE" "$stage_dir/LICENSE-libprov.txt"
  bundle="$output_dir/openssl-gost-$platform.zip"
  (cd "$stage_dir" && zip -X -9 -r "$bundle" bin config \
    LICENSE-OpenSSL.txt LICENSE-GOST-Provider.txt LICENSE-libprov.txt)
  exit 0
fi
fi

if [[ "$platform" == macos-universal ]]; then
  for arch in arm64 x86_64; do
    clang++ -std=c++17 -O2 -Wall -Wextra -Werror -arch "$arch" \
      -mmacosx-version-min=11.0 -I"$root_dir/src/lib/pkcs11" \
      "$root_dir/tests/portable/portable-token-e2e.cpp" \
      -o "$work_dir/portable-token-e2e-$arch"
  done
  lipo -create "$work_dir/portable-token-e2e-arm64" "$work_dir/portable-token-e2e-x86_64" \
    -output "$stage_dir/bin/portable-token-e2e"
  lipo "$stage_dir/bin/portable-token-e2e" -verify_arch arm64 x86_64
  codesign --force --sign - "$stage_dir/bin/portable-token-e2e"
else
  c++ -std=c++17 -O2 -Wall -Wextra -Werror -static-libstdc++ -static-libgcc \
    -I"$root_dir/src/lib/pkcs11" "$root_dir/tests/portable/portable-token-e2e.cpp" \
    -ldl -o "$stage_dir/bin/portable-token-e2e"
fi

cp "$root_dir/tests/portable/run-test-kit.sh" "$stage_dir/run-test.sh"
cp "$root_dir/tests/portable/verify-gost-openssl.sh" "$stage_dir/scripts/verify-gost-openssl.sh"
cp "$root_dir/tests/portable/run-fresh-integration.sh" "$stage_dir/scripts/run-fresh-integration.sh"
cp "$root_dir/tests/portable/run-pkcs11-integration.sh" "$stage_dir/scripts/run-pkcs11-integration.sh"
cp "$root_dir/tests/portable/portable-token-e2e.cpp" "$stage_dir/src/portable-token-e2e.cpp"
cp "$root_dir/src/lib/pkcs11/"*.h "$stage_dir/src/pkcs11/"
cp "$root_dir/packaging/portable/TEST-KIT-README.txt" "$stage_dir/README.txt"
cp "$root_dir/packaging/portable/testkit.conf" "$stage_dir/testkit.conf"
cp "$root_dir/LICENSE" "$stage_dir/LICENSE-TestClient.txt"
if [[ ${OPENSSL_GOST_USE_BUNDLE:-0} != 1 ]]; then
  cp "$source_dir/LICENSE.txt" "$stage_dir/LICENSE-OpenSSL.txt"
  cp "$engine_dir/LICENSE" "$stage_dir/LICENSE-GOST-Provider.txt"
  cp "$engine_dir/libprov/LICENSE" "$stage_dir/LICENSE-libprov.txt"
fi
for required in "$module_name" softhsm2-util softhsm2-export LICENSE-SoftHSM.txt LICENSE-Botan.txt; do
  if [[ ! -f "$product_dir/$required" ]]; then
    echo "required product file is missing: $product_dir/$required" >&2
    exit 1
  fi
done
cp "$product_dir/$module_name" "$stage_dir/$module_name"
cp "$product_dir/softhsm2-util" "$stage_dir/bin/softhsm2-util"
cp "$product_dir/softhsm2-export" "$stage_dir/bin/softhsm2-export"
cp "$product_dir/LICENSE-SoftHSM.txt" "$stage_dir/LICENSE-SoftHSM.txt"
cp "$product_dir/LICENSE-Botan.txt" "$stage_dir/LICENSE-Botan.txt"
if [[ -f "$product_dir/README.txt" ]]; then
  cp "$product_dir/README.txt" "$stage_dir/PRODUCT-README.txt"
fi
"$root_dir/scripts/portable/bundle-opensc-unix.sh" "$platform" "$stage_dir"
opensc_version=$(sed -n '1p' "$stage_dir/OPENSC-VERSION.txt")
printf 'PLATFORM=%s\nMODULE_NAME=%s\nOPENSSL_VERSION=%s\nOPENSC_VERSION=%s\n' \
  "$platform" "$module_name" "$OPENSSL_VERSION" "$opensc_version" > "$stage_dir/testkit.env"
if [[ ${OPENSSL_GOST_USE_BUNDLE:-0} == 1 ]]; then
  printf 'OPENSSL_GOST_BUNDLE_TAG=%s\n' "$bundle_tag" >> "$stage_dir/testkit.env"
fi
{
  printf 'Platform: %s\n' "$platform"
  printf 'Built on fresh GitHub verification runner\n'
  printf 'Kernel: '; uname -a
  printf '\nC++ compiler:\n'; c++ --version 2>/dev/null || clang++ --version
  printf '\nBundled OpenSSL:\n'; \
    OPENSSL_CONF="$stage_dir/config/openssl.cnf" OPENSSL_MODULES="$stage_dir/bin" \
      "$stage_dir/bin/openssl" version -a
  printf '\nBundled OpenSC pkcs11-tool version:\n%s\n' "$opensc_version"
  printf '\nClient binary:\n'; file "$stage_dir/bin/portable-token-e2e"
  printf '\nOpenSSL binary:\n'; file "$stage_dir/bin/openssl"
  printf '\nOpenSC pkcs11-tool binary:\n'; file "$stage_dir/bin/pkcs11-tool"
} > "$stage_dir/ENVIRONMENT.txt"

chmod +x "$stage_dir/run-test.sh" "$stage_dir/bin/openssl" "$stage_dir/bin/pkcs11-tool" \
  "$stage_dir/bin/portable-token-e2e" "$stage_dir/bin/softhsm2-util" \
  "$stage_dir/bin/softhsm2-export" "$stage_dir/scripts/"*.sh
if [[ $(uname -s) == Darwin ]]; then
  if otool -L "$stage_dir/bin/openssl" | grep -E 'lib(ssl|crypto)' | \
      grep -v '@loader_path/'; then
    echo "test-kit OpenSSL depends on OpenSSL outside the kit" >&2; exit 1
  fi
  if otool -L "$stage_dir/bin/pkcs11-tool" "$stage_dir/bin/opensc-lib/"* | \
      grep -F '/Library/OpenSC/'; then
    echo "test-kit pkcs11-tool unexpectedly depends on the installed OpenSC tree" >&2
    exit 1
  fi
  lipo "$stage_dir/bin/pkcs11-tool" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/softhsm2-util" -verify_arch arm64 x86_64
  lipo "$stage_dir/bin/softhsm2-export" -verify_arch arm64 x86_64
else
  if ldd "$stage_dir/bin/openssl" | grep -E 'lib(ssl|crypto)' | \
      grep -v "$stage_dir/bin/"; then
    echo "test-kit OpenSSL depends on OpenSSL outside the kit" >&2; exit 1
  fi
  if ldd "$stage_dir/bin/portable-token-e2e" | grep -Eq 'lib(stdc\+\+|gcc_s)'; then
    echo "test-kit client unexpectedly depends on C++ runtime libraries" >&2
    exit 1
  fi
  if ldd "$stage_dir/bin/pkcs11-tool" | grep -F 'not found'; then
    echo "test-kit pkcs11-tool has an unresolved dependency" >&2
    exit 1
  fi
  for tool in softhsm2-util softhsm2-export; do
    if ldd "$stage_dir/bin/$tool" | grep -Eq 'lib(ssl|crypto|stdc\+\+|gcc_s|botan)'; then
      echo "test-kit $tool has an unexpected runtime dependency" >&2
      exit 1
    fi
  done
fi

rm -f "$output_dir/$archive_name"
(cd "$stage_dir" && zip -X -9 -r "$output_dir/$archive_name" .)
if [[ $(uname -s) == Darwin ]]; then
  shasum -a 256 "$output_dir/$archive_name"
else
  sha256sum "$output_dir/$archive_name"
fi
