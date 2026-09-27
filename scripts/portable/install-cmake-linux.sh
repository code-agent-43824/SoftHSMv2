#!/usr/bin/env bash
set -euo pipefail

version=3.31.10
case "$(uname -m)" in
  x86_64) sha256=3cb3dd247b6a1de2d0f4b20c6fd4326c9024e894cebc9dc8699758887e566ca7 ;;
  aarch64) sha256=a343c6294f770742904e6a6792e0956b5ff8212abfb63cac99237de2e210fa0f ;;
  *) echo "unsupported CMake architecture: $(uname -m)" >&2; exit 2 ;;
esac

archive="${RUNNER_TEMP:?}/cmake-${version}-$(uname -m).tar.gz"
curl --fail --location --retry 5 --output "$archive" \
  "https://github.com/Kitware/CMake/releases/download/v${version}/cmake-${version}-linux-$(uname -m).tar.gz"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check
tar -xzf "$archive" -C /usr/local --strip-components=1
/usr/local/bin/cmake --version
