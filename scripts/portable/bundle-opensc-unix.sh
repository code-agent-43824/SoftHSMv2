#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: bundle-opensc-unix.sh <linux-x64|linux-arm64|macos-universal> <stage-dir>" >&2
  exit 2
fi

platform=$1
stage_dir=$(cd "$2" && pwd)
opensc_dir="$stage_dir/bin/opensc-lib"
mkdir -p "$opensc_dir"

if [[ "$platform" == linux-* ]]; then
  command -v pkcs11-tool >/dev/null || {
    echo 'pkcs11-tool is missing; install the binary OpenSC operating-system package first' >&2
    exit 1
  }
  command -v patchelf >/dev/null || {
    echo 'patchelf is required to make the packaged pkcs11-tool relocatable' >&2
    exit 1
  }
  installed_tool=$(command -v pkcs11-tool)
  cp "$installed_tool" "$stage_dir/bin/pkcs11-tool"
  : > "$stage_dir/OPENSC-DEPENDENCIES.txt"
  while IFS= read -r dependency; do
    [[ -n "$dependency" && -f "$dependency" ]] || continue
    leaf=$(basename "$dependency")
    case "$leaf" in
      ld-linux-*|libc.so.*|libdl.so.*|libm.so.*|libpthread.so.*|librt.so.*|libgcc_s.so.*|libstdc++.so.*)
        continue
        ;;
    esac
    cp -L "$dependency" "$opensc_dir/$leaf"
    printf '%s <- %s\n' "$leaf" "$dependency" >> "$stage_dir/OPENSC-DEPENDENCIES.txt"
  done < <(ldd "$installed_tool" | awk '
    /=> \// { print $3 }
    /^[[:space:]]*\// { print $1 }
  ' | sort -u)
  patchelf --set-rpath '$ORIGIN/opensc-lib' "$stage_dir/bin/pkcs11-tool"
  for library in "$opensc_dir"/*; do
    [[ -f "$library" ]] || continue
    patchelf --set-rpath '$ORIGIN' "$library"
  done
  license=${OPENSC_LICENSE_PATH:-/usr/share/doc/opensc/copyright}
  if [[ -f "$license" ]]; then
    cp "$license" "$stage_dir/LICENSE-OpenSC.txt"
  else
    echo 'OpenSC package copyright file is missing' >&2
    exit 1
  fi
  opensc_version=${OPENSC_PACKAGE_VERSION:-$(dpkg-query -W -f='${Version}' opensc)}
else
  [[ "$platform" == macos-universal ]] || {
    echo "unsupported OpenSC platform: $platform" >&2
    exit 2
  }
  : "${OPENSC_VERSION:?OPENSC_VERSION is required}"
  : "${OPENSC_MACOS_SHA256:?OPENSC_MACOS_SHA256 is required}"
  work_dir="${RUNNER_TEMP:-$stage_dir}/opensc-macos-$OPENSC_VERSION"
  dmg="$work_dir/OpenSC-$OPENSC_VERSION.dmg"
  mount_point="$work_dir/mount"
  mkdir -p "$work_dir" "$mount_point"
  if [[ -e /Library/OpenSC ]]; then
    echo '/Library/OpenSC already exists; refusing to modify a pre-existing OpenSC installation' >&2
    exit 1
  fi
  curl --fail --location --retry 5 --output "$dmg" \
    "https://github.com/OpenSC/OpenSC/releases/download/$OPENSC_VERSION/OpenSC-$OPENSC_VERSION.dmg"
  printf '%s  %s\n' "$OPENSC_MACOS_SHA256" "$dmg" | shasum -a 256 --check
  hdiutil attach -nobrowse -readonly -mountpoint "$mount_point" "$dmg"
  pkg=$(find "$mount_point" -maxdepth 3 -type f -iname '*.pkg' -print | \
    grep -Eiv '(startup|token)' | sort | head -n 1 || true)
  if [[ -z "$pkg" ]]; then
    find "$mount_point" -maxdepth 3 -print >&2
    hdiutil detach "$mount_point"
    echo 'OpenSC DMG contains no suitable installer package' >&2
    exit 1
  fi
  sudo installer -pkg "$pkg" -target /
  hdiutil detach "$mount_point"

  installed_tool=/Library/OpenSC/bin/pkcs11-tool
  [[ -x "$installed_tool" ]] || { echo "installed pkcs11-tool is missing: $installed_tool" >&2; exit 1; }
  cp "$installed_tool" "$stage_dir/bin/pkcs11-tool"
  queue=("$installed_tool")
  index=0
  : > "$stage_dir/OPENSC-DEPENDENCIES.txt"
  : > "$work_dir/seen.txt"
  while [[ $index -lt ${#queue[@]} ]]; do
    source_binary=${queue[$index]}
    index=$((index + 1))
    while IFS= read -r reference; do
      case "$reference" in
        /System/Library/*|/usr/lib/*) continue ;;
      esac
      leaf=$(basename "$reference")
      if grep -Fxq "$leaf" "$work_dir/seen.txt"; then continue; fi
      resolved=
      if [[ -f "$reference" ]]; then
        resolved=$reference
      else
        resolved=$(find /Library/OpenSC -type f -name "$leaf" -print -quit)
      fi
      [[ -n "$resolved" && -f "$resolved" ]] || {
        echo "cannot resolve non-system OpenSC dependency: $reference" >&2
        exit 1
      }
      printf '%s\n' "$leaf" >> "$work_dir/seen.txt"
      cp -L "$resolved" "$opensc_dir/$leaf"
      printf '%s <- %s\n' "$leaf" "$resolved" >> "$stage_dir/OPENSC-DEPENDENCIES.txt"
      queue+=("$resolved")
    done < <(otool -L "$source_binary" | tail -n +2 | sed -E 's/^[[:space:]]*([^[:space:]]+).*/\1/')
  done

  for binary in "$stage_dir/bin/pkcs11-tool" "$opensc_dir"/*; do
    [[ -f "$binary" ]] || continue
    binary_dir=$(dirname "$binary")
    while IFS= read -r reference; do
      case "$reference" in
        /System/Library/*|/usr/lib/*) continue ;;
      esac
      leaf=$(basename "$reference")
      [[ -f "$opensc_dir/$leaf" ]] || continue
      if [[ "$binary_dir" == "$opensc_dir" ]]; then
        replacement="@loader_path/$leaf"
      else
        replacement="@loader_path/opensc-lib/$leaf"
      fi
      install_name_tool -change "$reference" "$replacement" "$binary"
    done < <(otool -L "$binary" | tail -n +2 | sed -E 's/^[[:space:]]*([^[:space:]]+).*/\1/')
    if [[ "$binary_dir" == "$opensc_dir" ]]; then
      install_name_tool -id "@loader_path/$(basename "$binary")" "$binary"
    fi
    codesign --force --sign - "$binary"
  done
  license=$(find /Library/OpenSC -type f \( -iname 'COPYING*' -o -iname 'LICENSE*' \) -print -quit)
  if [[ -n "$license" ]]; then
    cp "$license" "$stage_dir/LICENSE-OpenSC.txt"
  else
    curl --fail --location --retry 5 \
      "https://raw.githubusercontent.com/OpenSC/OpenSC/$OPENSC_VERSION/COPYING" \
      --output "$stage_dir/LICENSE-OpenSC.txt"
  fi
  opensc_version=$OPENSC_VERSION
  # The fresh verifier must prove that the copied tool does not fall back to
  # the just-installed tree. Moving it aside is recoverable and runner-local.
  sudo mv /Library/OpenSC "$work_dir/installed-tree-disabled"
fi

chmod +x "$stage_dir/bin/pkcs11-tool"
[[ -n "$opensc_version" ]] || { echo 'cannot determine packaged OpenSC version' >&2; exit 1; }
printf '%s\n' "$opensc_version" > "$stage_dir/OPENSC-VERSION.txt"
