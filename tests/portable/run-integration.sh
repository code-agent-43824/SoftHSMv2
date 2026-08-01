#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: run-integration.sh <module> <softhsm2-util> <openssl> <config> <work-dir>" >&2
  exit 2
fi

module=$1
utility=$2
openssl=$3
config=$4
work_dir=$5
root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
deps_dir="$work_dir/java-deps"
classes_dir="$work_dir/java-classes"
bc_version=1.85

mkdir -p "$deps_dir" "$classes_dir"

download_jar() {
  local artifact=$1
  local expected_sha256=$2
  local target="$deps_dir/$artifact-$bc_version.jar"
  curl --fail --location --retry 5 --output "$target" \
    "https://repo1.maven.org/maven2/org/bouncycastle/$artifact/$bc_version/$artifact-$bc_version.jar"
  if [[ $(uname -s) != Darwin ]] && command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$expected_sha256" "$target" | sha256sum --check
  else
    printf '%s  %s\n' "$expected_sha256" "$target" | shasum -a 256 --check
  fi
}

download_jar bcprov-jdk18on 20af26bf6060bb8005cc2389916812c1e0e998dc48d2ced7131b89461b54cff7
download_jar bcpkix-jdk18on c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996
download_jar bcutil-jdk18on 590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d

classpath="$deps_dir/bcprov-jdk18on-$bc_version.jar:$deps_dir/bcpkix-jdk18on-$bc_version.jar:$deps_dir/bcutil-jdk18on-$bc_version.jar"
javac -encoding UTF-8 -cp "$classpath" -d "$classes_dir" \
  "$root_dir/tests/portable/PortableTokenIntegrationTest.java"
java -cp "$classes_dir:$classpath" PortableTokenIntegrationTest \
  "$module" "$utility" "$openssl" "$config" "$work_dir/scenario"
