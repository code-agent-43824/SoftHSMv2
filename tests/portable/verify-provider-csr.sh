#!/usr/bin/env bash
# The scenario of docs/JOURNAL.md, 17 October 2026: the system OpenSSL creates
# a CSR through the system pkcs11-provider with a key held by this module. The
# provider closes its sessions and finalizes the module from OpenSSL's exit
# handler, after main has returned; the module used to die there with SIGSEGV
# once the CSR had already been written. So the exit status is the check, and
# the provider runs without no-deinit, which would skip those late calls.
#
# Usage: verify-provider-csr.sh <module> <softhsm2-util> <work-directory>
# Needs OpenSSL 3 as `openssl` and pkcs11-provider in its modules directory,
# both from the distribution. RSA and EC keys, with the Rutoken profile off
# and on.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  printf 'usage: %s <module> <softhsm2-util> <work-directory>\n' "$0" >&2
  exit 2
fi
module=$(realpath "$1")
util=$(realpath "$2")
work=$3
mkdir -p "$work"
work=$(realpath "$work")

# P11_PROVIDER_MODULE names another pkcs11.so; by default it is the one the
# distribution installed beside OpenSSL's modules.
modules_dir=$(openssl version -m | sed -n 's/^MODULESDIR: "\(.*\)"$/\1/p')
provider=${P11_PROVIDER_MODULE:-$modules_dir/pkcs11.so}
if [[ ! -f $provider ]]; then
  printf '[PROVIDER-CSR] FAIL: no pkcs11-provider at %s\n' "$provider" >&2
  exit 1
fi
printf '[PROVIDER-CSR] %s, provider %s\n' "$(openssl version)" "$provider"
if [[ -z ${P11_PROVIDER_MODULE:-} ]] && command -v dpkg-query >/dev/null 2>&1; then
  printf '[PROVIDER-CSR] package %s\n' \
    "$(dpkg-query -W -f '${Package} ${Version}' pkcs11-provider 2>/dev/null || echo unknown)"
fi

# Not the factory PINs: under the profile a token still holding them reports
# CKF_USER_PIN_TO_BE_CHANGED, as the device does, and pkcs11-provider 1.x then
# refuses to log in at all.
# The key itself - RSA modulus and exponent, EC point - whatever the encoding:
# pkcs11-provider 1.2 writes an EC key into the CSR with explicit curve
# parameters where 0.3 writes the curve's name.
public_numbers() {
  openssl pkey -pubin -in "$1" -noout -text_pub |
    awk '/^(Modulus|pub):/ { keep = 1; next } /^[^ ]/ { keep = 0 } keep; /^Exponent:/' |
    tr -d ' \n'
}

so_pin=56781234
user_pin=43218765
label=provider-csr

for profile in false true; do
  store="$work/profile-$profile"
  rm -rf "$store"
  mkdir -p "$store/tokens"
  write_config() {
    printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nFAKE_RUTOKEN_ECP = %s\n' \
      "$store" "$1" > "$store/softhsm.conf"
  }
  export SOFTHSM2_CONF="$store/softhsm.conf"
  # The token is made with the profile off: there it is one ordinary slot.
  write_config false
  "$util" --module "$module" --init-token --free --label "$label" --so-pin "$so_pin" --pin "$user_pin" >/dev/null
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$store/rsa.pem" 2>/dev/null
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$store/ec.pem" 2>/dev/null
  "$util" --module "$module" --import "$store/rsa.pem" --token "$label" --label rsa --id 01 --pin "$user_pin" >/dev/null
  "$util" --module "$module" --import "$store/ec.pem" --token "$label" --label ec --id 02 --pin "$user_pin" >/dev/null
  write_config "$profile"

  printf '%s\n' "$user_pin" > "$store/pin.txt"
  cat > "$store/openssl.cnf" <<EOF
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect
[default_sect]
activate = 1
[pkcs11_sect]
module = $provider
pkcs11-module-path = $module
pkcs11-module-token-pin = file:$store/pin.txt
activate = 1
EOF

  for key in rsa ec; do
    status=0
    OPENSSL_CONF="$store/openssl.cnf" openssl req -new \
      -key "pkcs11:token=$label;object=$key;type=private" \
      -subj "/CN=provider-csr-$key" -out "$store/$key.csr" \
      2> "$store/$key-req.log" || status=$?
    if [[ $status -ne 0 ]]; then
      printf '[PROVIDER-CSR] FAIL: FAKE_RUTOKEN_ECP=%s, %s: openssl req exited with %s\n' \
        "$profile" "$key" "$status" >&2
      cat "$store/$key-req.log" >&2
      exit 1
    fi
    verified=$(env -u OPENSSL_CONF openssl req -verify -noout -in "$store/$key.csr" 2>&1)
    if [[ $verified != *'verify OK'* ]]; then
      printf '[PROVIDER-CSR] FAIL: FAKE_RUTOKEN_ECP=%s, %s: %s\n' "$profile" "$key" "$verified" >&2
      exit 1
    fi
    env -u OPENSSL_CONF openssl req -in "$store/$key.csr" -pubkey -noout \
      > "$store/$key-csr-public.pem"
    openssl pkey -in "$store/$key.pem" -pubout -out "$store/$key-public.pem"
    if [[ $(public_numbers "$store/$key-csr-public.pem") != \
          $(public_numbers "$store/$key-public.pem") ]]; then
      printf '[PROVIDER-CSR] FAIL: FAKE_RUTOKEN_ECP=%s, %s: the CSR carries another key\n' \
        "$profile" "$key" >&2
      exit 1
    fi
    printf '[PROVIDER-CSR] PASS: FAKE_RUTOKEN_ECP=%s, %s: exit 0, the CSR verifies and carries the token key\n' \
      "$profile" "$key"
  done
done
unset SOFTHSM2_CONF
printf '[PROVIDER-CSR] PASS: CSR through pkcs11-provider without no-deinit\n'
