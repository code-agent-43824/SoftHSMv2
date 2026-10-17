#!/usr/bin/env bash
# A TLS connection whose client key lives in this module under the Rutoken
# profile, made through OpenSSL 3 and pkcs11-provider.
#
#   run-tls.sh <module> <softhsm2-util> <pkcs11-tool> <pkcs11-provider> <tls-client> <work-directory>
#
# On a fresh store of its own: a token with the factory PINs, an RSA and an
# EC key pair generated on it under FAKE_RUTOKEN_ECP = true, for each key a
# CSR made by `openssl req` through the provider and a certificate from a
# throwaway CA, then tls-client connects to `openssl s_server` on 127.0.0.1,
# which requires that certificate, and gets its line back. Every OpenSSL
# process has to exit 0: the provider closes its sessions and finalizes the
# module after main (docs/JOURNAL.md, 17 October 2026).
#
# OPENSSL names the OpenSSL 3 command line whose libraries tls-client uses
# (default: openssl from PATH); P11_TLS_PORT the first of two local ports
# (default 48443).
set -euo pipefail

if [[ $# -ne 6 ]]; then
  printf 'usage: %s <module> <softhsm2-util> <pkcs11-tool> <pkcs11-provider> <tls-client> <work-directory>\n' \
    "$0" >&2
  exit 2
fi
module=$(realpath "$1")
util=$(realpath "$2")
tool=$(realpath "$3")
provider=$(realpath "$4")
client=$(realpath "$5")
mkdir -p "$6"
work=$(realpath "$6")
openssl_bin=${OPENSSL:-openssl}
port=${P11_TLS_PORT:-48443}
unset OPENSSL_CONF OPENSSL_MODULES

fail() {
  printf '[TLS] FAIL: %s\n' "$1" >&2
  exit 1
}

printf '[TLS] %s, provider %s\n' "$("$openssl_bin" version)" "$provider"

# The factory PINs of the Rutoken profile. The token reports
# CKF_USER_PIN_TO_BE_CHANGED with them, as the device does; the provider has
# to log in all the same.
so_pin=87654321
user_pin=12345678
label=tls-test

rm -rf "$work/store"
mkdir -p "$work/store/tokens"
write_config() {
  printf 'directories.tokendir = %s/store/tokens\nobjectstore.backend = file\nlog.level = ERROR\nFAKE_RUTOKEN_ECP = %s\n' \
    "$work" "$1" > "$work/store/softhsm.conf"
}
export SOFTHSM2_CONF="$work/store/softhsm.conf"
# The token is made with the profile off, where it is one ordinary slot; the
# keys are generated on it with the profile on.
write_config false
"$util" --module "$module" --init-token --free --label "$label" \
  --so-pin "$so_pin" --pin "$user_pin" > "$work/init-token.log"
write_config true
"$tool" --module "$module" --token-label "$label" --login --pin "$user_pin" \
  --keypairgen --key-type rsa:2048 --label tls-rsa --id 01 > "$work/keygen-rsa.log" 2>&1 ||
  { cat "$work/keygen-rsa.log" >&2; fail 'RSA key generation on the token'; }
"$tool" --module "$module" --token-label "$label" --login --pin "$user_pin" \
  --keypairgen --key-type EC:prime256v1 --label tls-ec --id 02 > "$work/keygen-ec.log" 2>&1 ||
  { cat "$work/keygen-ec.log" >&2; fail 'EC key generation on the token'; }
printf '[TLS] FAKE_RUTOKEN_ECP=true, factory PINs, RSA-2048 and EC P-256 generated on the token\n'

printf '%s\n' "$user_pin" > "$work/pin.txt"
cat > "$work/pkcs11.cnf" <<EOF
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
pkcs11-module-token-pin = file:$work/pin.txt
activate = 1
EOF

# The throwaway CA and the server; nothing of theirs is on the token.
cat > "$work/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = tls-test-ca
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
[server]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,DNS:localhost
[client]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
EOF
plain() { OPENSSL_CONF=/dev/null "$openssl_bin" "$@"; }
plain req -x509 -config "$work/ca.cnf" -extensions ca -newkey rsa:2048 -nodes \
  -keyout "$work/ca.key" -out "$work/ca.pem" -days 2 2>/dev/null
plain req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "$work/server.key" -subj /CN=localhost -out "$work/server.csr" 2>/dev/null
plain x509 -req -in "$work/server.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
  -CAcreateserial -days 2 -extfile "$work/ca.cnf" -extensions server \
  -out "$work/server.pem" 2>/dev/null

server_pid=
stop_server() {
  if [[ -n $server_pid ]]; then kill "$server_pid" 2>/dev/null || true; fi
}
trap stop_server EXIT

for key in rsa ec; do
  uri="pkcs11:token=$label;object=tls-$key;type=private"
  status=0
  OPENSSL_CONF="$work/pkcs11.cnf" "$openssl_bin" req -new -key "$uri" \
    -subj "/CN=tls-client-$key" -out "$work/client-$key.csr" \
    2> "$work/req-$key.log" || status=$?
  if [[ $status -ne 0 ]]; then
    cat "$work/req-$key.log" >&2
    fail "$key: openssl req through pkcs11-provider exited with $status"
  fi
  verified=$(plain req -verify -noout -in "$work/client-$key.csr" 2>&1)
  [[ $verified == *'verify OK'* ]] || fail "$key: the CSR does not verify: $verified"
  plain x509 -req -in "$work/client-$key.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
    -CAcreateserial -days 2 -extfile "$work/ca.cnf" -extensions client \
    -out "$work/client-$key.pem" 2>/dev/null

  # Started directly, not through plain(): $! has to be the server itself, or
  # stop_server would kill a subshell and leave the server holding the port.
  OPENSSL_CONF=/dev/null "$openssl_bin" s_server -accept "127.0.0.1:$port" \
    -cert "$work/server.pem" -key "$work/server.key" -CAfile "$work/ca.pem" \
    -Verify 1 -verify_return_error -rev -naccept 1 > "$work/server-$key.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 100); do
    grep -q '^ACCEPT' "$work/server-$key.log" 2>/dev/null && break
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 0.1
  done
  grep -q '^ACCEPT' "$work/server-$key.log" ||
    { cat "$work/server-$key.log" >&2; fail "$key: s_server did not start on port $port"; }

  status=0
  OPENSSL_CONF="$work/pkcs11.cnf" "$client" 127.0.0.1 "$port" "$uri" \
    "$work/client-$key.pem" "$work/ca.pem" > "$work/client-$key.log" 2>&1 || status=$?
  cat "$work/client-$key.log"
  [[ $status -eq 0 ]] || fail "$key: tls-client exited with $status"
  wait "$server_pid" || true
  server_pid=
  grep -Fq "CN=tls-client-$key" "$work/server-$key.log" ||
    grep -Fq "CN = tls-client-$key" "$work/server-$key.log" ||
    { cat "$work/server-$key.log" >&2; fail "$key: the server did not see the token certificate"; }
  printf '[TLS] PASS: %s: the CSR through the provider and the TLS connection with the token key\n' "$key"
  port=$((port + 1))
done
unset SOFTHSM2_CONF
printf '[TLS] PASS: TLS with the client key in the module under FAKE_RUTOKEN_ECP\n'
