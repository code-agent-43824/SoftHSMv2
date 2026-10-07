#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 || -z ${RUTOKEN_PIN:-} ]]; then
  echo 'usage: RUTOKEN_PIN=<secret> verify-rutoken-cms-cross.sh <kit-dir> <module> <slot> <certificate-id> <token-ca.pem>' >&2
  exit 2
fi
kit=$(cd "$1" && pwd)
module=$2
slot=$3
certificate_id=$4
token_ca=$5
openssl="$kit/bin/openssl"
tool="$kit/bin/pkcs11-tool"
out="$kit/test-output/gost-cms"
mkdir -p "$out"
export OPENSSL_CONF="$kit/config/openssl-gost-engine.cnf"
export OPENSSL_ENGINES="$kit/bin"
export OPENSSL_MODULES="$kit/bin"

"$kit/scripts/verify-gost-cms.sh" "$kit"
"$tool" --module "$module" --slot "$slot" --login --pin env:RUTOKEN_PIN \
  --rutoken-pkcs7-verify --input-file "$out/openssl-smime.der" \
  --rutoken-trusted "$out/ca.der" --output-file "$out/rutoken-verified.txt" \
  > "$out/rutoken-verify.log"
cmp "$out/message.txt" "$out/rutoken-verified.txt"
echo '[GOST-CMS] PASS: OpenSSL envelope verified by Rutoken'

constraints=$("$openssl" x509 -in "$token_ca" -noout -ext basicConstraints)
grep -F 'critical' <<< "$constraints" >/dev/null
grep -F 'CA:TRUE' <<< "$constraints" >/dev/null
"$tool" --module "$module" --slot "$slot" --login --pin env:RUTOKEN_PIN \
  --rutoken-pkcs7-sign --id "$certificate_id" \
  --input-file "$out/message.txt" --output-file "$out/rutoken-signed.der" \
  > "$out/rutoken-sign.log"
"$openssl" smime -verify -inform DER -in "$out/rutoken-signed.der" \
  -CAfile "$token_ca" -out "$out/openssl-verified-rutoken.txt"
cmp "$out/message.txt" "$out/openssl-verified-rutoken.txt"
echo '[GOST-CMS] PASS: Rutoken envelope verified by OpenSSL'
