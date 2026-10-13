#!/usr/bin/env bash
set -euo pipefail

[[ $# == 1 ]] || { echo 'usage: verify-gost-cms.sh <kit-dir>' >&2; exit 2; }
kit=$(cd "$1" && pwd)
openssl="$kit/bin/openssl"
out="$kit/test-output/gost-cms"
mkdir -p "$out"
export OPENSSL_CONF="$kit/config/openssl-gost-engine.cnf"
export OPENSSL_ENGINES="$kit/bin"
export OPENSSL_MODULES="$kit/bin"

"$openssl" engine -t gost > "$out/engine.txt"
grep -F '[ available ]' "$out/engine.txt" >/dev/null
printf 'Portable GOST CMS cross-check\n' > "$out/message.txt"
"$openssl" genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:A \
  -out "$out/key.pem"
"$openssl" req -engine gost -new -x509 -key "$out/key.pem" \
  -out "$out/ca.pem" -subj '/CN=Portable GOST CMS CA' -days 1 \
  -addext 'basicConstraints=critical,CA:TRUE'
"$openssl" x509 -in "$out/ca.pem" -outform DER -out "$out/ca.der"
"$openssl" smime -sign -md streebog256 -binary -nodetach \
  -in "$out/message.txt" -signer "$out/ca.pem" -inkey "$out/key.pem" \
  -outform DER -out "$out/openssl-smime.der"
"$openssl" smime -verify -inform DER -in "$out/openssl-smime.der" \
  -CAfile "$out/ca.pem" -out "$out/openssl-smime-message.txt"
cmp "$out/message.txt" "$out/openssl-smime-message.txt"
"$openssl" cms -sign -md streebog256 -binary -nodetach \
  -in "$out/message.txt" -signer "$out/ca.pem" -inkey "$out/key.pem" \
  -outform DER -out "$out/openssl-cms.der"
"$openssl" cms -verify -inform DER -in "$out/openssl-cms.der" \
  -CAfile "$out/ca.pem" -out "$out/openssl-cms-message.txt"
cmp "$out/message.txt" "$out/openssl-cms-message.txt"
"$openssl" asn1parse -inform DER -in "$out/openssl-smime.der" \
  > "$out/openssl-smime-asn1.txt"
grep -F 'GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)' \
  "$out/openssl-smime-asn1.txt" >/dev/null

# OpenSSL encodes TC26-A's SubjectPublicKeyInfo with only the curve OID.
# A PKCS #11 verifier must infer the 2012/256 digest parameter from the key
# algorithm, including for envelopes produced outside the module.
tc26="$out/tc26"
mkdir -p "$tc26"
printf 'External TC26-A GOST CMS cross-check\n' > "$tc26/message.txt"
"$openssl" genpkey -engine gost -algorithm gost2012_256 -pkeyopt paramset:TCA \
  -out "$tc26/key.pem"
"$openssl" req -engine gost -new -x509 -key "$tc26/key.pem" \
  -out "$tc26/ca.pem" -subj '/CN=Portable TC26 GOST CMS CA' -days 1 \
  -addext 'basicConstraints=critical,CA:TRUE'
"$openssl" x509 -in "$tc26/ca.pem" -outform DER -out "$tc26/ca.der"
"$openssl" asn1parse -inform DER -in "$tc26/ca.der" > "$tc26/ca-asn1.txt"
grep -F 'GOST R 34.10-2012 (256 bit) ParamSet A' "$tc26/ca-asn1.txt" >/dev/null
for mode in smime cms; do
  "$openssl" "$mode" -sign -md streebog256 -binary -nodetach \
    -in "$tc26/message.txt" -signer "$tc26/ca.pem" -inkey "$tc26/key.pem" \
    -outform DER -out "$tc26/openssl-$mode.der"
  "$openssl" "$mode" -verify -binary -inform DER -in "$tc26/openssl-$mode.der" \
    -CAfile "$tc26/ca.pem" -out "$tc26/openssl-$mode-message.txt"
  cmp "$tc26/message.txt" "$tc26/openssl-$mode-message.txt"
done
echo '[GOST-CMS] PASS: ENGINE, S/MIME and CMS on CryptoPro-A and TC26-A'
