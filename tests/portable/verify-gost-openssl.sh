#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 && $# -ne 2 ]]; then
  echo 'usage: verify-gost-openssl.sh <kit-dir> [exported-gost.der]' >&2
  exit 2
fi
kit_dir=$1
openssl="$kit_dir/bin/openssl"
evidence="$kit_dir/test-output/gost-openssl"
mkdir -p "$evidence"
"$openssl" list -providers > "$evidence/providers.txt"
grep -F 'gostprov' "$evidence/providers.txt" >/dev/null
grep -F 'default' "$evidence/providers.txt" >/dev/null

if [[ $# -eq 2 ]]; then
  "$openssl" pkey -inform DER -in "$2" -out "$evidence/exported-gost.pem"
  "$openssl" pkey -in "$evidence/exported-gost.pem" -pubout \
    -out "$evidence/exported-gost.pub.pem"
  "$openssl" dgst -md_gost12_256 -sign "$evidence/exported-gost.pem" \
    -out "$evidence/exported-gost.sig" "$evidence/m1.bin"
  "$openssl" dgst -md_gost12_256 -verify "$evidence/exported-gost.pub.pem" \
    -signature "$evidence/exported-gost.sig" "$evidence/m1.bin"
  echo '[GOST-OPENSSL] PASS: SoftHSM-exported key signed and verified'
  exit 0
fi

printf '012345678901234567890123456789012345678901234567890123456789012' \
  > "$evidence/m1.bin"
printf 'x12345678901234567890123456789012345678901234567890123456789012' \
  > "$evidence/tampered.bin"
test "$("$openssl" dgst -md_gost12_256 "$evidence/m1.bin" | sed 's/.*= //')" = \
  '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500'
test "$("$openssl" dgst -md_gost12_512 "$evidence/m1.bin" | sed 's/.*= //')" = \
  '1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48'
for bits in 256 512; do
  "$openssl" genpkey -algorithm "gost2012_$bits" -pkeyopt paramset:A \
    -out "$evidence/gost$bits.pem"
  "$openssl" pkey -in "$evidence/gost$bits.pem" -pubout \
    -out "$evidence/gost$bits.pub.pem"
  "$openssl" dgst "-md_gost12_$bits" -sign "$evidence/gost$bits.pem" \
    -out "$evidence/gost$bits.sig" "$evidence/m1.bin"
  "$openssl" dgst "-md_gost12_$bits" -verify "$evidence/gost$bits.pub.pem" \
    -signature "$evidence/gost$bits.sig" "$evidence/m1.bin"
  if "$openssl" dgst "-md_gost12_$bits" -verify "$evidence/gost$bits.pub.pem" \
      -signature "$evidence/gost$bits.sig" "$evidence/tampered.bin" >/dev/null 2>&1; then
    echo "tampered GOST-$bits message was accepted" >&2
    exit 1
  fi
done
for algorithm in kuznyechik-ctr magma-ctr kuznyechik-ctr-acpkm magma-ctr-acpkm; do
  iv=0011223344556677
  [[ $algorithm == magma-* ]] && iv=00112233
  "$openssl" enc "-$algorithm" \
    -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    -iv "$iv" -in "$evidence/m1.bin" -out "$evidence/$algorithm.bin"
  "$openssl" enc -d "-$algorithm" \
    -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
    -iv "$iv" -in "$evidence/$algorithm.bin" \
    -out "$evidence/$algorithm.roundtrip.bin"
  cmp "$evidence/m1.bin" "$evidence/$algorithm.roundtrip.bin"
done
echo '[GOST-OPENSSL] PASS: digests, signatures, Kuznyechik/Magma CTR-ACPKM and tamper rejection'
