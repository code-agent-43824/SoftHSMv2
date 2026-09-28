#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 && $# -ne 2 && ! ( $# -eq 3 && $2 == --pkcs11 ) ]]; then
  echo 'usage: verify-gost-openssl.sh <kit-dir> [exported-gost.der | --pkcs11 scenario-dir]' >&2
  exit 2
fi
kit_dir=$1
openssl="$kit_dir/bin/openssl"
evidence="$kit_dir/test-output/gost-openssl"
mkdir -p "$evidence"
"$openssl" list -providers > "$evidence/providers.txt"
grep -F 'gostprov' "$evidence/providers.txt" >/dev/null
grep -F 'default' "$evidence/providers.txt" >/dev/null

if [[ $# -eq 3 ]]; then
  scenario=$3/gost-pkcs11
  for bits in 256 512; do
    [[ $bits == 512 && ${P11_TEST_REQUIRE_GOST_IMPORT_EXPORT:-YES} == NO ]] && continue
    message="$scenario/message.bin"
    [[ $bits == 512 ]] && message="$scenario/message512.bin"
    "$openssl" dgst "-md_gost12_$bits" -binary -out "$evidence/openssl-digest$bits.bin" \
      "$scenario/message.bin"
    cmp "$scenario/digest$bits.bin" "$evidence/openssl-digest$bits.bin"
    cmp "$scenario/digest$bits.bin" "$scenario/digest$bits-multipart.bin"
    "$openssl" pkey -pubin -inform DER -in "$scenario/public$bits.der" \
      -out "$evidence/softhsm-public$bits.pem"
    changed="$evidence/changed-message$bits.bin"
    cp "$message" "$changed"
    printf 'x' | dd of="$changed" bs=1 seek=0 conv=notrunc 2>/dev/null
    variants=("")
    [[ $bits == 256 ]] && variants+=(-multipart)
    for variant in "${variants[@]}"; do
      signature="$scenario/signature$bits$variant.bin"
      "$openssl" dgst "-md_gost12_$bits" -verify "$evidence/softhsm-public$bits.pem" \
        -signature "$signature" "$message"
      if "$openssl" dgst "-md_gost12_$bits" -verify "$evidence/softhsm-public$bits.pem" \
          -signature "$signature" "$changed" >/dev/null 2>&1; then
        echo "SoftHSM GOST-$bits signature accepted a changed message" >&2; exit 1
      fi
      damaged="$evidence/damaged-signature$bits$variant.bin"
      dd if="$signature" of="$damaged" bs=1 count="$(($(wc -c < "$signature") - 1))" 2>/dev/null
      if "$openssl" dgst "-md_gost12_$bits" -verify "$evidence/softhsm-public$bits.pem" \
          -signature "$damaged" "$message" >/dev/null 2>&1; then
        echo "SoftHSM GOST-$bits accepted a truncated signature" >&2; exit 1
      fi
    done
    if [[ $bits == 256 ]]; then
      "$openssl" dgst -md_gost12_256 -verify "$evidence/softhsm-public256.pem" \
        -signature "$scenario/signature256-paramset.bin" "$message"
    fi
  done
  if [[ ${P11_TEST_REQUIRE_GOST_SYMMETRIC:-YES} != NO ]]; then
    for algorithm in magma kuznyechik; do
      key=$(od -An -tx1 -v "$scenario/$algorithm-key.bin" | tr -d ' \n')
      iv=$(od -An -tx1 -v "$scenario/$algorithm-iv.bin" | tr -d ' \n')
      "$openssl" enc "-$algorithm-ctr-acpkm" -K "$key" -iv "$iv" \
        -in "$scenario/$algorithm-plain.bin" -out "$evidence/openssl-$algorithm.bin"
      cmp "$scenario/$algorithm-cipher.bin" "$evidence/openssl-$algorithm.bin"
    done
  fi
  echo '[GOST-OPENSSL] PASS: SoftHSM PKCS #11 digests, signatures and shared ciphers'
  exit 0
fi

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
