param(
    [Parameter(Mandatory = $true)][string]$KitDir,
    [string]$ExportedKey
)
$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$OpenSSL = Join-Path $KitDir "bin/openssl.exe"
$Evidence = Join-Path $KitDir "test-output/gost-openssl"
New-Item -ItemType Directory -Force -Path $Evidence | Out-Null

function Invoke-OpenSSL([string[]]$Arguments) {
    & $OpenSSL @Arguments
    if ($LASTEXITCODE -ne 0) {
        $ExitCode = $LASTEXITCODE
        Write-Host "[GOST-OPENSSL] failed command: $($Arguments -join ' ') (exit $ExitCode)"
        $PreviousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $OpenSSL list -public-key-algorithms -provider gostprov -provider default 2>&1 |
                Select-String -Pattern 'gost2012_256|gost2012_512|gost2001' |
                ForEach-Object { Write-Host "[GOST-OPENSSL] algorithm diagnostic: $_" }
        }
        finally { $ErrorActionPreference = $PreviousPreference }
        throw "OpenSSL failed: $($Arguments[0]) (exit $ExitCode)"
    }
}

$Providers = @(& $OpenSSL list -providers)
if ($LASTEXITCODE -ne 0) { throw "OpenSSL provider listing failed" }
$Providers | Set-Content -LiteralPath (Join-Path $Evidence "providers.txt")
$ProviderText = $Providers -join "`n"
if ($ProviderText -notmatch 'gostprov' -or $ProviderText -notmatch 'default') {
    $Providers | ForEach-Object { Write-Host "[GOST-OPENSSL] provider listing: $_" }
    & $OpenSSL list -providers -provider-path (Join-Path $KitDir "bin") `
        -provider gostprov -provider default -verbose
    throw "GOST and default providers must both load"
}

$Message = Join-Path $Evidence "m1.bin"
if ($ExportedKey) {
    $Private = Join-Path $Evidence "exported-gost.pem"
    $Public = Join-Path $Evidence "exported-gost.pub.pem"
    $Signature = Join-Path $Evidence "exported-gost.sig"
    Invoke-OpenSSL -Arguments @("pkey", "-inform", "DER", "-in", $ExportedKey, "-out", $Private)
    Invoke-OpenSSL -Arguments @("pkey", "-in", $Private, "-pubout", "-out", $Public)
    Invoke-OpenSSL -Arguments @("dgst", "-md_gost12_256", "-sign", $Private,
        "-out", $Signature, $Message)
    Invoke-OpenSSL -Arguments @("dgst", "-md_gost12_256", "-verify", $Public,
        "-signature", $Signature, $Message)
    Write-Host "[GOST-OPENSSL] PASS: SoftHSM-exported key signed and verified"
    $global:LASTEXITCODE = 0
    return
}

$Text = '012345678901234567890123456789012345678901234567890123456789012'
[IO.File]::WriteAllBytes($Message, [Text.Encoding]::ASCII.GetBytes($Text))
$Tampered = Join-Path $Evidence "tampered.bin"
[IO.File]::WriteAllBytes($Tampered, [Text.Encoding]::ASCII.GetBytes("x$($Text.Substring(1))"))
foreach ($Case in @(
    @{ Bits = 256; Hash = '9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500' },
    @{ Bits = 512; Hash = '1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48' }
)) {
    $Bits = $Case.Bits
    $Actual = @(& $OpenSSL dgst "-md_gost12_$Bits" $Message)
    if ($LASTEXITCODE -ne 0 -or ($Actual -join '') -notmatch [regex]::Escape($Case.Hash)) {
        throw "Streebog-$Bits reference vector mismatch"
    }
    $Private = Join-Path $Evidence "gost$Bits.pem"
    $Public = Join-Path $Evidence "gost$Bits.pub.pem"
    $Signature = Join-Path $Evidence "gost$Bits.sig"
    Invoke-OpenSSL -Arguments @("genpkey", "-algorithm", "gost2012_$Bits", "-pkeyopt",
        "paramset:A", "-out", $Private)
    Invoke-OpenSSL -Arguments @("pkey", "-in", $Private, "-pubout", "-out", $Public)
    Invoke-OpenSSL -Arguments @("dgst", "-md_gost12_$Bits", "-sign", $Private,
        "-out", $Signature, $Message)
    Invoke-OpenSSL -Arguments @("dgst", "-md_gost12_$Bits", "-verify", $Public,
        "-signature", $Signature, $Message)
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $OpenSSL dgst "-md_gost12_$Bits" -verify $Public -signature $Signature $Tampered *> $null
        $NegativeCode = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $PreviousPreference }
    if ($NegativeCode -eq 0) { throw "tampered GOST-$Bits message was accepted" }
}
foreach ($Algorithm in @("kuznyechik-ctr", "magma-ctr", "kuznyechik-ctr-acpkm", "magma-ctr-acpkm")) {
    $IV = if ($Algorithm.StartsWith("magma-")) { "00112233" } else { "0011223344556677" }
    $Cipher = Join-Path $Evidence "$Algorithm.bin"
    $Roundtrip = Join-Path $Evidence "$Algorithm.roundtrip.bin"
    $Key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
    Invoke-OpenSSL -Arguments @("enc", "-$Algorithm", "-K", $Key, "-iv", $IV,
        "-in", $Message, "-out", $Cipher)
    Invoke-OpenSSL -Arguments @("enc", "-d", "-$Algorithm", "-K", $Key, "-iv", $IV,
        "-in", $Cipher, "-out", $Roundtrip)
    if ((Get-FileHash -Algorithm SHA256 $Message).Hash -ne
        (Get-FileHash -Algorithm SHA256 $Roundtrip).Hash) {
        throw "$Algorithm roundtrip mismatch"
    }
}
Write-Host "[GOST-OPENSSL] PASS: digests, signatures, Kuznyechik/Magma CTR-ACPKM and tamper rejection"
$global:LASTEXITCODE = 0
