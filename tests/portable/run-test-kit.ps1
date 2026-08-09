$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -gt 1) {
    throw "usage: run-test.ps1 [path-to-alternative-pkcs11-library]"
}

$KitDir = $PSScriptRoot
$Settings = @{}
Get-Content (Join-Path $KitDir "testkit.env") | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { $Settings[$Matches[1]] = $Matches[2] }
}
$Client = (Resolve-Path (Join-Path $KitDir "bin/portable-token-e2e.exe")).Path
$OpenSSL = (Resolve-Path (Join-Path $KitDir "bin/openssl.exe")).Path
$Module = if ($args.Count -eq 1) {
    (Resolve-Path -LiteralPath $args[0]).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $KitDir $Settings.MODULE_NAME)).Path
}
if (-not (Test-Path -LiteralPath $Module -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $Module"
}
$AdjacentConfig = Join-Path (Split-Path -Parent $Module) "softhsm.conf"
$Config = if (Test-Path -LiteralPath $AdjacentConfig -PathType Leaf) {
    (Resolve-Path -LiteralPath $AdjacentConfig).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $KitDir "softhsm.conf")).Path
}
$env:P11_TEST_CLIENT = $Client
$env:OPENSSL_CONF = (Resolve-Path (Join-Path $KitDir "config/openssl.cnf")).Path

Write-Host "[TEST-KIT] platform=$($Settings.PLATFORM)"
Write-Host "[TEST-KIT] PKCS #11 library=$Module"
Write-Host "[TEST-KIT] SoftHSM config=$Config"
Write-Host "[TEST-KIT] precompiled client=$Client"
Write-Host "[TEST-KIT] bundled OpenSSL=$OpenSSL"

& (Join-Path $KitDir "scripts/run-fresh-integration.ps1") $Module $OpenSSL $Config
if ($LASTEXITCODE -ne 0) { throw "downloadable test kit failed" }
