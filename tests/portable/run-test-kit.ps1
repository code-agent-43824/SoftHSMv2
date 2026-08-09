$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -lt 1 -or $args.Count -gt 2) {
    throw "usage: run-test.ps1 <product-package.zip-or-directory> [scenario-directory]"
}

$KitDir = $PSScriptRoot
$Product = (Resolve-Path -LiteralPath $args[0]).Path
$Settings = @{}
Get-Content (Join-Path $KitDir "testkit.env") | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { $Settings[$Matches[1]] = $Matches[2] }
}
$Client = (Resolve-Path (Join-Path $KitDir "bin/portable-token-e2e.exe")).Path
$OpenSSL = (Resolve-Path (Join-Path $KitDir "bin/openssl.exe")).Path
$env:P11_TEST_CLIENT = $Client
$env:OPENSSL_CONF = (Resolve-Path (Join-Path $KitDir "config/openssl.cnf")).Path

Write-Host "[TEST-KIT] platform=$($Settings.PLATFORM)"
Write-Host "[TEST-KIT] product source=$Product"
Write-Host "[TEST-KIT] precompiled client=$Client"
Write-Host "[TEST-KIT] bundled OpenSSL=$OpenSSL"

$Arguments = @($Product, $Settings.MODULE_NAME, $OpenSSL)
if ($args.Count -eq 2) { $Arguments += [IO.Path]::GetFullPath($args[1]) }
& (Join-Path $KitDir "scripts/run-fresh-integration.ps1") @Arguments
if ($LASTEXITCODE -ne 0) { throw "downloadable test kit failed" }
