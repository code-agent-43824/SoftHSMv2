$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 3) {
    throw "usage: run-fresh-integration.ps1 <pkcs11-library> <openssl> <bundled-mode>"
}

$ModuleSource = (Resolve-Path -LiteralPath $args[0]).Path
$OpenSSL = (Resolve-Path -LiteralPath $args[1]).Path
$BundledMode = $args[2].ToUpperInvariant()
if ($BundledMode -notin @("YES", "NO")) {
    throw "bundled-mode must be YES or NO"
}
$KitDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$ScenarioDir = Join-Path $KitDir "test-output"
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { "$($env:HOMEDRIVE)$($env:HOMEPATH)" }
if (-not $UserHome) { throw "USERPROFILE or HOMEDRIVE/HOMEPATH is required" }
$UserConfig = Join-Path (Join-Path $UserHome "softhsm") "softhsm.conf"
$UserConfigPreexisting = Test-Path -LiteralPath $UserConfig

New-Item -ItemType Directory -Force -Path $ScenarioDir | Out-Null
if (-not (Test-Path -LiteralPath $ModuleSource -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $ModuleSource"
}
if ($BundledMode -eq "YES") {
    $Module = $ModuleSource
    Write-Host "[SCRIPT] using bundled PKCS #11 library directly inside test kit: $Module"
}
else {
    $Module = $ModuleSource
    Write-Host "[SCRIPT] using alternate PKCS #11 library directly in its original directory: $Module"
    if ($env:SOFTHSM2_CONF) {
        Write-Host "[SCRIPT] preserving caller-provided SOFTHSM2_CONF=$($env:SOFTHSM2_CONF)"
    }
}
if (-not $env:P11_TEST_USER_PIN) { throw "USER_PIN is missing from testkit.conf" }
if (-not $env:P11_TEST_REQUIRE_GOST_IMPORT_EXPORT) {
    $env:P11_TEST_REQUIRE_GOST_IMPORT_EXPORT = $BundledMode
}
if (-not $env:P11_TEST_REQUIRE_GOST_SYMMETRIC) {
    $env:P11_TEST_REQUIRE_GOST_SYMMETRIC = $BundledMode
}
if (-not $env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT) {
    $env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT = $BundledMode
}

& (Join-Path $PSScriptRoot "run-pkcs11-integration.ps1") $Module $OpenSSL $ScenarioDir
if ($LASTEXITCODE -ne 0) { throw "generic PKCS #11 integration test failed" }
if ($BundledMode -eq "YES") {
    $Adjacent = Join-Path (Split-Path -Parent $Module) "softhsm.conf"
    $Override = $env:SOFTHSM2_CONF -and (Test-Path -LiteralPath $env:SOFTHSM2_CONF -PathType Leaf)
    if ((Test-Path -LiteralPath $Adjacent -PathType Leaf) -and -not $Override) {
        $AdjacentTokens = Join-Path (Split-Path -Parent $Module) "tokens"
        if (-not (Test-Path -LiteralPath $AdjacentTokens -PathType Container)) {
            throw "module did not create adjacent test-kit token storage"
        }
        if (-not $UserConfigPreexisting -and (Test-Path -LiteralPath $UserConfig)) {
            throw "module unexpectedly created a per-user configuration"
        }
        Write-Host "[SCRIPT] verified adjacent test-kit token storage: $AdjacentTokens"
    }
    else {
        Write-Host "[SCRIPT] bundled module uses explicit override or legacy fallback"
    }
}
