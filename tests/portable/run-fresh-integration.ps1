$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 4) {
    throw "usage: run-fresh-integration.ps1 <pkcs11-library> <openssl> <softhsm.conf> <bundled-mode>"
}

$ModuleSource = (Resolve-Path -LiteralPath $args[0]).Path
$OpenSSL = (Resolve-Path -LiteralPath $args[1]).Path
$ConfigSource = (Resolve-Path -LiteralPath $args[2]).Path
$BundledMode = $args[3].ToUpperInvariant()
if ($BundledMode -notin @("YES", "NO")) {
    throw "bundled-mode must be YES or NO"
}
$TempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$WorkRoot = Join-Path $TempRoot ("softhsm-fresh-test-" + [guid]::NewGuid())
$PackageDir = Join-Path $WorkRoot "package"
$ScenarioDir = Join-Path $WorkRoot "scenario"
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { "$($env:HOMEDRIVE)$($env:HOMEPATH)" }
if (-not $UserHome) { throw "USERPROFILE or HOMEDRIVE/HOMEPATH is required" }
$UserConfig = Join-Path $UserHome "softhsm2.conf"
$UserConfigPreexisting = Test-Path -LiteralPath $UserConfig

New-Item -ItemType Directory -Force -Path $ScenarioDir | Out-Null
if (-not (Test-Path -LiteralPath $ModuleSource -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $ModuleSource"
}
if ($BundledMode -eq "YES") {
    if (-not (Test-Path -LiteralPath $ConfigSource -PathType Leaf)) {
        throw "softhsm.conf is not a file: $ConfigSource"
    }
    New-Item -ItemType Directory -Force -Path $PackageDir | Out-Null
    $Module = Join-Path $PackageDir (Split-Path -Leaf $ModuleSource)
    Write-Host "[SCRIPT] copying bundled PKCS #11 library $ModuleSource into disposable package $PackageDir"
    Copy-Item -LiteralPath $ModuleSource -Destination $Module
    Copy-Item -LiteralPath $ConfigSource -Destination (Join-Path $PackageDir "softhsm.conf")
    Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
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
if (-not $env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT) {
    $env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT = $BundledMode
}

& (Join-Path $PSScriptRoot "run-pkcs11-integration.ps1") $Module $OpenSSL $ScenarioDir
if ($LASTEXITCODE -ne 0) { throw "generic PKCS #11 integration test failed" }
if ($BundledMode -eq "YES") {
    if (-not (Test-Path -LiteralPath $UserConfig -PathType Leaf)) {
        throw "module did not create its canonical user configuration"
    }
    if (Test-Path -LiteralPath (Join-Path $PackageDir "tokens")) {
        throw "module unexpectedly created token storage beside itself"
    }
    if (-not $UserConfigPreexisting) {
        $SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ConfigSource).Hash
        $UserHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $UserConfig).Hash
        if ($SourceHash -ne $UserHash) { throw "canonical user config does not match adjacent template" }
        $UserTokens = Join-Path (Split-Path -Parent $UserConfig) "tokens"
        if (-not (Test-Path -LiteralPath $UserTokens -PathType Container)) {
            throw "module did not create token storage beside the canonical user config"
        }
        Write-Host "[SCRIPT] verified first-use config copy and token storage in canonical user directory: $(Split-Path -Parent $UserConfig)"
    }
    else {
        Write-Host "[SCRIPT] verified reuse of pre-existing canonical user config: $UserConfig"
    }
    Write-Host "[SCRIPT] verified no token storage was created beside the tested module"
}
