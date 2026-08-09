$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 3) {
    throw "usage: run-fresh-integration.ps1 <pkcs11-library> <openssl> <softhsm.conf>"
}

$ModuleSource = (Resolve-Path -LiteralPath $args[0]).Path
$OpenSSL = (Resolve-Path -LiteralPath $args[1]).Path
$ConfigSource = (Resolve-Path -LiteralPath $args[2]).Path
$TempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$WorkRoot = Join-Path $TempRoot ("softhsm-fresh-test-" + [guid]::NewGuid())
$PackageDir = Join-Path $WorkRoot "package"
$ScenarioDir = Join-Path $WorkRoot "scenario"

New-Item -ItemType Directory -Force -Path $PackageDir, $ScenarioDir | Out-Null
if (-not (Test-Path -LiteralPath $ModuleSource -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $ModuleSource"
}
if (-not (Test-Path -LiteralPath $ConfigSource -PathType Leaf)) {
    throw "softhsm.conf is not a file: $ConfigSource"
}
$Module = Join-Path $PackageDir (Split-Path -Leaf $ModuleSource)
Write-Host "[SCRIPT] copying PKCS #11 library $ModuleSource into disposable package $PackageDir"
Copy-Item -LiteralPath $ModuleSource -Destination $Module
Copy-Item -LiteralPath $ConfigSource -Destination (Join-Path $PackageDir "softhsm.conf")

Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
$env:P11_TEST_INITIALIZE_TOKEN = "YES"
$env:P11_TEST_SO_PIN = "12345678"
$env:P11_TEST_USER_PIN = "12345678"
$env:P11_TEST_TOKEN_LABEL = "portable-ci-token"
$env:P11_TEST_KEY_LABEL = "portable-ci-rsa"
$env:P11_TEST_OBJECT_ID_HEX = "504f525441424c45"

& (Join-Path $PSScriptRoot "run-pkcs11-integration.ps1") $Module $OpenSSL $ScenarioDir
if ($LASTEXITCODE -ne 0) { throw "generic PKCS #11 integration test failed" }
if (-not (Test-Path -PathType Container (Join-Path $PackageDir "tokens"))) {
    throw "module did not create its tokens directory beside itself"
}
Write-Host "[SCRIPT] verified portable-only behavior: tokens directory exists beside tested module"
