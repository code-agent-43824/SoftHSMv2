$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 3) {
    throw "usage: run-fresh-integration.ps1 <package.zip> <module-name> <openssl>"
}

$Archive = (Resolve-Path $args[0]).Path
$ModuleName = $args[1]
$OpenSSL = (Resolve-Path $args[2]).Path
$WorkRoot = Join-Path $env:RUNNER_TEMP "softhsm-fresh-test"
$PackageDir = Join-Path $WorkRoot "package"
$ScenarioDir = Join-Path $WorkRoot "scenario"

Write-Host "[SCRIPT] extracting downloaded package $Archive into $PackageDir"
New-Item -ItemType Directory -Force -Path $PackageDir, $ScenarioDir | Out-Null
Expand-Archive -Path $Archive -DestinationPath $PackageDir -Force
$Module = (Resolve-Path (Join-Path $PackageDir $ModuleName)).Path
if (-not (Test-Path (Join-Path $PackageDir "softhsm.conf"))) { throw "softhsm.conf is missing" }

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
Write-Host "[SCRIPT] verified portable-only behavior: tokens directory exists beside downloaded module"
