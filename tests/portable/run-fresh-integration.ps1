$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -lt 3 -or $args.Count -gt 4) {
    throw "usage: run-fresh-integration.ps1 <package.zip-or-directory> <module-name> <openssl> [scenario-directory]"
}

$Product = (Resolve-Path -LiteralPath $args[0]).Path
$ModuleName = $args[1]
$OpenSSL = (Resolve-Path $args[2]).Path
$TempRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$WorkRoot = Join-Path $TempRoot ("softhsm-fresh-test-" + [guid]::NewGuid())
$PackageDir = Join-Path $WorkRoot "package"
$ScenarioDir = if ($args.Count -eq 4) { [IO.Path]::GetFullPath($args[3]) } else { Join-Path $WorkRoot "scenario" }

New-Item -ItemType Directory -Force -Path $PackageDir, $ScenarioDir | Out-Null
if (Test-Path -LiteralPath $Product -PathType Container) {
    Write-Host "[SCRIPT] copying product directory $Product into $PackageDir"
    Get-ChildItem -LiteralPath $Product -Force |
        Copy-Item -Destination $PackageDir -Recurse -Force
}
else {
    if ([IO.Path]::GetExtension($Product) -ne ".zip") {
        throw "product source must be a ZIP archive or directory: $Product"
    }
    Write-Host "[SCRIPT] extracting downloaded package $Product into $PackageDir"
    Expand-Archive -LiteralPath $Product -DestinationPath $PackageDir -Force
}
$ModulePath = Join-Path $PackageDir $ModuleName
if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
    throw "$ModuleName is missing; a product directory must contain the extracted product files"
}
$Module = (Resolve-Path -LiteralPath $ModulePath).Path
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
