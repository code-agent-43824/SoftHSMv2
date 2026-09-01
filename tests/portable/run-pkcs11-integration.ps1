$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 3) {
    throw "usage: run-pkcs11-integration.ps1 <pkcs11-module> <openssl> <scenario-directory>"
}

function Write-Step([string]$Message) {
    Write-Host "[SCRIPT] $Message"
}

function Invoke-Native([string]$Executable, [string[]]$Arguments, [string]$Description) {
    Write-Step $Description
    $Rendered = @($Executable) + ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    })
    Write-Host ("[COMMAND] " + ($Rendered -join " "))
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Description failed with exit code $LASTEXITCODE" }
}

$Module = (Resolve-Path $args[0]).Path
$OpenSSL = (Resolve-Path $args[1]).Path
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$ScenarioDir = [IO.Path]::GetFullPath($args[2])
New-Item -ItemType Directory -Force -Path $ScenarioDir | Out-Null
$BuildDir = Join-Path $ScenarioDir "client-build"
$Tester = if ($env:P11_TEST_CLIENT) { (Resolve-Path $env:P11_TEST_CLIENT).Path } else {
    New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
    Join-Path $BuildDir "portable-token-e2e.exe"
}

$Initialize = if ($env:P11_TEST_INITIALIZE_TOKEN) { $env:P11_TEST_INITIALIZE_TOKEN } else { "NO" }
$Slot = if ($env:P11_TEST_SLOT_ID) { $env:P11_TEST_SLOT_ID } else { "<automatic; exactly one matching token is required>" }
$TokenLabel = if ($env:P11_TEST_TOKEN_LABEL) { $env:P11_TEST_TOKEN_LABEL } else { "portable-ci-token" }
$KeyLabel = if ($env:P11_TEST_KEY_LABEL) { $env:P11_TEST_KEY_LABEL } else { "portable-ci-rsa" }
$ObjectId = if ($env:P11_TEST_OBJECT_ID_HEX) { $env:P11_TEST_OBJECT_ID_HEX } else { "504f525441424c45" }
$RequireGostImportExport = if ($env:P11_TEST_REQUIRE_GOST_IMPORT_EXPORT) { $env:P11_TEST_REQUIRE_GOST_IMPORT_EXPORT } else { "YES" }
$RequireGostSymmetric = if ($env:P11_TEST_REQUIRE_GOST_SYMMETRIC) { $env:P11_TEST_REQUIRE_GOST_SYMMETRIC } else { "YES" }
$RequireRsaImportExport = if ($env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT) { $env:P11_TEST_REQUIRE_RSA_IMPORT_EXPORT } else { "YES" }
$ExcludedFunctions = if ($env:P11_TEST_EXCLUDE_FUNCTIONS) { $env:P11_TEST_EXCLUDE_FUNCTIONS } else { "<none>" }
$SoPinLength = if ($env:P11_TEST_SO_PIN) { $env:P11_TEST_SO_PIN.Length } else { 0 }
$UserPinLength = if ($env:P11_TEST_USER_PIN) { $env:P11_TEST_USER_PIN.Length } else { 0 }
Write-Step "module=$Module"
Write-Step "OpenSSL CLI=$OpenSSL"
Write-Step "scenario directory=$ScenarioDir"
Write-Step "P11_TEST_INITIALIZE_TOKEN=$Initialize"
Write-Step "P11_TEST_SLOT_ID=$Slot"
Write-Step "P11_TEST_TOKEN_LABEL=$TokenLabel"
Write-Step "P11_TEST_KEY_LABEL=$KeyLabel"
Write-Step "P11_TEST_OBJECT_ID_HEX=$ObjectId"
Write-Step "P11_TEST_REQUIRE_GOST_IMPORT_EXPORT=$RequireGostImportExport"
Write-Step "P11_TEST_REQUIRE_GOST_SYMMETRIC=$RequireGostSymmetric"
Write-Step "P11_TEST_REQUIRE_RSA_IMPORT_EXPORT=$RequireRsaImportExport"
Write-Step "P11_TEST_EXCLUDE_FUNCTIONS=$ExcludedFunctions"
Write-Step "P11_TEST_SO_PIN=<redacted,length=$SoPinLength>"
Write-Step "P11_TEST_USER_PIN=<redacted,length=$UserPinLength>"

if ($env:P11_TEST_CLIENT) {
    Write-Step "using bundled precompiled PKCS #11 client=$Tester"
} else {
    $CompileArgs = @(
        "/nologo", "/std:c++17", "/O2", "/EHsc", "/W4",
        "/I$(Join-Path $RootDir 'src/lib/pkcs11')",
        (Join-Path $RootDir "tests/portable/portable-token-e2e.cpp"),
        "/Fe:$Tester"
    )
    Invoke-Native "cl" $CompileArgs "compile the dependency-light direct PKCS #11 client"
}

Push-Location $ScenarioDir
try {
    Invoke-Native $Tester @("prepare", $Module, $ScenarioDir) `
        "PKCS #11 prepare phase: select token, optionally initialize it, run isolated GOST checks, then generate RSA-2048 and create CSR"
} finally { Pop-Location }

Invoke-Native $OpenSSL @("req", "-in", (Join-Path $ScenarioDir "request.pem"), "-verify", "-noout") `
    "independently verify the token-signed PKCS#10 request"
Invoke-Native $OpenSSL @(
    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "1",
    "-subj", "/CN=Portable PKCS11 Test CA",
    "-keyout", (Join-Path $ScenarioDir "ca.key"), "-out", (Join-Path $ScenarioDir "ca.pem")
) "create an external one-day RSA test CA"
Invoke-Native $OpenSSL @(
    "x509", "-req", "-in", (Join-Path $ScenarioDir "request.pem"),
    "-CA", (Join-Path $ScenarioDir "ca.pem"), "-CAkey", (Join-Path $ScenarioDir "ca.key"),
    "-CAcreateserial", "-days", "1", "-sha256", "-out", (Join-Path $ScenarioDir "issued.pem")
) "issue a leaf certificate for the token-generated public key"
Invoke-Native $OpenSSL @("verify", "-CAfile", (Join-Path $ScenarioDir "ca.pem"), (Join-Path $ScenarioDir "issued.pem")) `
    "verify the externally issued leaf certificate"
Invoke-Native $OpenSSL @("x509", "-in", (Join-Path $ScenarioDir "issued.pem"), "-outform", "DER", "-out", (Join-Path $ScenarioDir "issued.der")) `
    "convert leaf certificate to DER"
Invoke-Native $OpenSSL @("x509", "-in", (Join-Path $ScenarioDir "ca.pem"), "-outform", "DER", "-out", (Join-Path $ScenarioDir "ca.der")) `
    "convert CA certificate to DER"

$Payload = Join-Path $ScenarioDir "payload.bin"
Write-Step "write detached-CMS test payload to $Payload"
[IO.File]::WriteAllText($Payload, "portable PKCS11 detached CMS payload`n", [Text.UTF8Encoding]::new($false))
$Cms = Join-Path $ScenarioDir "signature.p7s"
Push-Location $ScenarioDir
try {
    Invoke-Native $Tester @(
        "finish", $Module, $ScenarioDir,
        (Join-Path $ScenarioDir "issued.der"), (Join-Path $ScenarioDir "ca.der"), $Payload, $Cms
    ) "PKCS #11 finish phase: reopen key, import X.509 certificate, digest and sign CMS attributes"
} finally { Pop-Location }

$Verified = Join-Path $ScenarioDir "verified.bin"
Invoke-Native $OpenSSL @(
    "cms", "-verify", "-binary", "-inform", "DER", "-in", $Cms, "-content", $Payload,
    "-CAfile", (Join-Path $ScenarioDir "ca.pem"), "-purpose", "any", "-out", $Verified
) "independently verify detached CMS"
Write-Step "compare SHA-256 of original and OpenSSL-recovered content"
$PayloadHash = (Get-FileHash -Algorithm SHA256 $Payload).Hash
$VerifiedHash = (Get-FileHash -Algorithm SHA256 $Verified).Hash
Write-Host "[RESULT] payload SHA256=$PayloadHash"
Write-Host "[RESULT] verified SHA256=$VerifiedHash"
if ($PayloadHash -ne $VerifiedHash) { throw "verified CMS content differs from the payload" }

Push-Location $ScenarioDir
try {
    Invoke-Native $Tester @("ready", $Module) `
        "reload the module and verify the token is ready for other utilities without initialization or PIN setup"
} finally { Pop-Location }

Write-Step "PASS: standard direct PKCS #11 and external OpenSSL integration test completed"
Write-Step "evidence retained in $ScenarioDir"
