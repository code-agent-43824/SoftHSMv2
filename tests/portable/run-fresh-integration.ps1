$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 3) {
    throw "usage: run-fresh-integration.ps1 <package.zip> <module-name> <openssl>"
}

$Archive = (Resolve-Path $args[0]).Path
$ModuleName = $args[1]
$OpenSSL = (Resolve-Path $args[2]).Path
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkRoot = Join-Path $env:RUNNER_TEMP "softhsm-fresh-test"
$PackageDir = Join-Path $WorkRoot "package"
$ScenarioDir = Join-Path $WorkRoot "scenario"
$Tester = Join-Path $WorkRoot "portable-token-e2e.exe"

New-Item -ItemType Directory -Force -Path $PackageDir, $ScenarioDir | Out-Null
Expand-Archive -Path $Archive -DestinationPath $PackageDir -Force
$Module = (Resolve-Path (Join-Path $PackageDir $ModuleName)).Path
if (-not (Test-Path (Join-Path $PackageDir "softhsm.conf"))) { throw "softhsm.conf is missing" }

cl /nologo /std:c++17 /O2 /EHsc /W4 `
    "/I$(Join-Path $RootDir 'src/lib/pkcs11')" `
    (Join-Path $RootDir "tests/portable/portable-token-e2e.cpp") `
    "/Fe:$Tester"
if ($LASTEXITCODE -ne 0) { throw "portable test client compilation failed" }

Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
Push-Location $env:RUNNER_TEMP
try {
    & $Tester prepare $Module $ScenarioDir 12345678 12345678
    if ($LASTEXITCODE -ne 0) { throw "PKCS #11 prepare phase failed" }
}
finally { Pop-Location }
if (-not (Test-Path -PathType Container (Join-Path $PackageDir "tokens"))) {
    throw "module did not create its tokens directory beside itself"
}

& $OpenSSL req -in (Join-Path $ScenarioDir "request.pem") -verify -noout
if ($LASTEXITCODE -ne 0) { throw "CSR verification failed" }
& $OpenSSL req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 `
    -subj "/CN=SoftHSM Portable Test CA" `
    -keyout (Join-Path $ScenarioDir "ca.key") -out (Join-Path $ScenarioDir "ca.pem")
if ($LASTEXITCODE -ne 0) { throw "CA generation failed" }
& $OpenSSL x509 -req -in (Join-Path $ScenarioDir "request.pem") `
    -CA (Join-Path $ScenarioDir "ca.pem") -CAkey (Join-Path $ScenarioDir "ca.key") -CAcreateserial `
    -days 1 -sha256 -out (Join-Path $ScenarioDir "issued.pem")
if ($LASTEXITCODE -ne 0) { throw "certificate issuance failed" }
& $OpenSSL verify -CAfile (Join-Path $ScenarioDir "ca.pem") (Join-Path $ScenarioDir "issued.pem")
if ($LASTEXITCODE -ne 0) { throw "certificate verification failed" }
& $OpenSSL x509 -in (Join-Path $ScenarioDir "issued.pem") -outform DER -out (Join-Path $ScenarioDir "issued.der")
if ($LASTEXITCODE -ne 0) { throw "leaf DER conversion failed" }
& $OpenSSL x509 -in (Join-Path $ScenarioDir "ca.pem") -outform DER -out (Join-Path $ScenarioDir "ca.der")
if ($LASTEXITCODE -ne 0) { throw "CA DER conversion failed" }

$Payload = Join-Path $ScenarioDir "payload.bin"
[IO.File]::WriteAllText($Payload, "portable PKCS11 detached CMS payload`n", [Text.UTF8Encoding]::new($false))
$Cms = Join-Path $ScenarioDir "signature.p7s"
Push-Location $env:RUNNER_TEMP
try {
    & $Tester finish $Module $ScenarioDir 12345678 `
        (Join-Path $ScenarioDir "issued.der") (Join-Path $ScenarioDir "ca.der") $Payload $Cms
    if ($LASTEXITCODE -ne 0) { throw "PKCS #11 finish phase failed" }
}
finally { Pop-Location }

$Verified = Join-Path $ScenarioDir "verified.bin"
& $OpenSSL cms -verify -binary -inform DER -in $Cms -content $Payload `
    -CAfile (Join-Path $ScenarioDir "ca.pem") -purpose any -out $Verified
if ($LASTEXITCODE -ne 0) { throw "external CMS verification failed" }
if ((Get-FileHash -Algorithm SHA256 $Payload).Hash -ne (Get-FileHash -Algorithm SHA256 $Verified).Hash) {
    throw "verified CMS content differs from the payload"
}

Write-Host "Fresh-runner direct PKCS #11 and OpenSSL integration test passed"
