$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:OPENSSL_VERSION) { throw "OPENSSL_VERSION is required" }
if (-not $env:OPENSSL_SHA256) { throw "OPENSSL_SHA256 is required" }
if (-not $env:PORTABLE_PRODUCT_DIR) { throw "PORTABLE_PRODUCT_DIR is required" }

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$ProductDir = (Resolve-Path -LiteralPath $env:PORTABLE_PRODUCT_DIR).Path
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { Join-Path $RootDir ".portable-work" }
$Platform = "windows-$($env:PORTABLE_ARCH)"
$WorkDir = Join-Path $WorkRoot "testkit-$Platform"
$OpenSSLArchive = Join-Path $WorkDir "openssl.tar.gz"
$OpenSSLSource = Join-Path $WorkDir "openssl-$($env:OPENSSL_VERSION)"
$OpenSSLPrefix = Join-Path $WorkDir "openssl-install"
$StageDir = Join-Path $WorkDir "stage"
$OutputDir = Join-Path $RootDir "dist"

New-Item -ItemType Directory -Force -Path $WorkDir, $StageDir, $OutputDir,
    (Join-Path $StageDir "bin"), (Join-Path $StageDir "config"),
    (Join-Path $StageDir "scripts"), (Join-Path $StageDir "src"),
    (Join-Path $StageDir "src/pkcs11") | Out-Null
$Url = "https://github.com/openssl/openssl/releases/download/openssl-$($env:OPENSSL_VERSION)/openssl-$($env:OPENSSL_VERSION).tar.gz"
Invoke-WebRequest -Uri $Url -OutFile $OpenSSLArchive
$ActualHash = (Get-FileHash -Algorithm SHA256 $OpenSSLArchive).Hash.ToLowerInvariant()
if ($ActualHash -ne $env:OPENSSL_SHA256.ToLowerInvariant()) {
    throw "OpenSSL checksum mismatch: expected $($env:OPENSSL_SHA256), got $ActualHash"
}
tar -xzf $OpenSSLArchive -C $WorkDir

Push-Location $OpenSSLSource
try {
    $Target = if ($env:PORTABLE_ARCH -eq "arm64") { "VC-WIN64-ARM" } else { "VC-WIN64A" }
    perl Configure $Target no-shared no-module no-tests no-asm /MT `
        "--prefix=$OpenSSLPrefix" "--libdir=lib"
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL configure failed" }
    nmake build_sw
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
    nmake install_sw
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL install failed" }
}
finally { Pop-Location }

$Client = Join-Path $StageDir "bin/portable-token-e2e.exe"
$CompileArgs = @(
    "/nologo", "/std:c++17", "/O2", "/EHsc", "/W4", "/MT",
    "/I$(Join-Path $RootDir 'src/lib/pkcs11')",
    (Join-Path $RootDir "tests/portable/portable-token-e2e.cpp"),
    "/Fe:$Client"
)
& cl @CompileArgs
if ($LASTEXITCODE -ne 0) { throw "test client compile failed" }

Copy-Item (Join-Path $OpenSSLPrefix "bin/openssl.exe") (Join-Path $StageDir "bin/openssl.exe")
Copy-Item (Join-Path $OpenSSLSource "apps/openssl.cnf") (Join-Path $StageDir "config/openssl.cnf")
Copy-Item (Join-Path $RootDir "tests/portable/run-test-kit.ps1") (Join-Path $StageDir "run-test.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/run-test-kit.cmd") (Join-Path $StageDir "run-test.cmd")
Copy-Item (Join-Path $RootDir "tests/portable/run-fresh-integration.ps1") (Join-Path $StageDir "scripts/run-fresh-integration.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/run-pkcs11-integration.ps1") (Join-Path $StageDir "scripts/run-pkcs11-integration.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/portable-token-e2e.cpp") (Join-Path $StageDir "src/portable-token-e2e.cpp")
Copy-Item (Join-Path $RootDir "src/lib/pkcs11/*.h") (Join-Path $StageDir "src/pkcs11")
Copy-Item (Join-Path $RootDir "packaging/portable/TEST-KIT-README.txt") (Join-Path $StageDir "README.txt")
Copy-Item (Join-Path $RootDir "packaging/portable/testkit.conf") (Join-Path $StageDir "testkit.conf")
Copy-Item (Join-Path $RootDir "LICENSE") (Join-Path $StageDir "LICENSE-TestClient.txt")
Copy-Item (Join-Path $OpenSSLSource "LICENSE.txt") (Join-Path $StageDir "LICENSE-OpenSSL.txt")
$RequiredProductFiles = @("softhsm2.dll", "softhsm.conf", "LICENSE-SoftHSM.txt", "LICENSE-Botan.txt")
foreach ($Name in $RequiredProductFiles) {
    $Source = Join-Path $ProductDir $Name
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "required product file is missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $StageDir $Name)
}
$ProductReadme = Join-Path $ProductDir "README.txt"
if (Test-Path -LiteralPath $ProductReadme -PathType Leaf) {
    Copy-Item -LiteralPath $ProductReadme -Destination (Join-Path $StageDir "PRODUCT-README.txt")
}
@(
    "PLATFORM=$Platform",
    "MODULE_NAME=softhsm2.dll",
    "OPENSSL_VERSION=$($env:OPENSSL_VERSION)"
) | Set-Content -Encoding ascii (Join-Path $StageDir "testkit.env")

$OpenSSLExe = Join-Path $StageDir "bin/openssl.exe"
$Environment = @(
    "Platform: $Platform",
    "Built on fresh GitHub verification runner",
    "OS: $([Environment]::OSVersion.VersionString)",
    "Architecture: $([Runtime.InteropServices.RuntimeInformation]::OSArchitecture)",
    "",
    "C++ compiler:",
    ((& cmd.exe /d /c "cl 2>&1") -join "`n"),
    "",
    "Bundled OpenSSL:",
    ((& $OpenSSLExe version -a 2>&1) -join "`n")
)
$Environment | Set-Content -Encoding utf8 (Join-Path $StageDir "ENVIRONMENT.txt")

foreach ($Binary in @($OpenSSLExe, $Client)) {
    $Unexpected = & dumpbin /dependents $Binary |
        Select-String -Pattern 'libcrypto|libssl|vcruntime|msvcp|ucrtbased' -CaseSensitive:$false
    if ($Unexpected) {
        $Unexpected | Write-Error
        throw "$Binary has an unexpected non-system runtime dependency"
    }
}

$ArchivePath = Join-Path $OutputDir "softhsm-testkit-$Platform.zip"
Remove-Item $ArchivePath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 $ArchivePath
