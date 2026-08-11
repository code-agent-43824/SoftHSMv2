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

switch ($env:PORTABLE_ARCH.ToLowerInvariant()) {
    "x86" {
        $OpenSSLTarget = "VC-WIN32"
        $ExpectedMachinePattern = '14C machine \(x86\)'
    }
    "x64" {
        $OpenSSLTarget = "VC-WIN64A"
        $ExpectedMachinePattern = '8664 machine \(x64\)'
    }
    "arm64" {
        $OpenSSLTarget = "VC-WIN64-ARM"
        $ExpectedMachinePattern = 'AA64 machine \(ARM64\)'
    }
    default { throw "unsupported PORTABLE_ARCH: $($env:PORTABLE_ARCH)" }
}

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
    perl Configure $OpenSSLTarget no-shared no-module no-tests no-asm /MT `
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
$RequiredProductFiles = @("softhsm2.dll", "LICENSE-SoftHSM.txt", "LICENSE-Botan.txt")
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
& (Join-Path $RootDir "scripts/portable/bundle-opensc-windows.ps1") `
    -StageDir $StageDir -ExpectedMachinePattern $ExpectedMachinePattern
$OpenSCVersion = (Get-Content -LiteralPath (Join-Path $StageDir "OPENSC-VERSION.txt") -First 1).Trim()
@(
    "PLATFORM=$Platform",
    "MODULE_NAME=softhsm2.dll",
    "OPENSSL_VERSION=$($env:OPENSSL_VERSION)",
    "OPENSC_VERSION=$OpenSCVersion"
) | Set-Content -Encoding ascii (Join-Path $StageDir "testkit.env")

$OpenSSLExe = Join-Path $StageDir "bin/openssl.exe"
$Pkcs11Tool = Join-Path $StageDir "bin/pkcs11-tool.exe"
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
    ((& $OpenSSLExe version -a 2>&1) -join "`n"),
    "",
    "Bundled OpenSC pkcs11-tool version:",
    $OpenSCVersion
)
$Environment | Set-Content -Encoding utf8 (Join-Path $StageDir "ENVIRONMENT.txt")

foreach ($Binary in @($OpenSSLExe, $Client, (Join-Path $StageDir "softhsm2.dll"))) {
    $MachineHeader = & dumpbin /headers $Binary |
        Select-String -Pattern $ExpectedMachinePattern
    if (-not $MachineHeader) {
        throw "$Binary does not have the expected $($env:PORTABLE_ARCH) PE machine type"
    }
    $Unexpected = & dumpbin /dependents $Binary |
        Select-String -Pattern 'libcrypto|libssl|vcruntime|msvcp|ucrtbased' -CaseSensitive:$false
    if ($Unexpected) {
        $Unexpected | Write-Error
        throw "$Binary has an unexpected non-system runtime dependency"
    }
}

foreach ($Binary in @($Pkcs11Tool) + @(Get-ChildItem -LiteralPath (Join-Path $StageDir "bin") -Filter *.dll -File)) {
    $Path = if ($Binary -is [IO.FileInfo]) { $Binary.FullName } else { [string]$Binary }
    $MachineHeader = & dumpbin /headers $Path |
        Select-String -Pattern $ExpectedMachinePattern
    if (-not $MachineHeader) {
        throw "$Path does not have the expected $($env:PORTABLE_ARCH) PE machine type"
    }
}

$ArchivePath = Join-Path $OutputDir "softhsm-testkit-$Platform.zip"
Remove-Item $ArchivePath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 $ArchivePath
