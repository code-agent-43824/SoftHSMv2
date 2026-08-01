$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:OPENSSL_VERSION) { throw "OPENSSL_VERSION is required" }
if (-not $env:OPENSSL_SHA256) { throw "OPENSSL_SHA256 is required" }

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { Join-Path $RootDir ".portable-work" }
$WorkDir = Join-Path $WorkRoot "windows-$($env:PORTABLE_ARCH)"
$OpenSSLArchive = Join-Path $WorkDir "openssl.tar.gz"
$OpenSSLSource = Join-Path $WorkDir "openssl-$($env:OPENSSL_VERSION)"
$OpenSSLPrefix = Join-Path $WorkDir "openssl-install"
$BuildDir = Join-Path $WorkDir "softhsm-build"
$StageDir = Join-Path $WorkDir "stage"
$OutputDir = Join-Path $RootDir "dist"
$ArchiveName = "softhsm-portable-windows-$($env:PORTABLE_ARCH).zip"

New-Item -ItemType Directory -Force -Path $WorkDir, $OutputDir | Out-Null
$OpenSSLUrl = "https://github.com/openssl/openssl/releases/download/openssl-$($env:OPENSSL_VERSION)/openssl-$($env:OPENSSL_VERSION).tar.gz"
Invoke-WebRequest -Uri $OpenSSLUrl -OutFile $OpenSSLArchive
$ActualHash = (Get-FileHash -Algorithm SHA256 $OpenSSLArchive).Hash.ToLowerInvariant()
if ($ActualHash -ne $env:OPENSSL_SHA256.ToLowerInvariant()) {
    throw "OpenSSL checksum mismatch: expected $($env:OPENSSL_SHA256), got $ActualHash"
}
tar -xzf $OpenSSLArchive -C $WorkDir

Push-Location $OpenSSLSource
try {
    $OpenSSLTarget = if ($env:PORTABLE_ARCH -eq "arm64") { "VC-WIN64-ARM" } else { "VC-WIN64A" }
    perl Configure $OpenSSLTarget no-shared no-module no-tests no-asm "--prefix=$OpenSSLPrefix" "--libdir=lib"
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL configure failed" }
    nmake
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
    nmake install_sw install_ssldirs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL install failed" }
}
finally {
    Pop-Location
}

$CMakeArch = if ($env:PORTABLE_ARCH -eq "arm64") { "ARM64" } else { "x64" }
cmake -S $RootDir -B $BuildDir -A $CMakeArch `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    -DENABLE_PORTABLE=ON `
    -DENABLE_STATIC=OFF `
    -DENABLE_P11_KIT=OFF `
    -DBUILD_TESTS=OFF `
    -DWITH_OBJECTSTORE_BACKEND_DB=OFF `
    -DWITH_CRYPTO_BACKEND=openssl `
    "-DOPENSSL_ROOT_DIR=$OpenSSLPrefix"
if ($LASTEXITCODE -ne 0) { throw "SoftHSM configure failed" }
cmake --build $BuildDir --config Release --target softhsm2 --parallel
if ($LASTEXITCODE -ne 0) { throw "SoftHSM build failed" }

$ModulePath = Get-ChildItem -Path $BuildDir -Filter softhsm2.dll -Recurse | Select-Object -First 1
if (-not $ModulePath) { throw "softhsm2.dll was not produced" }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
Copy-Item $ModulePath.FullName (Join-Path $StageDir "softhsm2.dll")
Copy-Item (Join-Path $RootDir "packaging/portable/softhsm.conf") (Join-Path $StageDir "softhsm.conf")
Copy-Item (Join-Path $RootDir "packaging/portable/README.txt") (Join-Path $StageDir "README.txt")
Copy-Item (Join-Path $RootDir "LICENSE") (Join-Path $StageDir "LICENSE-SoftHSM.txt")
Copy-Item (Join-Path $OpenSSLSource "LICENSE.txt") (Join-Path $StageDir "LICENSE-OpenSSL.txt")

$UnexpectedDlls = & dumpbin /dependents (Join-Path $StageDir "softhsm2.dll") |
    Select-String -Pattern 'libcrypto|libssl|vcruntime|msvcp|ucrtbased' -CaseSensitive:$false
if ($UnexpectedDlls) {
    $UnexpectedDlls | Write-Error
    throw "portable module has an unexpected runtime dependency"
}

$ArchivePath = Join-Path $OutputDir $ArchiveName
Remove-Item $ArchivePath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 $ArchivePath
