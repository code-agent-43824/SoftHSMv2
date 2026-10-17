$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
# Windows PowerShell redraws Invoke-WebRequest's progress bar for every chunk
# it receives, which slows the downloads below several times over.
$ProgressPreference = "SilentlyContinue"

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:OPENSSL_VERSION) { throw "OPENSSL_VERSION is required" }
if (-not $env:OPENSSL_SHA256) { throw "OPENSSL_SHA256 is required" }
if (-not $env:BOTAN_VERSION) { throw "BOTAN_VERSION is required" }
if (-not $env:BOTAN_SHA256) { throw "BOTAN_SHA256 is required" }

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { Join-Path $RootDir ".portable-work" }
$WorkDir = Join-Path $WorkRoot "windows-$($env:PORTABLE_ARCH)"
$OpenSSLArchive = Join-Path $WorkDir "openssl.tar.gz"
$OpenSSLSource = Join-Path $WorkDir "openssl-$($env:OPENSSL_VERSION)"
$OpenSSLPrefix = Join-Path $WorkDir "openssl-install"
$BotanArchive = Join-Path $WorkDir "botan.tar.xz"
$BotanSource = Join-Path $WorkDir "Botan-$($env:BOTAN_VERSION)"
$BotanBuild = Join-Path $WorkDir "botan-build"
$BuildDir = Join-Path $WorkDir "softhsm-build"
$StageDir = Join-Path $WorkDir "stage"
$OutputDir = Join-Path $RootDir "dist"
$ArchiveName = "softhsm-portable-windows-$($env:PORTABLE_ARCH).zip"

switch ($env:PORTABLE_ARCH.ToLowerInvariant()) {
    "x86" {
        $OpenSSLTarget = "VC-WIN32"
        $BotanCpu = "x86_32"
        $CMakeArch = "Win32"
        $ExpectedMachinePattern = '14C machine \(x86\)'
    }
    "x64" {
        $OpenSSLTarget = "VC-WIN64A"
        $BotanCpu = "x86_64"
        $CMakeArch = "x64"
        $ExpectedMachinePattern = '8664 machine \(x64\)'
    }
    "arm64" {
        $OpenSSLTarget = "VC-WIN64-ARM"
        $BotanCpu = "arm64"
        $CMakeArch = "ARM64"
        $ExpectedMachinePattern = 'AA64 machine \(ARM64\)'
    }
    default { throw "unsupported PORTABLE_ARCH: $($env:PORTABLE_ARCH)" }
}

New-Item -ItemType Directory -Force -Path $WorkDir, $OutputDir | Out-Null
$OpenSSLUrl = "https://github.com/openssl/openssl/releases/download/openssl-$($env:OPENSSL_VERSION)/openssl-$($env:OPENSSL_VERSION).tar.gz"
Invoke-WebRequest -Uri $OpenSSLUrl -OutFile $OpenSSLArchive
$ActualHash = (Get-FileHash -Algorithm SHA256 $OpenSSLArchive).Hash.ToLowerInvariant()
if ($ActualHash -ne $env:OPENSSL_SHA256.ToLowerInvariant()) {
    throw "OpenSSL checksum mismatch: expected $($env:OPENSSL_SHA256), got $ActualHash"
}
# The log's timestamps on these lines time the download and the unpacking.
Write-Host "[BUILD] OpenSSL source downloaded and verified"
tar -xzf $OpenSSLArchive -C $WorkDir
Write-Host "[BUILD] OpenSSL source unpacked"

# nmake runs OpenSSL's makefile one command at a time; jom, Qt's nmake clone
# pinned in jom.lock, runs the same makefile in parallel. Every library object
# is compiled with /Zi into the one ossl_static.pdb, so concurrent cl
# processes need /FS to share it.
$JomEntry = @(Get-Content -LiteralPath (Join-Path $RootDir "scripts/portable/jom.lock") |
    Where-Object { $_ -match '^[0-9a-f]{64}\s' })
if ($JomEntry.Count -ne 1) { throw "jom.lock must pin exactly one jom archive" }
$JomSha256, $JomUrl = $JomEntry[0] -split '\s+'
$JomArchive = Join-Path $WorkDir "jom.zip"
$JomDir = Join-Path $WorkDir "jom"
Invoke-WebRequest -Uri $JomUrl -OutFile $JomArchive
$ActualJomHash = (Get-FileHash -Algorithm SHA256 $JomArchive).Hash.ToLowerInvariant()
if ($ActualJomHash -ne $JomSha256) {
    throw "jom checksum mismatch: expected $JomSha256, got $ActualJomHash"
}
Expand-Archive -LiteralPath $JomArchive -DestinationPath $JomDir -Force
$Jom = Join-Path $JomDir "jom.exe"

# Botan does not depend on OpenSSL, so it builds alongside it: its jom runs
# as a separate process while OpenSSL's single-threaded stretches - Configure,
# generated files, the final links - leave cores idle.
$BotanUrl = "https://botan.randombit.net/releases/Botan-$($env:BOTAN_VERSION).tar.xz"
Invoke-WebRequest -Uri $BotanUrl -OutFile $BotanArchive
$ActualBotanHash = (Get-FileHash -Algorithm SHA256 $BotanArchive).Hash.ToLowerInvariant()
if ($ActualBotanHash -ne $env:BOTAN_SHA256.ToLowerInvariant()) {
    throw "Botan checksum mismatch: expected $($env:BOTAN_SHA256), got $ActualBotanHash"
}
tar -xJf $BotanArchive -C $WorkDir

python (Join-Path $BotanSource "configure.py") --cc=msvc --os=windows --cpu=$BotanCpu `
    --msvc-runtime=MT --disable-shared --minimized-build --enable-modules=streebog,gost_3410,emsa_raw `
    --without-documentation "--with-build-dir=$BotanBuild"
if ($LASTEXITCODE -ne 0) { throw "Botan configure failed" }
# Botan's makefile is in nmake syntax too, and jom runs it in parallel; its
# objects carry no debug information, so no PDB is shared and /FS is not
# needed. It starts before CL is changed for OpenSSL below.
$BotanOut = Join-Path $WorkDir "botan-build.out.log"
$BotanErr = Join-Path $WorkDir "botan-build.err.log"
$BotanProcess = Start-Process -FilePath $Jom -NoNewWindow -PassThru `
    -WorkingDirectory (Get-Location).Path `
    -RedirectStandardOutput $BotanOut -RedirectStandardError $BotanErr `
    -ArgumentList @("/J", $env:NUMBER_OF_PROCESSORS, "/f", "`"$(Join-Path $BotanBuild 'Makefile')`"", "libs")
# Windows PowerShell reports a started process's exit code only if its
# handle was taken while it ran.
$null = $BotanProcess.Handle
$BotanStarted = [DateTime]::UtcNow
Write-Host "[BUILD] Botan build started in the background"

Push-Location $OpenSSLSource
$PreviousCl = $env:CL
$OpenSSLBuilt = $false
try {
    perl Configure $OpenSSLTarget no-shared no-module no-tests no-asm "--prefix=$OpenSSLPrefix" "--libdir=lib"
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL configure failed" }
    $env:CL = ("$PreviousCl /FS").Trim()
    & $Jom /J $env:NUMBER_OF_PROCESSORS
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
    nmake install_sw install_ssldirs
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL install failed" }
    $OpenSSLBuilt = $true
}
finally {
    if ($null -eq $PreviousCl) { Remove-Item Env:CL -ErrorAction SilentlyContinue }
    else { $env:CL = $PreviousCl }
    Pop-Location
    if (-not $OpenSSLBuilt -and -not $BotanProcess.HasExited) { Stop-Process -Id $BotanProcess.Id -Force }
}

$BotanProcess.WaitForExit()
Get-Content -LiteralPath $BotanOut, $BotanErr | Write-Host
Write-Host ("[BUILD] Botan build ran from {0:HH:mm:ss} to {1:HH:mm:ss} UTC, exit code {2}" -f
    $BotanStarted, $BotanProcess.ExitTime.ToUniversalTime(), $BotanProcess.ExitCode)
if ($BotanProcess.ExitCode -ne 0) { throw "Botan build failed" }
$BotanLibrary = Get-ChildItem -Path $BotanBuild -Filter "botan*.lib" | Select-Object -First 1
if (-not $BotanLibrary) { throw "Botan static library was not produced" }
Write-Host "[BUILD] OpenSSL and Botan built"

cmake -S $RootDir -B $BuildDir -A $CMakeArch `
    -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    -DENABLE_PORTABLE=ON `
    -DENABLE_STATIC=OFF `
    -DENABLE_P11_KIT=OFF `
    -DBUILD_TESTS=OFF `
    -DWITH_OBJECTSTORE_BACKEND_DB=OFF `
    -DWITH_CRYPTO_BACKEND=openssl `
    -DENABLE_GOST_3411_2012=ON `
    -DENABLE_GOST_3410_2012_256=ON `
    -DENABLE_GOST_3410_2012_512=ON `
    "-DBOTAN_GOST_INCLUDE_DIR=$(Join-Path $BotanBuild 'build/include')" `
    "-DBOTAN_GOST_LIBRARY=$($BotanLibrary.FullName)" `
    "-DOPENSSL_ROOT_DIR=$OpenSSLPrefix"
if ($LASTEXITCODE -ne 0) { throw "SoftHSM configure failed" }
cmake --build $BuildDir --config Release --target softhsm2 softhsm2-util softhsm2-export --parallel
if ($LASTEXITCODE -ne 0) { throw "SoftHSM build failed" }

$ModulePath = Get-ChildItem -Path $BuildDir -Filter softhsm2.dll -Recurse | Select-Object -First 1
if (-not $ModulePath) { throw "softhsm2.dll was not produced" }
$UtilPath = Get-ChildItem -Path $BuildDir -Filter softhsm2-util.exe -Recurse | Select-Object -First 1
if (-not $UtilPath) { throw "softhsm2-util.exe was not produced" }
$ExportPath = Get-ChildItem -Path $BuildDir -Filter softhsm2-export.exe -Recurse | Select-Object -First 1
if (-not $ExportPath) { throw "softhsm2-export.exe was not produced" }
New-Item -ItemType Directory -Force -Path $StageDir | Out-Null
Copy-Item $ModulePath.FullName (Join-Path $StageDir "softhsm2.dll")
Copy-Item $UtilPath.FullName (Join-Path $StageDir "softhsm2-util.exe")
Copy-Item $ExportPath.FullName (Join-Path $StageDir "softhsm2-export.exe")
Copy-Item (Join-Path $RootDir "packaging/portable/README.txt") (Join-Path $StageDir "README.txt")
Copy-Item (Join-Path $RootDir "LICENSE") (Join-Path $StageDir "LICENSE-SoftHSM.txt")
Copy-Item (Join-Path $OpenSSLSource "LICENSE.txt") (Join-Path $StageDir "LICENSE-OpenSSL.txt")
Copy-Item (Join-Path $BotanSource "license.txt") (Join-Path $StageDir "LICENSE-Botan.txt")

foreach ($BinaryName in @("softhsm2.dll", "softhsm2-util.exe", "softhsm2-export.exe")) {
    $Binary = Join-Path $StageDir $BinaryName
    $MachineHeader = & dumpbin /headers $Binary | Select-String -Pattern $ExpectedMachinePattern
    if (-not $MachineHeader) {
        throw "$BinaryName does not have the expected $($env:PORTABLE_ARCH) PE machine type"
    }
    $UnexpectedDlls = & dumpbin /dependents $Binary |
        Select-String -Pattern 'libcrypto|libssl|botan|vcruntime|msvcp|ucrtbased' -CaseSensitive:$false
    if ($UnexpectedDlls) {
        $UnexpectedDlls | Write-Error
        throw "$BinaryName has an unexpected runtime dependency"
    }
}
& (Join-Path $StageDir "softhsm2-util.exe") --version
if ($LASTEXITCODE -ne 0) { throw "softhsm2-util.exe smoke test failed" }
& (Join-Path $StageDir "softhsm2-export.exe") --version
if ($LASTEXITCODE -ne 0) { throw "softhsm2-export.exe smoke test failed" }

$ArchivePath = Join-Path $OutputDir $ArchiveName
Remove-Item $ArchivePath -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $StageDir "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Get-FileHash -Algorithm SHA256 $ArchivePath
