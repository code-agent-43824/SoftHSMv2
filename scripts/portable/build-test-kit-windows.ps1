$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:OPENSSL_VERSION) { throw "OPENSSL_VERSION is required" }
if (-not $env:OPENSSL_SHA256) { throw "OPENSSL_SHA256 is required" }
foreach ($Name in @("GOST_ENGINE_COMMIT", "GOST_ENGINE_SHA256", "GOST_LIBPROV_COMMIT", "GOST_LIBPROV_SHA256")) {
    if (-not [Environment]::GetEnvironmentVariable($Name)) { throw "$Name is required" }
}
if (-not $env:PORTABLE_PRODUCT_DIR) { throw "PORTABLE_PRODUCT_DIR is required" }

$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$ProductDir = (Resolve-Path -LiteralPath $env:PORTABLE_PRODUCT_DIR).Path
$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { Join-Path $RootDir ".portable-work" }
$Platform = "windows-$($env:PORTABLE_ARCH)"
$WorkDir = Join-Path $WorkRoot "testkit-$Platform"
$OpenSSLArchive = Join-Path $WorkDir "openssl.tar.gz"
$OpenSSLSource = Join-Path $WorkDir "openssl-$($env:OPENSSL_VERSION)"
$OpenSSLPrefix = Join-Path $WorkDir "openssl-install"
$EngineSource = Join-Path $WorkDir "gost-engine"
$EngineBuild = Join-Path $WorkDir "gost-build"
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
foreach ($Input in @(
    @{ Name = "engine"; Repo = "gost-engine/engine"; Commit = $env:GOST_ENGINE_COMMIT;
       Hash = $env:GOST_ENGINE_SHA256; Destination = $EngineSource },
    @{ Name = "libprov"; Repo = "provider-corner/libprov"; Commit = $env:GOST_LIBPROV_COMMIT;
       Hash = $env:GOST_LIBPROV_SHA256; Destination = (Join-Path $EngineSource "libprov") }
)) {
    $Archive = Join-Path $WorkDir "gost-$($Input.Name).tar.gz"
    Invoke-WebRequest -Uri "https://codeload.github.com/$($Input.Repo)/tar.gz/$($Input.Commit)" -OutFile $Archive
    $Hash = (Get-FileHash -Algorithm SHA256 $Archive).Hash.ToLowerInvariant()
    if ($Hash -ne $Input.Hash.ToLowerInvariant()) { throw "$($Input.Name) checksum mismatch" }
    New-Item -ItemType Directory -Force -Path $Input.Destination | Out-Null
    tar -xzf $Archive -C $Input.Destination --strip-components=1
    if ($LASTEXITCODE -ne 0) { throw "$($Input.Name) unpack failed" }
}

Push-Location $OpenSSLSource
try {
    perl Configure $OpenSSLTarget shared no-tests no-asm /MT `
        "--prefix=$OpenSSLPrefix" "--libdir=lib"
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL configure failed" }
    nmake build_sw
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL build failed" }
    nmake install_sw
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL install failed" }
}
finally { Pop-Location }

cmake -S $EngineSource -B $EngineBuild -G "NMake Makefiles" `
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    "-DOPENSSL_ROOT_DIR=$OpenSSLPrefix" `
    -DOPENSSL_ENGINES_DIR=bin -DGOST_BUILD_ENGINE=OFF `
    -DGOST_BUILD_STATIC_ENGINE=OFF -DGOST_BUILD_PROVIDER=ON
if ($LASTEXITCODE -ne 0) { throw "GOST provider configure failed" }
cmake --build $EngineBuild --target gost_prov
if ($LASTEXITCODE -ne 0) { throw "GOST provider build failed" }

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
$CryptoDlls = @(Get-ChildItem -LiteralPath (Join-Path $OpenSSLPrefix "bin") -File |
    Where-Object { $_.Name -match '^lib(crypto|ssl).*\.dll$' })
if ($CryptoDlls.Count -ne 2) { throw "expected bundled libcrypto and libssl DLLs" }
foreach ($Dll in $CryptoDlls) {
    Copy-Item -LiteralPath $Dll.FullName -Destination (Join-Path $StageDir "bin")
}
$ProviderDlls = @(Get-ChildItem -LiteralPath $EngineBuild -Filter gostprov.dll -File -Recurse)
if ($ProviderDlls.Count -ne 1) { throw "expected exactly one GOST provider DLL" }
Copy-Item -LiteralPath $ProviderDlls[0].FullName -Destination (Join-Path $StageDir "bin/gostprov.dll")
$OpenSSLConfig = [IO.File]::ReadAllText((Join-Path $OpenSSLSource "apps/openssl.cnf"))
[IO.File]::WriteAllText((Join-Path $StageDir "config/openssl.cnf"), $OpenSSLConfig,
    [Text.UTF8Encoding]::new($false))
$GOSTConfig = $OpenSSLConfig.Replace("[provider_sect]", "[provider_sect]`ngostprov = gost_sect")
$GOSTConfig = $GOSTConfig.Replace("[default_sect]", "[default_sect]`nactivate = 1")
$GOSTConfig += "`n[gost_sect]`nactivate = 1`n"
[IO.File]::WriteAllText((Join-Path $StageDir "config/openssl-gost.cnf"), $GOSTConfig,
    [Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $RootDir "tests/portable/run-test-kit.ps1") (Join-Path $StageDir "run-test.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/verify-gost-openssl.ps1") (Join-Path $StageDir "scripts/verify-gost-openssl.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/run-test-kit.cmd") (Join-Path $StageDir "run-test.cmd")
Copy-Item (Join-Path $RootDir "tests/portable/run-fresh-integration.ps1") (Join-Path $StageDir "scripts/run-fresh-integration.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/run-pkcs11-integration.ps1") (Join-Path $StageDir "scripts/run-pkcs11-integration.ps1")
Copy-Item (Join-Path $RootDir "tests/portable/portable-token-e2e.cpp") (Join-Path $StageDir "src/portable-token-e2e.cpp")
Copy-Item (Join-Path $RootDir "src/lib/pkcs11/*.h") (Join-Path $StageDir "src/pkcs11")
Copy-Item (Join-Path $RootDir "packaging/portable/TEST-KIT-README.txt") (Join-Path $StageDir "README.txt")
Copy-Item (Join-Path $RootDir "packaging/portable/testkit.conf") (Join-Path $StageDir "testkit.conf")
Copy-Item (Join-Path $RootDir "LICENSE") (Join-Path $StageDir "LICENSE-TestClient.txt")
Copy-Item (Join-Path $OpenSSLSource "LICENSE.txt") (Join-Path $StageDir "LICENSE-OpenSSL.txt")
Copy-Item (Join-Path $EngineSource "LICENSE") (Join-Path $StageDir "LICENSE-GOST-Provider.txt")
Copy-Item (Join-Path $EngineSource "libprov/LICENSE") (Join-Path $StageDir "LICENSE-libprov.txt")
$RequiredProductFiles = @("softhsm2.dll", "LICENSE-SoftHSM.txt", "LICENSE-Botan.txt")
foreach ($Name in $RequiredProductFiles) {
    $Source = Join-Path $ProductDir $Name
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "required product file is missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $StageDir $Name)
}
foreach ($ToolName in @("softhsm2-util.exe", "softhsm2-export.exe")) {
    $Source = Join-Path $ProductDir $ToolName
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "required product file is missing: $Source"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $StageDir "bin/$ToolName")
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
$env:OPENSSL_CONF = Join-Path $StageDir "config/openssl.cnf"
$env:OPENSSL_MODULES = Join-Path $StageDir "bin"
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

$CheckedBinaries = @($OpenSSLExe, $Client, (Join-Path $StageDir "softhsm2.dll"),
    (Join-Path $StageDir "bin/softhsm2-util.exe"), (Join-Path $StageDir "bin/softhsm2-export.exe")) +
    @($CryptoDlls | ForEach-Object { Join-Path $StageDir "bin/$($_.Name)" }) +
    @((Join-Path $StageDir "bin/gostprov.dll"))
foreach ($Binary in $CheckedBinaries) {
    $MachineHeader = & dumpbin /headers $Binary |
        Select-String -Pattern $ExpectedMachinePattern
    if (-not $MachineHeader) {
        throw "$Binary does not have the expected $($env:PORTABLE_ARCH) PE machine type"
    }
    $AllowedCrypto = ($Binary -eq $OpenSSLExe -or $Binary -like "*libcrypto*.dll" -or
        $Binary -like "*libssl*.dll" -or $Binary -like "*gostprov.dll")
    $Pattern = if ($AllowedCrypto) { 'vcruntime|msvcp|ucrtbased' }
               else { 'libcrypto|libssl|vcruntime|msvcp|ucrtbased' }
    $Unexpected = & dumpbin /dependents $Binary |
        Select-String -Pattern $Pattern -CaseSensitive:$false
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
