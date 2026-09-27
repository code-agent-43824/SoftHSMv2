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
if ($env:PORTABLE_ARCH -eq "x86") {
    # On 32-bit MSVC, upstream compares a size_t length to an int expression;
    # make the intended non-negative comparison explicit without suppressing /WX.
    $AmethPath = Join-Path $EngineSource "gost_ameth.c"
    $Ameth = [IO.File]::ReadAllText($AmethPath)
    $OldComparison = 'if (*len < 2 * half)'
    if ([regex]::Matches($Ameth, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 length comparison"
    }
    $Ameth = $Ameth.Replace($OldComparison, 'if (*len < (size_t)(2 * half))')
    [IO.File]::WriteAllText($AmethPath, $Ameth, [Text.UTF8Encoding]::new($false))
    $PmethPath = Join-Path $EngineSource "gost_pmeth.c"
    $Pmeth = [IO.File]::ReadAllText($PmethPath)
    $OldComparison = 'if (*siglen < order)'
    if ([regex]::Matches($Pmeth, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 signature length comparison"
    }
    $Pmeth = $Pmeth.Replace($OldComparison, 'if (*siglen < (size_t)order)')
    [IO.File]::WriteAllText($PmethPath, $Pmeth, [Text.UTF8Encoding]::new($false))
    $CryptPath = Join-Path $EngineSource "gost_crypt.c"
    $Crypt = [IO.File]::ReadAllText($CryptPath)
    $OldComparison = 'if (magma_cipher_do_ctr(ctx, out, in, inl) != inl)'
    if ([regex]::Matches($Crypt, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 Magma length comparison"
    }
    $Crypt = $Crypt.Replace($OldComparison,
        "int processed = magma_cipher_do_ctr(ctx, out, in, inl);`n  if (processed < 0 || (size_t)processed != inl)")
    [IO.File]::WriteAllText($CryptPath, $Crypt, [Text.UTF8Encoding]::new($false))
    $Gost2015Path = Join-Path $EngineSource "gost_gost2015.c"
    $Gost2015 = [IO.File]::ReadAllText($Gost2015Path)
    $OldComparison = 'while (len >= bl)'
    if ([regex]::Matches($Gost2015, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 GOST block length comparison"
    }
    $Gost2015 = $Gost2015.Replace($OldComparison, 'while (len >= (size_t)bl)')
    [IO.File]::WriteAllText($Gost2015Path, $Gost2015, [Text.UTF8Encoding]::new($false))
    $KeyxPath = Join-Path $EngineSource "gost_ec_keyx.c"
    $Keyx = [IO.File]::ReadAllText($KeyxPath)
    $OldComparison = 'if (*out_len < 2 * half_len)'
    if ([regex]::Matches($Keyx, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 key exchange length comparison"
    }
    $Keyx = $Keyx.Replace($OldComparison, 'if (*out_len < (size_t)(2 * half_len))')
    [IO.File]::WriteAllText($KeyxPath, $Keyx, [Text.UTF8Encoding]::new($false))
    $DigestPath = Join-Path $EngineSource "gost_prov_digest.c"
    $Digest = [IO.File]::ReadAllText($DigestPath)
    $OldComparison = 'if (outsize < GOST_digest_size(gctx->descriptor))'
    if ([regex]::Matches($Digest, [regex]::Escape($OldComparison)).Count -ne 1) {
        throw "expected exactly one upstream x86 digest size comparison"
    }
    $Digest = $Digest.Replace($OldComparison,
        'if (outsize < (size_t)GOST_digest_size(gctx->descriptor))')
    [IO.File]::WriteAllText($DigestPath, $Digest, [Text.UTF8Encoding]::new($false))
}
if ($env:PORTABLE_ARCH -eq "arm64") {
    # The pinned provider's optimized curve multiplication fast-fails during
    # GOST genpkey on Windows ARM64. Use OpenSSL's generic EC path on that ABI.
    $SignPath = Join-Path $EngineSource "gost_ec_sign.c"
    $Sign = [IO.File]::ReadAllText($SignPath)
    $OldDispatch = "    if (group == NULL || r == NULL || ctx == NULL)`n        return 0;"
    if ([regex]::Matches($Sign, [regex]::Escape($OldDispatch)).Count -ne 1) {
        throw "expected exactly one upstream EC multiplication dispatch"
    }
    $Sign = $Sign.Replace($OldDispatch,
        "$OldDispatch`n`n#if defined(_M_ARM64)`n    return EC_POINT_mul(group, r, n, q, m, ctx);`n#else")
    $OldEnd = "    return 0;`n}`n`n/*`n *`n * Generates GOST"
    if ([regex]::Matches($Sign, [regex]::Escape($OldEnd)).Count -ne 1) {
        throw "expected exactly one upstream EC dispatch end"
    }
    $Sign = $Sign.Replace($OldEnd, "    return 0;`n#endif`n}`n`n/*`n *`n * Generates GOST")
    [IO.File]::WriteAllText($SignPath, $Sign, [Text.UTF8Encoding]::new($false))
    # Trace the native fast-fail to distinguish provider setup, RNG, and EC math.
    $KeymgmtPath = Join-Path $EngineSource "gost_prov_keymgmt.c"
    $Keymgmt = [IO.File]::ReadAllText($KeymgmtPath)
    foreach ($Patch in @(
        @{ Old = '    key_data->ec = internal_ec_paramgen(key_data->param_nid);';
           New = '    fprintf(stderr, "[GOST-ARM64] before paramgen\n");`n    key_data->ec = internal_ec_paramgen(key_data->param_nid);' },
        @{ Old = '    if (FLAGS_CONTAIN(gctx->selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)';
           New = '    fprintf(stderr, "[GOST-ARM64] after paramgen\n");`n    if (FLAGS_CONTAIN(gctx->selection, OSSL_KEYMGMT_SELECT_PRIVATE_KEY)' }
    )) {
        if ([regex]::Matches($Keymgmt, [regex]::Escape($Patch.Old)).Count -ne 1) {
            throw "expected exactly one upstream ARM64 keymgmt trace point"
        }
        $Keymgmt = $Keymgmt.Replace($Patch.Old, $Patch.New.Replace('`n', "`n"))
    }
    $AfterKeygen = "        goto end;`n`n    return key_data;"
    if ([regex]::Matches($Keymgmt, [regex]::Escape($AfterKeygen)).Count -ne 1) {
        throw "expected exactly one upstream ARM64 keygen return"
    }
    $Keymgmt = $Keymgmt.Replace($AfterKeygen,
        "        goto end;`n`n    fprintf(stderr, `"[GOST-ARM64] after public key return\n`");`n    return key_data;")
    $Keymgmt = "#include <stdio.h>`n" + $Keymgmt
    [IO.File]::WriteAllText($KeymgmtPath, $Keymgmt, [Text.UTF8Encoding]::new($false))
    $Sign = [IO.File]::ReadAllText($SignPath)
    foreach ($Patch in @(
        @{ Old = '    if (!EC_GROUP_get_order(group, order, NULL)) {';
           New = '    fprintf(stderr, "[GOST-ARM64] before group order\n");`n    if (!EC_GROUP_get_order(group, order, NULL)) {' },
        @{ Old = '        if (!BN_rand_range(d, order)) {';
           New = '        fprintf(stderr, "[GOST-ARM64] before RNG\n");`n        if (!BN_rand_range(d, order)) {' },
        @{ Old = '    if (!EC_KEY_set_private_key(ec, d)) {';
           New = '    fprintf(stderr, "[GOST-ARM64] after RNG\n");`n    if (!EC_KEY_set_private_key(ec, d)) {' },
        @{ Old = '    return (ok) ? gost_ec_compute_public(ec) : 0;';
           New = '    fprintf(stderr, "[GOST-ARM64] before public key\n");`n    return (ok) ? gost_ec_compute_public(ec) : 0;' }
    )) {
        if ([regex]::Matches($Sign, [regex]::Escape($Patch.Old)).Count -ne 1) {
            throw "expected exactly one upstream ARM64 keygen trace point"
        }
        $Sign = $Sign.Replace($Patch.Old, $Patch.New.Replace('`n', "`n"))
    }
    foreach ($Patch in @(
        @{ Old = '    if (!gost_ec_point_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {';
           New = '    fprintf(stderr, "[GOST-ARM64] before point mul\n");`n    if (!gost_ec_point_mul(group, pub_key, priv_key, NULL, NULL, ctx)) {' },
        @{ Old = '    if (!EC_KEY_set_public_key(ec, pub_key)) {';
           New = '    fprintf(stderr, "[GOST-ARM64] after point mul\n");`n    if (!EC_KEY_set_public_key(ec, pub_key)) {' },
        @{ Old = '    ok = 1;`n err:';
           New = '    fprintf(stderr, "[GOST-ARM64] after set public key\n");`n    ok = 1;`n err:' }
    )) {
        $Old = $Patch.Old.Replace('`n', "`n")
        if ([regex]::Matches($Sign, [regex]::Escape($Old)).Count -ne 1) {
            throw "expected exactly one upstream ARM64 public-key trace point"
        }
        $Sign = $Sign.Replace($Old, $Patch.New.Replace('`n', "`n"))
    }
    $Sign = "#include <stdio.h>`n" + $Sign
    [IO.File]::WriteAllText($SignPath, $Sign, [Text.UTF8Encoding]::new($false))
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

# Keep upstream's /WX for all other diagnostics; its x86-only signedness
# warnings are handled above where known, and masked for remaining vendor code.
$GostCFlags = if ($env:PORTABLE_ARCH -eq "x86") { @("-DCMAKE_C_FLAGS=/wd4018") } else { @() }
cmake -S $EngineSource -B $EngineBuild -G "NMake Makefiles" `
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POLICY_DEFAULT_CMP0091=NEW `
    -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded `
    "-DCMAKE_MODULE_LINKER_FLAGS=/EXPORT:OSSL_provider_init" `
    "-DOPENSSL_ROOT_DIR=$OpenSSLPrefix" `
    -DOPENSSL_ENGINES_DIR=bin -DGOST_BUILD_ENGINE=OFF `
    -DGOST_BUILD_STATIC_ENGINE=OFF -DGOST_BUILD_PROVIDER=ON @GostCFlags
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
$ProviderExports = & dumpbin /exports $ProviderDlls[0].FullName
if ($LASTEXITCODE -ne 0 -or -not ($ProviderExports | Select-String -Pattern '\bOSSL_provider_init\b')) {
    throw "GOST provider DLL does not export OSSL_provider_init"
}
Copy-Item -LiteralPath $ProviderDlls[0].FullName -Destination (Join-Path $StageDir "bin/gostprov.dll")
$OpenSSLConfig = [IO.File]::ReadAllText((Join-Path $OpenSSLSource "apps/openssl.cnf"))
[IO.File]::WriteAllText((Join-Path $StageDir "config/openssl.cnf"), $OpenSSLConfig,
    [Text.UTF8Encoding]::new($false))
Copy-Item (Join-Path $EngineSource "test/provider.cnf") (Join-Path $StageDir "config/openssl-gost.cnf")
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
