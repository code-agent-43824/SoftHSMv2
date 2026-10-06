param(
    [Parameter(Mandatory = $true)][string]$Module,
    [Parameter(Mandatory = $true)][string]$Client,
    [Parameter(Mandatory = $true)][string]$Util,
    [Parameter(Mandatory = $true)][string]$EvidenceDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$CaseDir = Join-Path $EvidenceDir ("config-override-" + [Guid]::NewGuid().ToString('N'))
$Bundle = Join-Path $CaseDir 'bundle'
$WithUser = Join-Path $CaseDir 'with-user'
$FreshHome = Join-Path $CaseDir 'fresh-home'
$MissingHome = Join-Path $CaseDir 'missing-home'
$DirectoryHome = Join-Path $CaseDir 'directory-home'
$ModuleName = Split-Path -Leaf $Module
$NoAdjacent = Join-Path $CaseDir 'no-adjacent'
@($Bundle, (Join-Path $WithUser 'softhsm'), $FreshHome, $MissingHome, $DirectoryHome, $NoAdjacent) |
    ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
Copy-Item -LiteralPath $Module -Destination (Join-Path $NoAdjacent $ModuleName)
$PlainModule = Join-Path $NoAdjacent $ModuleName
$Config = Join-Path $Bundle 'softhsm.conf'
@('directories.tokendir = tokens', 'objectstore.backend = file', 'log.level = ERROR') |
    Set-Content -LiteralPath $Config -Encoding Ascii
$UserConfig = Join-Path (Join-Path $WithUser 'softhsm') 'softhsm.conf'
'directories.tokendir = user-tokens' | Set-Content -LiteralPath $UserConfig -Encoding Ascii

$PreviousProfile = $env:USERPROFILE
$PreviousConfig = $env:SOFTHSM2_CONF
try {
    $env:USERPROFILE = $WithUser
    $env:SOFTHSM2_CONF = $Config
    & $Client first-run $Module (Join-Path $Bundle 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'readable SOFTHSM2_CONF was not used' }
    if (Test-Path -LiteralPath (Join-Path (Join-Path $WithUser 'softhsm') 'user-tokens')) {
        throw 'per-user token directory was touched despite the override'
    }
    if ((Get-Content -LiteralPath $UserConfig -Raw).Trim() -ne
        'directories.tokendir = user-tokens') {
        throw 'per-user configuration was modified despite the override'
    }

    $env:USERPROFILE = $FreshHome
    & $Client probe $Module
    if ($LASTEXITCODE -ne 0) { throw 'override failed with an empty user profile' }
    & $Util --show-slots | Out-File -LiteralPath (Join-Path $CaseDir 'utility-slots.txt')
    if ($LASTEXITCODE -ne 0) { throw 'softhsm2-util did not use the override' }
    if (Test-Path -LiteralPath (Join-Path $FreshHome 'softhsm')) {
        throw 'per-user configuration was created despite the override'
    }

    $env:USERPROFILE = $MissingHome
    $env:SOFTHSM2_CONF = Join-Path $CaseDir 'missing.conf'
    & $Client first-run $PlainModule (Join-Path (Join-Path $MissingHome 'softhsm') 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'missing override did not fall back' }
    if ((Get-Content -LiteralPath (Join-Path (Join-Path $MissingHome 'softhsm') 'softhsm.conf') -Raw) -notmatch
        'directories\.tokendir = tokens') {
        throw 'default user configuration was not created'
    }

    $env:USERPROFILE = $DirectoryHome
    $env:SOFTHSM2_CONF = $Bundle
    & $Client first-run $PlainModule (Join-Path (Join-Path $DirectoryHome 'softhsm') 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'directory override did not fall back' }

    $Adjacent = Join-Path $CaseDir 'adjacent'
    $AdjacentUtilDir = Join-Path $Adjacent 'tools/bin'
    $AdjacentHome = Join-Path $CaseDir 'adjacent-home'
    $Elsewhere = Join-Path $CaseDir 'elsewhere'
    @($AdjacentUtilDir, $AdjacentHome, $Elsewhere) |
        ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
    Copy-Item -LiteralPath $Module -Destination (Join-Path $Adjacent $ModuleName)
    Copy-Item -LiteralPath $Util -Destination (Join-Path $AdjacentUtilDir 'softhsm2-util.exe')
    @('directories.tokendir = tokens', 'objectstore.backend = file',
      'FAKE_RUTOKEN_ECP = true', 'log.level = ERROR') |
        Set-Content -LiteralPath (Join-Path $Adjacent 'softhsm.conf') -Encoding Ascii
    'directories.tokendir = alias-tokens' |
        Set-Content -LiteralPath (Join-Path $Adjacent 'softhsm2.conf') -Encoding Ascii
    'invalid config in process working directory' |
        Set-Content -LiteralPath (Join-Path $Elsewhere 'softhsm.conf') -Encoding Ascii
    $env:USERPROFILE = $AdjacentHome
    Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
    Push-Location $Elsewhere
    try {
        $SelectedModule = & (Join-Path $AdjacentUtilDir 'softhsm2-util.exe') --show-config default-pkcs11-lib
        if ($LASTEXITCODE -ne 0 -or [IO.Path]::GetFullPath($SelectedModule.Trim()) -ne
            [IO.Path]::GetFullPath((Join-Path $Adjacent $ModuleName))) {
            throw 'utility did not find the module two directories above tools/bin'
        }
        $Slots = & (Join-Path $AdjacentUtilDir 'softhsm2-util.exe') --show-slots
        if ($LASTEXITCODE -ne 0 -or ($Slots -join "`n") -notmatch 'Slot 14') {
            throw 'utility did not use the adjacent Rutoken configuration'
        }
        & (Join-Path $AdjacentUtilDir 'softhsm2-util.exe') --init-token --slot 0 `
            --label adjacent-test --so-pin 12345678 --pin 12345678 `
            --so-pin-retries 4 --user-pin-retries 5 `
            --min-pin-len 6 --max-pin-len 12
        if ($LASTEXITCODE -ne 0) { throw 'utility could not initialize a token beside the module' }
        & $Client probe (Join-Path $Adjacent $ModuleName)
        if ($LASTEXITCODE -ne 0) { throw 'module did not use its adjacent configuration' }
        $env:SOFTHSM2_CONF = Join-Path $CaseDir 'missing.conf'
        & $Client probe (Join-Path $Adjacent $ModuleName)
        if ($LASTEXITCODE -ne 0) { throw 'missing override did not fall back to adjacent config' }
        Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
    }
    finally { Pop-Location }
    if (-not (Test-Path -LiteralPath (Join-Path $Adjacent 'tokens')) -or
        @((Get-ChildItem -LiteralPath (Join-Path $Adjacent 'tokens') -Filter 'token.object' -Recurse -ErrorAction SilentlyContinue)).Count -eq 0 -or
        (Test-Path -LiteralPath (Join-Path $Adjacent 'alias-tokens')) -or
        (Test-Path -LiteralPath (Join-Path $AdjacentHome 'softhsm'))) {
        throw 'adjacent lookup touched the wrong token store'
    }

    $OverrideModule = Join-Path $CaseDir 'override-module'
    $OverrideStore = Join-Path $CaseDir 'override-store'
    $OverrideHome = Join-Path $CaseDir 'override-home'
    @($OverrideModule, $OverrideStore, $OverrideHome) |
        ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
    Copy-Item -LiteralPath $Module -Destination (Join-Path $OverrideModule $ModuleName)
    'directories.tokendir = tokens' | Set-Content -LiteralPath (Join-Path $OverrideModule 'softhsm.conf') -Encoding Ascii
    'directories.tokendir = tokens' | Set-Content -LiteralPath (Join-Path $OverrideStore 'softhsm.conf') -Encoding Ascii
    $env:USERPROFILE = $OverrideHome
    $env:SOFTHSM2_CONF = Join-Path $OverrideStore 'softhsm.conf'
    & $Client first-run (Join-Path $OverrideModule $ModuleName) (Join-Path $OverrideStore 'tokens')
    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath (Join-Path $OverrideModule 'tokens')) -or
        (Test-Path -LiteralPath (Join-Path $OverrideHome 'softhsm'))) {
        throw 'explicit override did not outrank adjacent configuration'
    }

    $AliasModule = Join-Path $CaseDir 'alias-module'
    $AliasHome = Join-Path $CaseDir 'alias-home'
    @($AliasModule, $AliasHome) |
        ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
    Copy-Item -LiteralPath $Module -Destination (Join-Path $AliasModule $ModuleName)
    'directories.tokendir = tokens' | Set-Content -LiteralPath (Join-Path $AliasModule 'softhsm2.conf') -Encoding Ascii
    $env:USERPROFILE = $AliasHome
    Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
    & $Client first-run (Join-Path $AliasModule $ModuleName) (Join-Path $AliasModule 'tokens')
    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath (Join-Path $AliasHome 'softhsm'))) {
        throw 'legacy adjacent configuration alias failed'
    }

    $PlainModule = Join-Path $CaseDir 'plain-module'
    $PlainHome = Join-Path $CaseDir 'plain-home'
    $PlainUtilDir = Join-Path $PlainModule 'tools/bin'
    @($PlainUtilDir, $PlainHome) |
        ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
    Copy-Item -LiteralPath $Module -Destination (Join-Path $PlainModule $ModuleName)
    Copy-Item -LiteralPath $Util -Destination (Join-Path $PlainUtilDir 'softhsm2-util.exe')
    $env:USERPROFILE = $PlainHome
    & $Client first-run (Join-Path $PlainModule $ModuleName) (Join-Path (Join-Path $PlainHome 'softhsm') 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'no-adjacent per-user fallback failed' }
    & (Join-Path $PlainUtilDir 'softhsm2-util.exe') --show-slots | Out-Null
    if ($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath (Join-Path $PlainModule 'tokens'))) {
        throw 'utility did not preserve per-user fallback'
    }
}
finally {
    if ($null -eq $PreviousProfile) { Remove-Item Env:USERPROFILE -ErrorAction SilentlyContinue }
    else { $env:USERPROFILE = $PreviousProfile }
    if ($null -eq $PreviousConfig) { Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue }
    else { $env:SOFTHSM2_CONF = $PreviousConfig }
}
Write-Host '[CONFIG] PASS: override > adjacent module config > per-user; utility and foreign CWD agree'
