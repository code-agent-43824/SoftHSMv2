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
@($Bundle, (Join-Path $WithUser 'softhsm'), $FreshHome, $MissingHome, $DirectoryHome) |
    ForEach-Object { New-Item -ItemType Directory -Force -Path $_ | Out-Null }
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
    & $Client first-run $Module (Join-Path (Join-Path $MissingHome 'softhsm') 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'missing override did not fall back' }
    if ((Get-Content -LiteralPath (Join-Path (Join-Path $MissingHome 'softhsm') 'softhsm.conf') -Raw) -notmatch
        'directories\.tokendir = tokens') {
        throw 'default user configuration was not created'
    }

    $env:USERPROFILE = $DirectoryHome
    $env:SOFTHSM2_CONF = $Bundle
    & $Client first-run $Module (Join-Path (Join-Path $DirectoryHome 'softhsm') 'tokens')
    if ($LASTEXITCODE -ne 0) { throw 'directory override did not fall back' }
}
finally {
    if ($null -eq $PreviousProfile) { Remove-Item Env:USERPROFILE -ErrorAction SilentlyContinue }
    else { $env:USERPROFILE = $PreviousProfile }
    if ($null -eq $PreviousConfig) { Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue }
    else { $env:SOFTHSM2_CONF = $PreviousConfig }
}
Write-Host '[CONFIG] PASS: readable override isolates the store; invalid override falls back'
