param(
    [Parameter(Mandatory = $true)] [string] $Module,
    [Parameter(Mandatory = $true)] [string] $Cli,
    [Parameter(Mandatory = $true)] [string] $Spy,
    [Parameter(Mandatory = $true)] [string] $Util,
    [Parameter(Mandatory = $true)] [string] $OutputDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$CaseDir = Join-Path $OutputDir "rutoken-cli-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path (Join-Path $CaseDir 'tokens') | Out-Null
@(
    'directories.tokendir = tokens'
    'objectstore.backend = file'
    'log.level = ERROR'
    'FAKE_RUTOKEN_ECP = true'
) | Set-Content -LiteralPath (Join-Path $CaseDir 'softhsm2.conf') -Encoding ascii
$env:SOFTHSM2_CONF = Join-Path $CaseDir 'softhsm2.conf'

# Fixed PINs belong only to this disposable, isolated test token.
$env:TEST_RUTOKEN_USER_PIN = '12345678'
$env:TEST_RUTOKEN_LOCAL_PIN = 'local444'
$env:TEST_RUTOKEN_LOCAL_PIN_NEXT = 'local555'
function Invoke-Cli([string]$Program, [string[]]$Arguments, [string]$LogName) {
    $OldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $Lines = @(& $Program @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $Code = $LASTEXITCODE
    }
    finally { $ErrorActionPreference = $OldPreference }
    $Lines | Set-Content -LiteralPath (Join-Path $CaseDir $LogName) -Encoding utf8
    if ($Code -ne 0) { throw "$Program failed with exit code $Code; see $LogName" }
    return $Lines
}

Invoke-Cli $Util @('--module', $Module, '--init-token', '--slot', '0',
    '--label', 'Rutoken ECP', '--so-pin', $env:TEST_RUTOKEN_USER_PIN,
    '--pin', $env:TEST_RUTOKEN_USER_PIN) 'init.log' | Out-Null
$Info = Invoke-Cli $Cli @('--module', $Module, '--rutoken-info', '--rutoken-name',
    '--rutoken-json') 'info.log' | Where-Object { $_ -match '^\{' } | Select-Object -Last 1
$Info = $Info | ConvertFrom-Json
if ($Info.info.token_type_name -ne 'RUTOKEN_ECP' -or
    $Info.info.user_retries_left -ne 10 -or $Info.name.label -ne 'Rutoken ECP') {
    throw 'fork pkcs11-tool did not report the expected Rutoken profile'
}
Invoke-Cli $Cli @('--module', $Module, '--rutoken-set-name', 'Fork Rutoken CLI',
    '--login', '--pin', $env:TEST_RUTOKEN_USER_PIN) 'set-name.log' | Out-Null
Invoke-Cli $Cli @('--module', $Module, '--rutoken-set-local-pin', '4',
    '--rutoken-auth-pin', 'env:TEST_RUTOKEN_USER_PIN', '--new-pin',
    'env:TEST_RUTOKEN_LOCAL_PIN') 'set-local.log' | Out-Null
Invoke-Cli $Cli @('--module', $Module, '--rutoken-set-local-pin', '4',
    '--rutoken-auth-pin', 'env:TEST_RUTOKEN_LOCAL_PIN', '--new-pin',
    'env:TEST_RUTOKEN_LOCAL_PIN_NEXT') 'change-local.log' | Out-Null

$env:PKCS11SPY = $Module
$env:PKCS11SPY_OUTPUT = Join-Path $CaseDir 'pkcs11-spy.log'
$SpyInfo = Invoke-Cli $Cli @('--module', $Spy, '--rutoken-info', '--rutoken-name',
    '--rutoken-json') 'spy-info.log' | Where-Object { $_ -match '^\{' } | Select-Object -Last 1
$SpyInfo = $SpyInfo | ConvertFrom-Json
if ($SpyInfo.name.label -ne 'Fork Rutoken CLI' -or
    $SpyInfo.info.token_type_name -ne 'RUTOKEN_ECP') {
    throw 'fork pkcs11-spy changed the Rutoken CLI result'
}
$SpyLog = Get-Content -LiteralPath $env:PKCS11SPY_OUTPUT -Raw
foreach ($Function in @('C_EX_GetFunctionListExtended', 'C_EX_GetTokenInfoExtended',
    'C_EX_GetTokenName')) {
    if (-not $SpyLog.Contains($Function)) { throw "spy did not log $Function" }
}
Write-Host '[RUTOKEN-OPENSC] PASS: fork CLI info/name/local PIN and spy on isolated fake token'
