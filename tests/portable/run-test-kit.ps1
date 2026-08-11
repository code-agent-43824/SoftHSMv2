$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -gt 1) {
    throw "usage: run-test.ps1 [path-to-alternative-pkcs11-library]"
}

$KitDir = $PSScriptRoot
$Settings = @{}
Get-Content (Join-Path $KitDir "testkit.env") | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') { $Settings[$Matches[1]] = $Matches[2] }
}
$ConfigPath = Join-Path $KitDir "testkit.conf"
$UserHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { "$($env:HOMEDRIVE)$($env:HOMEPATH)" }
if (-not $UserHome) { throw "USERPROFILE or HOMEDRIVE/HOMEPATH is required" }
$UserConfig = Join-Path (Join-Path $UserHome "softhsm") "softhsm.conf"
$TestConfig = @{}
$AllowedConfig = @(
    "INITIALIZE_TOKEN", "EXCLUDED_FUNCTIONS", "USER_PIN", "SO_PIN",
    "SLOT_ID", "TOKEN_LABEL", "KEY_LABEL", "OBJECT_ID_HEX"
)
Get-Content -LiteralPath $ConfigPath | ForEach-Object {
    $Line = $_
    if (-not $Line.Trim() -or $Line.TrimStart().StartsWith("#")) { return }
    $Separator = $Line.IndexOf("=")
    if ($Separator -lt 1) { throw "invalid testkit.conf line: $Line" }
    $Name = $Line.Substring(0, $Separator).Trim()
    if ($Name -notin $AllowedConfig) { throw "unknown testkit.conf setting: $Name" }
    $TestConfig[$Name] = $Line.Substring($Separator + 1)
}

function Get-EffectiveSetting([string]$EnvironmentName, [string]$ConfigName, [string]$DefaultValue = "") {
    $EnvironmentValue = [Environment]::GetEnvironmentVariable($EnvironmentName, "Process")
    if ($EnvironmentValue) { return $EnvironmentValue }
    if ($TestConfig.ContainsKey($ConfigName)) { return [string]$TestConfig[$ConfigName] }
    return $DefaultValue
}

function Set-OptionalEnvironment([string]$Name, [string]$Value) {
    if ($Value) { Set-Item -Path "Env:$Name" -Value $Value }
    else { Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue }
}

$InitializeSetting = (Get-EffectiveSetting "P11_TEST_INITIALIZE_TOKEN" "INITIALIZE_TOKEN" "AUTO").ToUpperInvariant()
switch ($InitializeSetting) {
    "AUTO" {
        $TokenDirectory = Join-Path (Split-Path -Parent $UserConfig) "tokens"
        $StoredTokenCount = 0
        if (Test-Path -LiteralPath $TokenDirectory -PathType Container) {
            $StoredTokenCount = @(Get-ChildItem -LiteralPath $TokenDirectory -Directory -Force -ErrorAction Stop).Count
        }
        $Initialize = if ($args.Count -eq 0 -and $StoredTokenCount -eq 0) {
            "YES"
        }
        else { "NO" }
    }
    "YES" { $Initialize = "YES" }
    "NO" { $Initialize = "NO" }
    default { throw "INITIALIZE_TOKEN must be AUTO, YES, or NO" }
}

$Excluded = [System.Collections.Generic.List[string]]::new()
function Add-ExcludedFunction([string]$Name) {
    if (-not $Name) { return }
    if ($Name -notmatch '^C_[A-Za-z0-9_]+$') { throw "invalid excluded PKCS #11 function: $Name" }
    if ($Name -notin $Excluded) { $Excluded.Add($Name) }
}
(Get-EffectiveSetting "P11_TEST_EXCLUDE_FUNCTIONS" "EXCLUDED_FUNCTIONS") -split '[,;\s]+' |
    ForEach-Object { Add-ExcludedFunction $_ }
if ($Initialize -eq "NO") {
    @("C_InitToken", "C_InitPIN", "C_SetPIN") | ForEach-Object { Add-ExcludedFunction $_ }
}

$UserPin = Get-EffectiveSetting "P11_TEST_USER_PIN" "USER_PIN"
$SoPin = Get-EffectiveSetting "P11_TEST_SO_PIN" "SO_PIN"
if (-not $UserPin) { throw "USER_PIN must be set in testkit.conf" }
if ($Initialize -eq "YES" -and -not $SoPin) { throw "SO_PIN must be set when INITIALIZE_TOKEN=YES" }
$env:P11_TEST_INITIALIZE_TOKEN = $Initialize
$env:P11_TEST_USER_PIN = $UserPin
Set-OptionalEnvironment "P11_TEST_SO_PIN" $SoPin
Set-OptionalEnvironment "P11_TEST_EXCLUDE_FUNCTIONS" ($Excluded -join ",")
Set-OptionalEnvironment "P11_TEST_SLOT_ID" (Get-EffectiveSetting "P11_TEST_SLOT_ID" "SLOT_ID")
Set-OptionalEnvironment "P11_TEST_TOKEN_LABEL" (Get-EffectiveSetting "P11_TEST_TOKEN_LABEL" "TOKEN_LABEL")
Set-OptionalEnvironment "P11_TEST_KEY_LABEL" (Get-EffectiveSetting "P11_TEST_KEY_LABEL" "KEY_LABEL")
Set-OptionalEnvironment "P11_TEST_OBJECT_ID_HEX" (Get-EffectiveSetting "P11_TEST_OBJECT_ID_HEX" "OBJECT_ID_HEX")

$Client = (Resolve-Path (Join-Path $KitDir "bin/portable-token-e2e.exe")).Path
$OpenSSL = (Resolve-Path (Join-Path $KitDir "bin/openssl.exe")).Path
$Module = if ($args.Count -eq 1) {
    (Resolve-Path -LiteralPath $args[0]).Path
}
else {
    (Resolve-Path -LiteralPath (Join-Path $KitDir $Settings.MODULE_NAME)).Path
}
$BundledMode = if ($args.Count -eq 0) { "YES" } else { "NO" }
if (-not (Test-Path -LiteralPath $Module -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $Module"
}
$env:P11_TEST_CLIENT = $Client
$env:OPENSSL_CONF = (Resolve-Path (Join-Path $KitDir "config/openssl.cnf")).Path

Write-Host "[TEST-KIT] platform=$($Settings.PLATFORM)"
Write-Host "[TEST-KIT] settings=$ConfigPath"
Write-Host "[TEST-KIT] PKCS #11 library=$Module"
Write-Host "[TEST-KIT] canonical user config=$UserConfig"
Write-Host "[TEST-KIT] initialize token=$Initialize"
Write-Host "[TEST-KIT] excluded functions=$(if ($Excluded.Count) { $Excluded -join ',' } else { '<none>' })"
Write-Host "[TEST-KIT] precompiled client=$Client"
Write-Host "[TEST-KIT] bundled OpenSSL=$OpenSSL"
Write-Host "[TEST-KIT] all test evidence remains under=$(Join-Path $KitDir 'test-output')"

& (Join-Path $KitDir "scripts/run-fresh-integration.ps1") $Module $OpenSSL $BundledMode
if ($LASTEXITCODE -ne 0) { throw "downloadable test kit failed" }
