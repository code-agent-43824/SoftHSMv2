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
        $Initialize = if ($StoredTokenCount -eq 0) {
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
$Pkcs11Tool = (Resolve-Path (Join-Path $KitDir "bin/pkcs11-tool.exe")).Path
$SoftHSMUtil = (Resolve-Path (Join-Path $KitDir "bin/softhsm2-util.exe")).Path
$SoftHSMExport = (Resolve-Path (Join-Path $KitDir "bin/softhsm2-export.exe")).Path
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
Write-Host "[TEST-KIT] bundled OpenSC pkcs11-tool=$Pkcs11Tool"
Write-Host "[TEST-KIT] bundled SoftHSM utilities=$SoftHSMUtil, $SoftHSMExport"
Write-Host "[TEST-KIT] all test evidence remains under=$(Join-Path $KitDir 'test-output')"

& (Join-Path $KitDir "scripts/run-fresh-integration.ps1") $Module $OpenSSL $BundledMode
if ($LASTEXITCODE -ne 0) { throw "downloadable test kit failed" }

$OutputDir = Join-Path $KitDir "test-output"
if ($BundledMode -eq "YES") {
    $EffectiveTokenLabel = if ($env:P11_TEST_TOKEN_LABEL) { $env:P11_TEST_TOKEN_LABEL } else { "portable-ci-token" }
    $EffectiveKeyLabel = if ($env:P11_TEST_KEY_LABEL) { $env:P11_TEST_KEY_LABEL } else { "portable-ci-rsa" }
    $EffectiveObjectId = if ($env:P11_TEST_OBJECT_ID_HEX) { $env:P11_TEST_OBJECT_ID_HEX } else { "504f525441424c45" }
    $EcId = "${EffectiveObjectId}4543"
    $Selector = if ($env:P11_TEST_SLOT_ID) { @("--slot", $env:P11_TEST_SLOT_ID) } else { @("--token", $EffectiveTokenLabel) }
    $OpenSCSelector = if ($env:P11_TEST_SLOT_ID) { @("--slot", $env:P11_TEST_SLOT_ID) } else { @("--token-label", $EffectiveTokenLabel) }
    $UtilityLog = Join-Path $OutputDir "softhsm-utilities.log"
    $UtilityLines = [System.Collections.Generic.List[string]]::new()
    function Invoke-Utility([string]$Program, [string[]]$Arguments) {
        $PreviousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            $Lines = @(& $Program @Arguments 2>&1)
            $Code = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $PreviousErrorActionPreference }
        $Lines | ForEach-Object { Write-Host $_; $UtilityLines.Add([string]$_) }
        if ($Code -ne 0) { throw "$Program failed with exit code $Code" }
    }

    Invoke-Utility $SoftHSMUtil @("--show-config", "default-pkcs11-lib")
    Invoke-Utility $SoftHSMUtil @("--show-slots")
    $RsaExport = Join-Path $OutputDir "exported-rsa.pem"
    Invoke-Utility $SoftHSMExport @($Selector + @("--id", $EffectiveObjectId, "--label", $EffectiveKeyLabel,
        "--type", "rsa", "--pin", $UserPin, "--output", $RsaExport))
    Invoke-Utility $OpenSSL @("pkey", "-in", $RsaExport, "-check", "-noout")
    $RsaPublic = Join-Path $OutputDir "exported-rsa-public.der"
    $CertPublicPem = Join-Path $OutputDir "certificate-public.pem"
    $CertPublicDer = Join-Path $OutputDir "certificate-public.der"
    Invoke-Utility $OpenSSL @("pkey", "-in", $RsaExport, "-pubout", "-outform", "DER", "-out", $RsaPublic)
    Invoke-Utility $OpenSSL @("x509", "-in", (Join-Path $OutputDir "issued.pem"), "-pubkey", "-noout", "-out", $CertPublicPem)
    Invoke-Utility $OpenSSL @("pkey", "-pubin", "-in", $CertPublicPem, "-outform", "DER", "-out", $CertPublicDer)
    if ((Get-FileHash -Algorithm SHA256 $RsaPublic).Hash -ne (Get-FileHash -Algorithm SHA256 $CertPublicDer).Hash) {
        throw "exported RSA public key does not match the issued certificate"
    }

    foreach ($ObjectType in @("privkey", "pubkey")) {
        $PreviousErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = "Continue"
            & $Pkcs11Tool --module $Module @OpenSCSelector --login --pin $UserPin `
                --delete-object --type $ObjectType --id $EcId *> $null
        }
        finally { $ErrorActionPreference = $PreviousErrorActionPreference }
    }
    $SourceEc = Join-Path $OutputDir "source-ec.pem"
    $ExportedEc = Join-Path $OutputDir "exported-ec.pem"
    Invoke-Utility $OpenSSL @("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", $SourceEc)
    Invoke-Utility $SoftHSMUtil @(@("--import", $SourceEc) + $Selector + @("--label", "portable-export-ec", "--id", $EcId, "--pin", $UserPin))
    Invoke-Utility $SoftHSMExport @($Selector + @("--id", $EcId, "--label", "portable-export-ec",
        "--type", "ec", "--pin", $UserPin, "--output", $ExportedEc))
    Invoke-Utility $OpenSSL @("pkey", "-in", $ExportedEc, "-check", "-noout")
    $SourceEcPublic = Join-Path $OutputDir "source-ec-public.der"
    $ExportedEcPublic = Join-Path $OutputDir "exported-ec-public.der"
    Invoke-Utility $OpenSSL @("pkey", "-in", $SourceEc, "-pubout", "-outform", "DER", "-out", $SourceEcPublic)
    Invoke-Utility $OpenSSL @("pkey", "-in", $ExportedEc, "-pubout", "-outform", "DER", "-out", $ExportedEcPublic)
    if ((Get-FileHash -Algorithm SHA256 $SourceEcPublic).Hash -ne (Get-FileHash -Algorithm SHA256 $ExportedEcPublic).Hash) {
        throw "exported EC public key does not match the imported key"
    }
    $UtilityLines.Add("[UTIL] PASS: autonomous util and forced RSA/ECDSA PKCS#8 export")
    $UtilityLines | Set-Content -Encoding utf8 -LiteralPath $UtilityLog
    Write-Host "[UTIL] PASS: autonomous util and forced RSA/ECDSA PKCS#8 export"
}

function Invoke-OpenSCPkcs11Tool([string]$Option, [string]$LogName) {
    $PreviousErrorActionPreference = $ErrorActionPreference
    try {
        # Windows OpenSC writes the informational "Using slot ..." line to
        # stderr even on success. Windows PowerShell 5 turns native stderr in
        # a pipeline into NativeCommandError when the script preference is
        # Stop, so capture it first and judge only the native exit code.
        $ErrorActionPreference = "Continue"
        $Output = @(& $Pkcs11Tool --module $Module $Option 2>&1)
        $ExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference
    }
    $Output | ForEach-Object { Write-Host $_ }
    $Output | Out-File -LiteralPath (Join-Path $OutputDir $LogName) -Encoding utf8
    if ($ExitCode -ne 0) { throw "pkcs11-tool $Option failed with exit code $ExitCode" }
}

Write-Host "[OPENSC] checking C_Initialize and library information with pkcs11-tool -I"
Invoke-OpenSCPkcs11Tool "-I" "pkcs11-tool-I.log"
Write-Host "[OPENSC] checking slots and token information with pkcs11-tool -T"
Invoke-OpenSCPkcs11Tool "-T" "pkcs11-tool-T.log"
Write-Host "[OPENSC] PASS: packaged pkcs11-tool loaded the tested module"
