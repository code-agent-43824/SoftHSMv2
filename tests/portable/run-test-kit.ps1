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
$BundledModule = (Resolve-Path -LiteralPath (Join-Path $KitDir $Settings.MODULE_NAME)).Path
$Module = if ($args.Count -eq 1) { (Resolve-Path -LiteralPath $args[0]).Path } else { $BundledModule }
$BundledMode = if ([string]::Equals($Module, $BundledModule, [StringComparison]::OrdinalIgnoreCase)) {
    "YES"
} else { "NO" }
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
if ($InitializeSetting -eq "AUTO" -and $env:SOFTHSM2_CONF -and
    (Test-Path -LiteralPath $env:SOFTHSM2_CONF -PathType Leaf)) {
    throw "AUTO cannot select an explicitly configured token store; set INITIALIZE_TOKEN=NO or YES"
}
if ($BundledMode -eq "NO" -and $InitializeSetting -eq "AUTO") {
    $AlternateDir = Split-Path -Parent $Module
    if ((Test-Path -LiteralPath (Join-Path $AlternateDir 'softhsm.conf') -PathType Leaf) -or
        (Test-Path -LiteralPath (Join-Path $AlternateDir 'softhsm2.conf') -PathType Leaf)) {
        throw "AUTO cannot select a module-adjacent token store; set INITIALIZE_TOKEN=NO or YES"
    }
}
$TokenDirectory = "(explicit setting)"
switch ($InitializeSetting) {
    "AUTO" {
        $TokenDirectory = Join-Path (Split-Path -Parent $UserConfig) "tokens"
        if ($BundledMode -eq "YES" -and
            (Test-Path -LiteralPath (Join-Path $KitDir 'softhsm.conf') -PathType Leaf)) {
            $TokenDirectory = Join-Path $KitDir "tokens"
        }
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
if (-not (Test-Path -LiteralPath $Module -PathType Leaf)) {
    throw "PKCS #11 library is not a file: $Module"
}
$env:P11_TEST_CLIENT = $Client
$env:OPENSSL_CONF = (Resolve-Path (Join-Path $KitDir "config/openssl.cnf")).Path
function Invoke-GostVerifier([string]$ExportedKey) {
    $PreviousConfig = $env:OPENSSL_CONF
    $PreviousModules = $env:OPENSSL_MODULES
    try {
        $env:OPENSSL_CONF = (Resolve-Path (Join-Path $KitDir "config/openssl-gost.cnf")).Path
        $env:OPENSSL_MODULES = (Resolve-Path (Join-Path $KitDir "bin")).Path
        $Arguments = @{ KitDir = $KitDir }
        if ($ExportedKey) { $Arguments.ExportedKey = $ExportedKey }
        & (Join-Path $KitDir "scripts/verify-gost-openssl.ps1") @Arguments
        if ($LASTEXITCODE -ne 0) { throw "GOST OpenSSL verification failed" }
    }
    finally {
        $env:OPENSSL_CONF = $PreviousConfig
        if ($null -eq $PreviousModules) {
            Remove-Item Env:OPENSSL_MODULES -ErrorAction SilentlyContinue
        }
        else { $env:OPENSSL_MODULES = $PreviousModules }
    }
}

Write-Host "[TEST-KIT] platform=$($Settings.PLATFORM)"
Write-Host "[TEST-KIT] settings=$ConfigPath"
Write-Host "[TEST-KIT] PKCS #11 library=$Module"
Write-Host "[TEST-KIT] bundled config=$(Join-Path $KitDir 'softhsm.conf')"
Write-Host "[TEST-KIT] AUTO token directory=$TokenDirectory"
Write-Host "[TEST-KIT] initialize token=$Initialize"
Write-Host "[TEST-KIT] excluded functions=$(if ($Excluded.Count) { $Excluded -join ',' } else { '<none>' })"
Write-Host "[TEST-KIT] precompiled client=$Client"
Write-Host "[TEST-KIT] bundled OpenSSL=$OpenSSL"
Write-Host "[TEST-KIT] bundled OpenSC pkcs11-tool=$Pkcs11Tool"
Write-Host "[TEST-KIT] bundled SoftHSM utilities=$SoftHSMUtil, $SoftHSMExport"
Write-Host "[TEST-KIT] all test evidence remains under=$(Join-Path $KitDir 'test-output')"

if ($BundledMode -eq "YES") {
    & (Join-Path $KitDir "scripts/verify-config-override.ps1") $Module $Client $SoftHSMUtil (Join-Path $KitDir "test-output")
}

Invoke-GostVerifier
& (Join-Path $KitDir 'scripts/verify-gost-cms.ps1') -KitDir $KitDir

& (Join-Path $KitDir "scripts/run-fresh-integration.ps1") $Module $OpenSSL $BundledMode
if ($LASTEXITCODE -ne 0) { throw "downloadable test kit failed" }

$OutputDir = Join-Path $KitDir "test-output"
if ($BundledMode -eq "YES") {
    $EffectiveTokenLabel = if ($env:P11_TEST_TOKEN_LABEL) { $env:P11_TEST_TOKEN_LABEL } else { "portable-ci-token" }
    $EffectiveKeyLabel = if ($env:P11_TEST_KEY_LABEL) { $env:P11_TEST_KEY_LABEL } else { "portable-ci-rsa" }
    $EffectiveObjectId = if ($env:P11_TEST_OBJECT_ID_HEX) { $env:P11_TEST_OBJECT_ID_HEX } else { "504f525441424c45" }
    $ColonObjectId = $EffectiveObjectId -replace '(.{2})(?=.)', '$1:'
    $EcId = "${EffectiveObjectId}4543"
    $GostId = "${EffectiveObjectId}47"
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
    Invoke-Utility $SoftHSMExport @($Selector + @("--id", $ColonObjectId, "--label", $EffectiveKeyLabel,
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

    $ExportedGost = Join-Path $OutputDir "exported-gost.der"
    $GostAsn1 = Join-Path $OutputDir "exported-gost-asn1.txt"
    Invoke-Utility $SoftHSMExport @($Selector + @("--id", $GostId, "--label", "portable-ci-gost2012-256",
        "--type", "gost", "--pin", $UserPin, "--format", "der", "--output", $ExportedGost))
    $GostAsn1Lines = @(& $OpenSSL asn1parse -inform DER -in $ExportedGost 2>&1)
    $GostAsn1Code = $LASTEXITCODE
    $GostAsn1Lines | ForEach-Object { Write-Host $_; $UtilityLines.Add([string]$_) }
    $GostAsn1Lines | Set-Content -Encoding utf8 -LiteralPath $GostAsn1
    if ($GostAsn1Code -ne 0) { throw "OpenSSL could not parse exported GOST PKCS#8" }
    $GostAsn1Text = $GostAsn1Lines -join "`n"
    foreach ($Pattern in @(
        'GOST R 34\.10-2012 with 256 bit modulus|id-tc26-gost3410-12-256|1\.2\.643\.7\.1\.1\.1\.1',
        'id-GostR3410-2001-CryptoPro-A-ParamSet|1\.2\.643\.2\.2\.35\.1',
        'GOST R 34\.11-2012 with 256 bit hash|id-tc26-gost3411-12-256|1\.2\.643\.7\.1\.1\.2\.2'
    )) {
        if ($GostAsn1Text -notmatch $Pattern) { throw "exported GOST PKCS#8 is missing an expected OID" }
    }
    Invoke-GostVerifier $ExportedGost
    $UtilityLines.Add("[UTIL] PASS: autonomous util and forced RSA/ECDSA/GOST PKCS#8 export")
    $UtilityLines | Set-Content -Encoding utf8 -LiteralPath $UtilityLog
    Write-Host "[UTIL] PASS: autonomous util and forced RSA/ECDSA/GOST PKCS#8 export"
}

if ($BundledMode -eq "YES") {
    # The full vendor-neutral case battery, the same one the Linux push CI
    # runs, driven by the client itself so Windows runs it against the bundled
    # module exactly as the other platforms do. Each case is isolated in its
    # own store under test-output.
    Write-Host "[BATTERY] running the full e2e case battery against the bundled module"
    $BatteryLog = Join-Path $OutputDir "battery.log"
    & $Client battery $Module (Join-Path $OutputDir "battery") |
        Tee-Object -FilePath $BatteryLog
    if ($LASTEXITCODE -ne 0) { throw "e2e case battery failed" }
    foreach ($Pattern in @('C_EX_InitToken behaviour verified',
            'C_EX_SetTokenName = CKR_OK', 'C_EX_SetLocalPIN = CKR_OK')) {
        if (-not (Select-String -LiteralPath $BatteryLog -SimpleMatch -Pattern $Pattern -Quiet)) {
            throw "e2e battery did not prove $Pattern"
        }
    }
    Write-Host "[C_EX] PASS: InitToken, SetTokenName and SetLocalPIN functional battery"
    Write-Host "[BATTERY] PASS: full e2e case battery"
    $GostVerifyStore = Join-Path $OutputDir ("gost-cms-verify-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force (Join-Path $GostVerifyStore 'tokens') | Out-Null
    @('directories.tokendir = ./tokens', 'objectstore.backend = file',
      'FAKE_RUTOKEN_ECP = true') |
        Set-Content -LiteralPath (Join-Path $GostVerifyStore 'softhsm.conf') -Encoding ascii
    $OldSoftHsmConfig = $env:SOFTHSM2_CONF
    $OldExcludedFunctions = $env:P11_TEST_EXCLUDE_FUNCTIONS
    try {
        $env:SOFTHSM2_CONF = Join-Path $GostVerifyStore 'softhsm.conf'
        $env:P11_TEST_EXCLUDE_FUNCTIONS = ''
        & $Client cms-gost-verify-external $Module (Join-Path $OutputDir 'gost-cms')
        if ($LASTEXITCODE -ne 0) { throw 'OpenSSL GOST CMS envelope failed PKCS #11 verification' }
    }
    finally {
        if ($null -eq $OldSoftHsmConfig) { Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue }
        else { $env:SOFTHSM2_CONF = $OldSoftHsmConfig }
        if ($null -eq $OldExcludedFunctions) { Remove-Item Env:P11_TEST_EXCLUDE_FUNCTIONS -ErrorAction SilentlyContinue }
        else { $env:P11_TEST_EXCLUDE_FUNCTIONS = $OldExcludedFunctions }
    }
    Write-Host '[GOST-CMS] PASS: OpenSSL envelope verified by PKCS #11 module'
    & (Join-Path $KitDir 'scripts/verify-rutoken-opensc.ps1') `
        -Module $Module -Cli $Pkcs11Tool `
        -Spy (Join-Path $KitDir 'lib/pkcs11-spy.dll') `
        -Util $SoftHSMUtil -OutputDir $OutputDir
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
if ($BundledMode -eq 'YES' -and -not ($env:SOFTHSM2_CONF -and
    (Test-Path -LiteralPath $env:SOFTHSM2_CONF -PathType Leaf))) {
    Invoke-OpenSCPkcs11Tool '--rutoken-info' 'pkcs11-tool-rutoken-info.log'
    if (-not (Select-String -LiteralPath (Join-Path $OutputDir 'pkcs11-tool-rutoken-info.log') `
            -SimpleMatch -Pattern 'RUTOKEN_ECP' -Quiet)) {
        throw 'bundled token did not report Rutoken ECP'
    }
    Write-Host '[RUTOKEN-DEFAULT] PASS: bundled token reports Rutoken ECP'
}
Write-Host "[OPENSC] PASS: packaged pkcs11-tool loaded the tested module"
