# A TLS connection whose client key lives in this module under the Rutoken
# profile, made through OpenSSL 3 and pkcs11-provider - the Windows twin of
# run-tls.sh, with the same steps and the same checks.
#
#   run-tls.ps1 -Module <dll> -Util <softhsm2-util.exe> -Tool <pkcs11-tool.exe>
#               -Provider <pkcs11.dll> -Client <tls-client.exe>
#               -OpenSSL <openssl.exe> -Work <directory>
#
# On a fresh store of its own: a token with the factory PINs, an RSA and an
# EC key pair generated on it under FAKE_RUTOKEN_ECP = true, for each key a
# CSR made by `openssl req` through the provider and a certificate from a
# throwaway CA, then tls-client connects to `openssl s_server` on 127.0.0.1,
# which requires that certificate, and gets its line back. Every OpenSSL
# process has to exit 0: the provider closes its sessions and finalizes the
# module after main (docs/JOURNAL.md, 17 October 2026). P11_TLS_PORT names
# the first of two local ports (default 48443).
param(
    [Parameter(Mandatory = $true)][string]$Module,
    [Parameter(Mandatory = $true)][string]$Util,
    [Parameter(Mandatory = $true)][string]$Tool,
    [Parameter(Mandatory = $true)][string]$Provider,
    [Parameter(Mandatory = $true)][string]$Client,
    [Parameter(Mandatory = $true)][string]$OpenSSL,
    [Parameter(Mandatory = $true)][string]$Work
)
$ErrorActionPreference = 'Stop'

function Fail([string]$Message) {
    Write-Host "[TLS] FAIL: $Message"
    exit 1
}
# Paths as OpenSSL configuration and the provider read them.
function ConfigPath([string]$Path) { return $Path.Replace('\', '/') }
# LF line ends: these files are read by OpenSSL and SoftHSM, not by Windows.
function WriteLines([string]$Path, [string[]]$Lines) {
    [IO.File]::WriteAllText($Path, (($Lines -join "`n") + "`n"))
}
# A native command's stderr must not become a PowerShell error: Windows
# PowerShell 5.1 turns every redirected stderr line into one, and 'Stop'
# would end the script on OpenSSL's ordinary progress output.
function Run([string]$What, [string]$Exe, [string[]]$Arguments, [string]$Log) {
    $ErrorActionPreference = 'Continue'
    & $Exe @Arguments > $Log 2>&1
    $Status = $LASTEXITCODE
    if ($Status -ne 0) {
        Get-Content -LiteralPath $Log | Write-Host
        Fail "$What exited with $Status"
    }
}

foreach ($Name in 'Module', 'Util', 'Tool', 'Provider', 'Client', 'OpenSSL') {
    $Value = (Get-Variable -Name $Name).Value
    if (-not (Test-Path -LiteralPath $Value -PathType Leaf)) { Fail "$Name is missing: $Value" }
    Set-Variable -Name $Name -Value (Resolve-Path -LiteralPath $Value).Path
}
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$Work = (Resolve-Path -LiteralPath $Work).Path
$Port = if ($env:P11_TLS_PORT) { [int]$env:P11_TLS_PORT } else { 48443 }
Remove-Item Env:OPENSSL_CONF, Env:OPENSSL_MODULES -ErrorAction SilentlyContinue

Write-Host "[TLS] $(& $OpenSSL version), provider $Provider"

# The factory PINs of the Rutoken profile. The token reports
# CKF_USER_PIN_TO_BE_CHANGED with them, as the device does; the provider has
# to log in all the same.
$SoPin = '87654321'
$UserPin = '12345678'
$Label = 'tls-test'

$Store = Join-Path $Work 'store'
if (Test-Path -LiteralPath $Store) { Remove-Item -LiteralPath $Store -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $Store 'tokens') | Out-Null
$Config = Join-Path $Store 'softhsm.conf'
function WriteConfig([string]$Profile) {
    WriteLines $Config @("directories.tokendir = $(ConfigPath (Join-Path $Store 'tokens'))",
        'objectstore.backend = file', 'log.level = ERROR', "FAKE_RUTOKEN_ECP = $Profile")
}
$env:SOFTHSM2_CONF = $Config
# The token is made with the profile off, where it is one ordinary slot; the
# keys are generated on it with the profile on.
WriteConfig 'false'
Run 'token initialization' $Util @('--module', $Module, '--init-token', '--free', '--label', $Label,
    '--so-pin', $SoPin, '--pin', $UserPin) (Join-Path $Work 'init-token.log')
WriteConfig 'true'
Run 'RSA key generation on the token' $Tool @('--module', $Module, '--token-label', $Label,
    '--login', '--pin', $UserPin, '--keypairgen', '--key-type', 'rsa:2048', '--label', 'tls-rsa',
    '--id', '01') (Join-Path $Work 'keygen-rsa.log')
Run 'EC key generation on the token' $Tool @('--module', $Module, '--token-label', $Label,
    '--login', '--pin', $UserPin, '--keypairgen', '--key-type', 'EC:prime256v1', '--label', 'tls-ec',
    '--id', '02') (Join-Path $Work 'keygen-ec.log')
Write-Host '[TLS] FAKE_RUTOKEN_ECP=true, factory PINs, RSA-2048 and EC P-256 generated on the token'

$PinFile = Join-Path $Work 'pin.txt'
[IO.File]::WriteAllText($PinFile, $UserPin)
$Pkcs11Config = Join-Path $Work 'pkcs11.cnf'
WriteLines $Pkcs11Config @('openssl_conf = openssl_init', '[openssl_init]', 'providers = provider_sect',
  '[provider_sect]', 'default = default_sect', 'pkcs11 = pkcs11_sect',
  '[default_sect]', 'activate = 1', '[pkcs11_sect]',
  "module = $(ConfigPath $Provider)",
  "pkcs11-module-path = $(ConfigPath $Module)",
  "pkcs11-module-token-pin = file:$(ConfigPath $PinFile)",
  'activate = 1')

# The throwaway CA and the server; nothing of theirs is on the token.
$CaConfig = Join-Path $Work 'ca.cnf'
WriteLines $CaConfig @('[req]', 'distinguished_name = dn', 'prompt = no', '[dn]', 'CN = tls-test-ca',
  '[ca]', 'basicConstraints = critical,CA:TRUE', 'keyUsage = critical,keyCertSign,cRLSign',
  '[server]', 'basicConstraints = CA:FALSE',
  'keyUsage = critical,digitalSignature,keyEncipherment', 'extendedKeyUsage = serverAuth',
  'subjectAltName = IP:127.0.0.1,DNS:localhost',
  '[client]', 'basicConstraints = CA:FALSE', 'keyUsage = critical,digitalSignature',
  'extendedKeyUsage = clientAuth')
$NoConfig = Join-Path $Work 'empty.cnf'
[IO.File]::WriteAllText($NoConfig, '')
function Plain([string]$What, [string[]]$Arguments) {
    $env:OPENSSL_CONF = $NoConfig
    try { Run $What $OpenSSL $Arguments (Join-Path $Work "openssl-$($What.Replace(' ', '-')).log") }
    finally { Remove-Item Env:OPENSSL_CONF -ErrorAction SilentlyContinue }
}
$Ca = Join-Path $Work 'ca.pem'; $CaKey = Join-Path $Work 'ca.key'
$Server = Join-Path $Work 'server.pem'; $ServerKey = Join-Path $Work 'server.key'
Plain 'CA' @('req', '-x509', '-config', $CaConfig, '-extensions', 'ca', '-newkey', 'rsa:2048',
    '-nodes', '-keyout', $CaKey, '-out', $Ca, '-days', '2')
Plain 'server request' @('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-nodes', '-keyout', $ServerKey, '-subj', '/CN=localhost', '-out', (Join-Path $Work 'server.csr'))
Plain 'server certificate' @('x509', '-req', '-in', (Join-Path $Work 'server.csr'), '-CA', $Ca,
    '-CAkey', $CaKey, '-CAcreateserial', '-days', '2', '-extfile', $CaConfig,
    '-extensions', 'server', '-out', $Server)

foreach ($Key in 'rsa', 'ec') {
    $Uri = "pkcs11:token=$Label;object=tls-$Key;type=private"
    $Csr = Join-Path $Work "client-$Key.csr"
    $Certificate = Join-Path $Work "client-$Key.pem"
    $env:OPENSSL_CONF = $Pkcs11Config
    try {
        Run "${Key}: openssl req through pkcs11-provider" $OpenSSL @('req', '-new', '-key', $Uri,
            '-subj', "/CN=tls-client-$Key", '-out', $Csr) (Join-Path $Work "req-$Key.log")
    } finally { Remove-Item Env:OPENSSL_CONF -ErrorAction SilentlyContinue }
    Plain "verify $Key request" @('req', '-verify', '-noout', '-in', $Csr)
    $Verified = (Get-Content -LiteralPath (Join-Path $Work "openssl-verify-$Key-request.log")) -join "`n"
    if ($Verified -notlike '*verify OK*') { Fail "${Key}: the CSR does not verify: $Verified" }
    Plain "client $Key certificate" @('x509', '-req', '-in', $Csr, '-CA', $Ca, '-CAkey', $CaKey,
        '-CAcreateserial', '-days', '2', '-extfile', $CaConfig, '-extensions', 'client',
        '-out', $Certificate)

    $ServerOut = Join-Path $Work "server-$Key.log"
    $ServerErr = Join-Path $Work "server-$Key.err"
    $env:OPENSSL_CONF = $NoConfig
    $ServerProcess = Start-Process -FilePath $OpenSSL -NoNewWindow -PassThru `
        -RedirectStandardOutput $ServerOut -RedirectStandardError $ServerErr -ArgumentList @(
            's_server', '-accept', "127.0.0.1:$Port", '-cert', "`"$Server`"",
            '-key', "`"$ServerKey`"", '-CAfile', "`"$Ca`"", '-Verify', '1',
            '-verify_return_error', '-rev', '-naccept', '1')
    Remove-Item Env:OPENSSL_CONF -ErrorAction SilentlyContinue
    try {
        $Started = $false
        for ($i = 0; $i -lt 100 -and -not $ServerProcess.HasExited; $i++) {
            if ((Test-Path -LiteralPath $ServerOut) -and
                (Select-String -LiteralPath $ServerOut -Pattern '^ACCEPT' -Quiet)) { $Started = $true; break }
            Start-Sleep -Milliseconds 100
        }
        if (-not $Started) {
            Get-Content -LiteralPath $ServerOut, $ServerErr -ErrorAction SilentlyContinue | Write-Host
            Fail "${Key}: s_server did not start on port $Port"
        }
        $env:OPENSSL_CONF = $Pkcs11Config
        try {
            Run "${Key}: tls-client" $Client @('127.0.0.1', "$Port", $Uri, $Certificate, $Ca) `
                (Join-Path $Work "client-$Key.log")
        } finally { Remove-Item Env:OPENSSL_CONF -ErrorAction SilentlyContinue }
        Get-Content -LiteralPath (Join-Path $Work "client-$Key.log") | Write-Host
        if (-not $ServerProcess.WaitForExit(10000)) { Fail "${Key}: s_server did not finish" }
    } finally {
        if (-not $ServerProcess.HasExited) { Stop-Process -Id $ServerProcess.Id -Force }
    }
    $Seen = (Get-Content -LiteralPath $ServerOut, $ServerErr -ErrorAction SilentlyContinue) -join "`n"
    if ($Seen -notmatch "CN ?= ?tls-client-$Key") {
        Write-Host $Seen
        Fail "${Key}: the server did not see the token certificate"
    }
    Write-Host "[TLS] PASS: ${Key}: the CSR through the provider and the TLS connection with the token key"
    $Port++
}
Remove-Item Env:SOFTHSM2_CONF -ErrorAction SilentlyContinue
Write-Host '[TLS] PASS: TLS with the client key in the module under FAKE_RUTOKEN_ECP'
exit 0
