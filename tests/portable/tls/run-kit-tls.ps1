# The test kit's TLS block on Windows (tls\run.ps1 in the kit): run-tls.ps1
# against the kit's own module, utilities, and the OpenSSL and pkcs11-provider
# the kit carries in tls\openssl. Test evidence goes to test-output\tls.
# Environment variables are process-wide in PowerShell, so the ones the
# scenario sets are put back afterwards for the rest of run-test.ps1.
$ErrorActionPreference = 'Stop'
$TlsDir = $PSScriptRoot
$KitDir = Split-Path -Parent $TlsDir
$OpenSSLDir = Join-Path $TlsDir 'openssl'

$Saved = @{}
foreach ($Name in 'OPENSSL_CONF', 'OPENSSL_MODULES', 'SOFTHSM2_CONF') {
    $Saved[$Name] = [Environment]::GetEnvironmentVariable($Name)
}
try {
    & (Join-Path $TlsDir 'run-tls.ps1') `
        -Module (Join-Path $KitDir 'softhsm2.dll') `
        -Util (Join-Path $KitDir 'bin/softhsm2-util.exe') `
        -Tool (Join-Path $KitDir 'bin/pkcs11-tool.exe') `
        -Provider (Join-Path $OpenSSLDir 'lib/ossl-modules/pkcs11.dll') `
        -Client (Join-Path $OpenSSLDir 'bin/tls-client.exe') `
        -OpenSSL (Join-Path $OpenSSLDir 'bin/openssl.exe') `
        -Work (Join-Path $KitDir 'test-output/tls')
    $Status = $LASTEXITCODE
}
finally {
    foreach ($Name in $Saved.Keys) {
        [Environment]::SetEnvironmentVariable($Name, $Saved[$Name])
    }
}
exit $Status
