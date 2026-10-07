param(
    [Parameter(Mandatory = $true)][string]$KitDir,
    [Parameter(Mandatory = $true)][string]$Module,
    [Parameter(Mandatory = $true)][string]$Slot,
    [Parameter(Mandatory = $true)][string]$CertificateId,
    [Parameter(Mandatory = $true)][string]$TokenCaPem
)
$ErrorActionPreference = 'Stop'
if (-not $env:RUTOKEN_PIN) { throw 'RUTOKEN_PIN is required' }
$Kit = (Resolve-Path -LiteralPath $KitDir).Path
$Out = Join-Path $Kit 'test-output/gost-cms'
$OpenSSL = Join-Path $Kit 'bin/openssl.exe'
$Tool = Join-Path $Kit 'bin/pkcs11-tool.exe'
& (Join-Path $Kit 'scripts/verify-gost-cms.ps1') -KitDir $Kit
$env:OPENSSL_CONF = Join-Path $Kit 'config/openssl-gost-engine.cnf'
$env:OPENSSL_ENGINES = Join-Path $Kit 'bin'
$env:OPENSSL_MODULES = Join-Path $Kit 'bin'

& $Tool --module $Module --slot $Slot --login --pin env:RUTOKEN_PIN `
    --rutoken-pkcs7-verify --input-file (Join-Path $Out 'openssl-smime.der') `
    --rutoken-trusted (Join-Path $Out 'ca.der') `
    --output-file (Join-Path $Out 'rutoken-verified.txt') `
    > (Join-Path $Out 'rutoken-verify.log')
if ($LASTEXITCODE -ne 0) { throw 'Rutoken did not verify the OpenSSL envelope' }
if ((Get-FileHash -Algorithm SHA256 (Join-Path $Out 'message.txt')).Hash -ne
    (Get-FileHash -Algorithm SHA256 (Join-Path $Out 'rutoken-verified.txt')).Hash) {
    throw 'Rutoken verified different CMS content'
}
Write-Host '[GOST-CMS] PASS: OpenSSL envelope verified by Rutoken'

$Constraints = (& $OpenSSL x509 -in $TokenCaPem -noout -ext basicConstraints) -join "`n"
if ($LASTEXITCODE -ne 0 -or $Constraints -notmatch 'critical' -or $Constraints -notmatch 'CA:TRUE') {
    throw 'Token CA must have basicConstraints=critical,CA:TRUE'
}
& $Tool --module $Module --slot $Slot --login --pin env:RUTOKEN_PIN `
    --rutoken-pkcs7-sign --id $CertificateId `
    --input-file (Join-Path $Out 'message.txt') `
    --output-file (Join-Path $Out 'rutoken-signed.der') `
    > (Join-Path $Out 'rutoken-sign.log')
if ($LASTEXITCODE -ne 0) { throw 'Rutoken CMS signing failed' }
& $OpenSSL smime -verify -inform DER -in (Join-Path $Out 'rutoken-signed.der') `
    -CAfile $TokenCaPem -out (Join-Path $Out 'openssl-verified-rutoken.txt')
if ($LASTEXITCODE -ne 0) { throw 'OpenSSL did not verify the Rutoken envelope' }
if ((Get-FileHash -Algorithm SHA256 (Join-Path $Out 'message.txt')).Hash -ne
    (Get-FileHash -Algorithm SHA256 (Join-Path $Out 'openssl-verified-rutoken.txt')).Hash) {
    throw 'OpenSSL verified different Rutoken CMS content'
}
Write-Host '[GOST-CMS] PASS: Rutoken envelope verified by OpenSSL'
