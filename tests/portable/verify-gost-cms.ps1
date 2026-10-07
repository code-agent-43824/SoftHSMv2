param([Parameter(Mandatory = $true)][string]$KitDir)
$ErrorActionPreference = 'Stop'
$Kit = (Resolve-Path -LiteralPath $KitDir).Path
$OpenSSL = Join-Path $Kit 'bin/openssl.exe'
$Out = Join-Path $Kit 'test-output/gost-cms'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$OldConfig = $env:OPENSSL_CONF
$OldEngines = $env:OPENSSL_ENGINES
$OldModules = $env:OPENSSL_MODULES
function Invoke-OpenSSL([string[]]$Arguments) {
    & $OpenSSL @Arguments
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL CMS command failed: $($Arguments[0])" }
}
try {
    $env:OPENSSL_CONF = Join-Path $Kit 'config/openssl-gost-engine.cnf'
    $env:OPENSSL_ENGINES = Join-Path $Kit 'bin'
    $env:OPENSSL_MODULES = Join-Path $Kit 'bin'
    Invoke-OpenSSL -Arguments @('engine', '-t', 'gost') |
        Set-Content -LiteralPath (Join-Path $Out 'engine.txt')
    if (-not (Select-String -LiteralPath (Join-Path $Out 'engine.txt') -SimpleMatch '[ available ]')) {
        throw 'GOST engine is unavailable'
    }
    [IO.File]::WriteAllText((Join-Path $Out 'message.txt'), "Portable GOST CMS cross-check`n",
        [Text.Encoding]::ASCII)
    Invoke-OpenSSL -Arguments @('genpkey', '-engine', 'gost', '-algorithm', 'gost2012_256',
        '-pkeyopt', 'paramset:A', '-out', (Join-Path $Out 'key.pem'))
    Invoke-OpenSSL -Arguments @('req', '-engine', 'gost', '-new', '-x509',
        '-key', (Join-Path $Out 'key.pem'), '-out', (Join-Path $Out 'ca.pem'),
        '-subj', '/CN=Portable GOST CMS CA', '-days', '1',
        '-addext', 'basicConstraints=critical,CA:TRUE')
    Invoke-OpenSSL -Arguments @('x509', '-in', (Join-Path $Out 'ca.pem'), '-outform', 'DER',
        '-out', (Join-Path $Out 'ca.der'))
    foreach ($Mode in @('smime', 'cms')) {
        $Envelope = Join-Path $Out "openssl-$Mode.der"
        $Verified = Join-Path $Out "openssl-$Mode-message.txt"
        Invoke-OpenSSL -Arguments @($Mode, '-sign', '-md', 'streebog256', '-binary', '-nodetach',
            '-in', (Join-Path $Out 'message.txt'), '-signer', (Join-Path $Out 'ca.pem'),
            '-inkey', (Join-Path $Out 'key.pem'), '-outform', 'DER', '-out', $Envelope)
        Invoke-OpenSSL -Arguments @($Mode, '-verify', '-binary', '-inform', 'DER', '-in', $Envelope,
            '-CAfile', (Join-Path $Out 'ca.pem'), '-out', $Verified)
        if ((Get-FileHash -Algorithm SHA256 (Join-Path $Out 'message.txt')).Hash -ne
            (Get-FileHash -Algorithm SHA256 $Verified).Hash) {
            throw "$Mode verified different CMS content"
        }
    }
    Invoke-OpenSSL -Arguments @('asn1parse', '-inform', 'DER',
        '-in', (Join-Path $Out 'openssl-smime.der')) |
        Set-Content -LiteralPath (Join-Path $Out 'openssl-smime-asn1.txt')
    $GostAlgorithm = 'GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)'
    if (-not (Select-String -LiteralPath (Join-Path $Out 'openssl-smime-asn1.txt') -SimpleMatch $GostAlgorithm)) {
        throw 'S/MIME envelope lacks the GOST signature algorithm'
    }
    Write-Host '[GOST-CMS] PASS: ENGINE, S/MIME and CMS signing and verification'
}
finally {
    $env:OPENSSL_CONF = $OldConfig
    if ($null -eq $OldEngines) { Remove-Item Env:OPENSSL_ENGINES -ErrorAction SilentlyContinue }
    else { $env:OPENSSL_ENGINES = $OldEngines }
    if ($null -eq $OldModules) { Remove-Item Env:OPENSSL_MODULES -ErrorAction SilentlyContinue }
    else { $env:OPENSSL_MODULES = $OldModules }
}
