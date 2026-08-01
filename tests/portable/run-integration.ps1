$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($args.Count -ne 5) {
    throw "usage: run-integration.ps1 <module> <softhsm2-util> <openssl> <config> <work-dir>"
}

$Module = (Resolve-Path $args[0]).Path
$Utility = (Resolve-Path $args[1]).Path
$OpenSSL = (Resolve-Path $args[2]).Path
$Config = (Resolve-Path $args[3]).Path
$WorkDir = $args[4]
$RootDir = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$DepsDir = Join-Path $WorkDir "java-deps"
$ClassesDir = Join-Path $WorkDir "java-classes"
$BcVersion = "1.85"

New-Item -ItemType Directory -Force -Path $DepsDir, $ClassesDir | Out-Null

function Get-VerifiedJar {
    param(
        [string]$Artifact,
        [string]$ExpectedSha256
    )
    $Target = Join-Path $DepsDir "$Artifact-$BcVersion.jar"
    $Url = "https://repo1.maven.org/maven2/org/bouncycastle/$Artifact/$BcVersion/$Artifact-$BcVersion.jar"
    Invoke-WebRequest -Uri $Url -OutFile $Target
    $Actual = (Get-FileHash -Algorithm SHA256 $Target).Hash.ToLowerInvariant()
    if ($Actual -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "$Artifact checksum mismatch: expected $ExpectedSha256, got $Actual"
    }
    return $Target
}

$BcProv = Get-VerifiedJar "bcprov-jdk18on" "20af26bf6060bb8005cc2389916812c1e0e998dc48d2ced7131b89461b54cff7"
$BcPkix = Get-VerifiedJar "bcpkix-jdk18on" "c9f82b2d4e99c4bbdfccf684e52cc06ea06a0b567bfd0d08f9c5a3f417055996"
$BcUtil = Get-VerifiedJar "bcutil-jdk18on" "590f55ed5d68529239898a4a5c4f730b6e37f45d1cfa3fbe51f8485abe32c42d"
$Classpath = "$BcProv;$BcPkix;$BcUtil"

javac -encoding UTF-8 -cp $Classpath -d $ClassesDir (Join-Path $RootDir "tests/portable/PortableTokenIntegrationTest.java")
if ($LASTEXITCODE -ne 0) { throw "integration test compilation failed" }

java -cp "$ClassesDir;$Classpath" PortableTokenIntegrationTest `
    $Module $Utility $OpenSSL $Config (Join-Path $WorkDir "scenario")
if ($LASTEXITCODE -ne 0) { throw "portable token integration test failed" }
