param(
    [Parameter(Mandatory = $true)] [string] $StageDir,
    [Parameter(Mandatory = $true)] [string] $ExpectedMachinePattern
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }

$Platform = "windows-$($env:PORTABLE_ARCH)"
$ApiHeaders = @{ Accept = 'application/vnd.github+json' }
if ($env:OPENSC_GITHUB_TOKEN) {
    $ApiHeaders.Authorization = "Bearer $($env:OPENSC_GITHUB_TOKEN)"
}
$Release = Invoke-RestMethod -Uri 'https://api.github.com/repos/code-agent-43824/OpenSC/releases/latest' `
    -Headers $ApiHeaders
$Tag = [string]$Release.tag_name
if ($Tag -notmatch '^[0-9]+\.[0-9]+\.[0-9]+-portable\.[0-9]+$') {
    throw "unexpected OpenSC Latest tag: $Tag"
}
$ArchiveName = "opensc-portable-$Platform.zip"
$WorkDir = Join-Path $(if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }) `
    "opensc-fork-$Platform-$Tag"
New-Item -ItemType Directory -Force -Path $WorkDir, (Join-Path $StageDir 'bin'), `
    (Join-Path $StageDir 'lib') | Out-Null

function Get-ReleaseAsset([string]$Name) {
    $Asset = @($Release.assets | Where-Object { $_.name -eq $Name })
    if ($Asset.Count -ne 1) { throw "OpenSC release is missing $Name" }
    $Url = "https://github.com/code-agent-43824/OpenSC/releases/download/$Tag/$Name"
    if ($Asset[0].browser_download_url -ne $Url) {
        throw "invalid OpenSC release asset URL: $Name"
    }
    $Match = [regex]::Match([string]$Asset[0].digest, '^sha256:([0-9a-f]{64})$')
    if (-not $Match.Success) { throw "missing OpenSC release digest: $Name" }
    $Digest = $Match.Groups[1].Value
    $Path = Join-Path $WorkDir $Name
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
    if ($Actual -ne $Digest) { throw "OpenSC checksum mismatch for $Name" }
    return @{ Path = $Path; Digest = $Digest }
}

$Manifest = Get-ReleaseAsset 'SHA256SUMS'
$Archive = Get-ReleaseAsset $ArchiveName
$ManifestLine = @(Get-Content -LiteralPath $Manifest.Path | Where-Object {
    $_ -match "^[0-9a-f]{64}  $([regex]::Escape($ArchiveName))$"
})
if ($ManifestLine.Count -ne 1 -or $ManifestLine[0].Substring(0, 64) -ne $Archive.Digest) {
    throw "OpenSC manifest disagrees with release digest for $ArchiveName"
}

$Extracted = Join-Path $WorkDir 'extracted'
Expand-Archive -LiteralPath $Archive.Path -DestinationPath $Extracted -Force
$Files = @(
    @{ Source = 'bin/pkcs11-tool.exe'; Destination = 'bin/pkcs11-tool.exe' },
    @{ Source = 'bin/opensc.dll'; Destination = 'bin/opensc.dll' },
    @{ Source = 'lib/pkcs11-spy.dll'; Destination = 'lib/pkcs11-spy.dll' },
    @{ Source = 'lib/pkcs11-spy.conf'; Destination = 'lib/pkcs11-spy.conf' },
    @{ Source = 'LICENSE-OpenSC.txt'; Destination = 'LICENSE-OpenSC.txt' }
)
foreach ($File in $Files) {
    $Source = Join-Path $Extracted $File.Source
    if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
        throw "OpenSC release is missing $($File.Source)"
    }
    Copy-Item -LiteralPath $Source -Destination (Join-Path $StageDir $File.Destination)
}
foreach ($Relative in @('bin/pkcs11-tool.exe', 'bin/opensc.dll', 'lib/pkcs11-spy.dll')) {
    $Binary = Join-Path $StageDir $Relative
    if (-not (& dumpbin /headers $Binary | Select-String -Pattern $ExpectedMachinePattern)) {
        throw "$Binary does not have the expected PE machine type"
    }
}
Set-Content -LiteralPath (Join-Path $StageDir 'OPENSC-VERSION.txt') -Value $Tag -Encoding ascii
@("release=$Tag", "archive=$ArchiveName", "sha256=$($Archive.Digest)") |
    Set-Content -LiteralPath (Join-Path $StageDir 'OPENSC-SOURCE.txt') -Encoding ascii
