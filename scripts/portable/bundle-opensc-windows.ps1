param(
    [Parameter(Mandatory = $true)] [string] $StageDir,
    [Parameter(Mandatory = $true)] [string] $ExpectedMachinePattern
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not $env:PORTABLE_ARCH) { throw "PORTABLE_ARCH is required" }
if (-not $env:OPENSC_VERSION) { throw "OPENSC_VERSION is required" }

$HashVariable = "OPENSC_WINDOWS_$($env:PORTABLE_ARCH.ToUpperInvariant())_SHA256"
$ExpectedHash = [Environment]::GetEnvironmentVariable($HashVariable, "Process")
if (-not $ExpectedHash) { throw "$HashVariable is required" }

$WorkRoot = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$WorkDir = Join-Path $WorkRoot "opensc-windows-$($env:PORTABLE_ARCH)-$($env:OPENSC_VERSION)"
$Msi = Join-Path $WorkDir "OpenSC-$($env:OPENSC_VERSION)-Light_$($env:PORTABLE_ARCH).msi"
$InstallLog = Join-Path $WorkDir "install.log"
New-Item -ItemType Directory -Force -Path $WorkDir, (Join-Path $StageDir "bin") | Out-Null

$SearchRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) |
    Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) }
function Find-OpenSCTool {
    foreach ($Root in $SearchRoots) {
        $ProjectRoot = Join-Path $Root "OpenSC Project"
        if (Test-Path -LiteralPath $ProjectRoot -PathType Container) {
            Get-ChildItem -LiteralPath $ProjectRoot -Filter pkcs11-tool.exe -File -Recurse
        }
    }
}
$PreexistingTool = Find-OpenSCTool | Select-Object -First 1
if ($PreexistingTool) {
    throw "refusing to modify a pre-existing OpenSC installation: $($PreexistingTool.FullName)"
}

$Url = "https://github.com/OpenSC/OpenSC/releases/download/$($env:OPENSC_VERSION)/$(Split-Path -Leaf $Msi)"
Invoke-WebRequest -Uri $Url -OutFile $Msi
$ActualHash = (Get-FileHash -Algorithm SHA256 $Msi).Hash.ToLowerInvariant()
if ($ActualHash -ne $ExpectedHash.ToLowerInvariant()) {
    throw "OpenSC checksum mismatch: expected $ExpectedHash, got $ActualHash"
}

$Install = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
    "/i", $Msi, "ADDLOCAL=OpenSC_core,OpenSC_tools", "/qn", "/norestart", "/l*v", $InstallLog
)
if ($Install.ExitCode -ne 0) {
    Get-Content -LiteralPath $InstallLog -Tail 100 | Write-Error
    throw "OpenSC MSI installation failed with exit code $($Install.ExitCode)"
}

$InstalledTool = Find-OpenSCTool | Select-Object -First 1
if (-not $InstalledTool) { throw "installed pkcs11-tool.exe was not found" }

$OpenSCRoot = Split-Path -Parent (Split-Path -Parent $InstalledTool.FullName)
$Destination = Join-Path $StageDir "bin/pkcs11-tool.exe"
Copy-Item -LiteralPath $InstalledTool.FullName -Destination $Destination
$DependencyReport = Join-Path $StageDir "OPENSC-DEPENDENCIES.txt"
New-Item -ItemType File -Force -Path $DependencyReport | Out-Null
$Queue = [Collections.Generic.Queue[string]]::new()
$Queue.Enqueue($InstalledTool.FullName)
$Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$SystemNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
Get-ChildItem -LiteralPath (Join-Path $env:WINDIR "System32") -Filter *.dll -File |
    ForEach-Object { [void]$SystemNames.Add($_.Name) }

while ($Queue.Count) {
    $Binary = $Queue.Dequeue()
    $Dependencies = & dumpbin /dependents $Binary |
        ForEach-Object { if ($_ -match '^\s+([A-Za-z0-9_.+-]+\.dll)\s*$') { $Matches[1] } }
    foreach ($Name in $Dependencies) {
        if ($SystemNames.Contains($Name) -or -not $Seen.Add($Name)) { continue }
        $Resolved = Get-ChildItem -LiteralPath $OpenSCRoot -Filter $Name -File -Recurse |
            Select-Object -First 1
        if (-not $Resolved) {
            throw "cannot resolve non-system OpenSC dependency: $Name"
        }
        Copy-Item -LiteralPath $Resolved.FullName -Destination (Join-Path $StageDir "bin/$Name")
        Add-Content -LiteralPath $DependencyReport -Value "$Name <- $($Resolved.FullName)" -Encoding ascii
        $Queue.Enqueue($Resolved.FullName)
    }
}

$License = Get-ChildItem -LiteralPath $OpenSCRoot -File -Recurse |
    Where-Object { $_.Name -match '^(COPYING|LICENSE)' } |
    Select-Object -First 1
if ($License) {
    Copy-Item -LiteralPath $License.FullName -Destination (Join-Path $StageDir "LICENSE-OpenSC.txt")
}
else {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/OpenSC/OpenSC/$($env:OPENSC_VERSION)/COPYING" `
        -OutFile (Join-Path $StageDir "LICENSE-OpenSC.txt")
}

$Uninstall = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @(
    "/x", $Msi, "/qn", "/norestart"
)
if ($Uninstall.ExitCode -ne 0) { throw "OpenSC MSI uninstall failed with exit code $($Uninstall.ExitCode)" }
if (Test-Path -LiteralPath $InstalledTool.FullName -PathType Leaf) {
    throw "OpenSC MSI uninstall left pkcs11-tool.exe installed: $($InstalledTool.FullName)"
}

$MachineHeader = & dumpbin /headers $Destination | Select-String -Pattern $ExpectedMachinePattern
if (-not $MachineHeader) {
    throw "$Destination does not have the expected $($env:PORTABLE_ARCH) PE machine type"
}
Set-Content -LiteralPath (Join-Path $StageDir "OPENSC-VERSION.txt") `
    -Value $env:OPENSC_VERSION -Encoding ascii
