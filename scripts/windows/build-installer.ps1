[CmdletBinding()]
param(
    [string]$ProductVersion,
    [string]$ComposeFile,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseImagesFile,
    [string]$OutputDirectory,
    [string]$MakensisPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$SigningCertificateThumbprint,
    [ValidatePattern('^https://')]
    [string]$TimestampUrl = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a non-reparse regular file: $Path"
    }
    return $resolved.Path
}

function Resolve-RequiredCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$ExplicitPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return Resolve-ExistingFile -Path $ExplicitPath -Description $Name
    }
    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Stop
    return Resolve-ExistingFile -Path $command.Source -Description $Name
}

function Invoke-Checked {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Program,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed with exit code $LASTEXITCODE"
    }
}

function Assert-AuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode verification failed for $Path with status $($signature.Status)."
    }
    $actual = $signature.SignerCertificate.Thumbprint.Replace(" ", "")
    if (-not $actual.Equals($ExpectedThumbprint, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected signing certificate for $Path."
    }
}

function Read-And-ValidateImageLock {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $strictUtf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false, $true
    $text = [IO.File]::ReadAllText($Path, $strictUtf8)
    if ($text.Length -gt 16384 -or ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF)) {
        throw "Release image lock is too large or contains a BOM."
    }
    $rules = [ordered]@{
        DES_POSTGRES_IMAGE = "postgres"
        DES_API_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-api"
        DES_EGRESS_GUARD_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-egress-guard"
        DES_WORKER_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-worker"
        DES_WEB_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-web"
    }
    $values = @{}
    foreach ($rawLine in ($text -split "`r?`n")) {
        $line = $rawLine.Trim()
        if ($line.Length -eq 0 -or $line.StartsWith("#")) {
            continue
        }
        if ($line -notmatch '^([^=]+)=(.+)$') {
            throw "Release image lock contains an invalid line."
        }
        $key = $Matches[1]
        $value = $Matches[2]
        if ($key -ne $key.Trim() -or $value -ne $value.Trim() -or
            -not $rules.Contains($key) -or $values.ContainsKey($key)) {
            throw "Release image lock contains an unknown, duplicate, or non-canonical entry."
        }
        $repository = [Regex]::Escape([string]$rules[$key])
        if ($value -cnotmatch "^${repository}@sha256:[0-9a-f]{64}$") {
            throw "Release image $key must match its allowlisted repository and lowercase sha256 digest."
        }
        $values[$key] = $value
    }
    if ($values.Count -ne $rules.Count) {
        throw "Release image lock is missing one or more required images."
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw "Windows 11 x64 is required to build the Setup.exe artifact."
}
if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::X64) {
    throw "A native AMD64 Windows host is required; Windows on Arm is rejected."
}
$windowsKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$windows = Get-ItemProperty -LiteralPath $windowsKey
if ([int]$windows.CurrentBuildNumber -lt 22000 -or $windows.InstallationType -ne "Client") {
    throw "A Windows 11 client host is required; Windows Server is rejected."
}

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory "..\.."))
$launcherCargoManifest = Join-Path $repositoryRoot "desktop\windows\Cargo.toml"
$aclScriptSource = Join-Path $repositoryRoot "desktop\windows\resources\secure-acl.ps1"
$installerScript = Join-Path $repositoryRoot "installer\windows\DataXEnterpriseStudio.nsi"
if ([string]::IsNullOrWhiteSpace($ComposeFile)) {
    $ComposeFile = Join-Path $repositoryRoot "deploy\windows\compose.yaml"
}
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "dist\windows"
}

$cargo = Resolve-RequiredCommand -Name "cargo.exe"
$makensis = Resolve-RequiredCommand -Name "makensis.exe" -ExplicitPath $MakensisPath
$signtool = Resolve-RequiredCommand -Name "signtool.exe"
$composeSource = Resolve-ExistingFile -Path $ComposeFile -Description "Windows Compose file"
$imagesSource = Resolve-ExistingFile -Path $ReleaseImagesFile -Description "Release image lock"
$aclScriptSource = Resolve-ExistingFile -Path $aclScriptSource -Description "ACL helper"
$nsiSource = Resolve-ExistingFile -Path $installerScript -Description "NSIS installer script"
$launcherCargoManifest = Resolve-ExistingFile -Path $launcherCargoManifest -Description "Launcher Cargo manifest"
Read-And-ValidateImageLock -Path $imagesSource

$metadataJson = & $cargo metadata --format-version 1 --no-deps --manifest-path $launcherCargoManifest
if ($LASTEXITCODE -ne 0) {
    throw "cargo metadata failed with exit code $LASTEXITCODE"
}
$metadata = $metadataJson | ConvertFrom-Json
$package = @($metadata.packages) |
    Where-Object { $_.name -eq "datax-enterprise-studio-launcher" } |
    Select-Object -First 1
if ($null -eq $package) {
    throw "Launcher package metadata is missing."
}
$crateVersion = [string]$package.version
if ([string]::IsNullOrWhiteSpace($ProductVersion)) {
    $ProductVersion = $crateVersion
}
if ($ProductVersion -ne $crateVersion) {
    throw "ProductVersion must match Cargo package version $crateVersion."
}
if ($ProductVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "ProductVersion must be a three-part numeric version, for example 0.1.0."
}
$fileVersion = "$ProductVersion.0"

if (Test-Path -LiteralPath $OutputDirectory) {
    $outputItem = Get-Item -LiteralPath $OutputDirectory -Force
    if (-not $outputItem.PSIsContainer -or
        ($outputItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "OutputDirectory must be a non-reparse directory."
    }
}
else {
    [IO.Directory]::CreateDirectory($OutputDirectory) | Out-Null
}
$outputDirectoryResolved = (Resolve-Path -LiteralPath $OutputDirectory).Path
$stagingDirectory = Join-Path $outputDirectoryResolved "staging-$ProductVersion"
if (Test-Path -LiteralPath $stagingDirectory) {
    throw "Staging directory already exists; remove it explicitly before rebuilding: $stagingDirectory"
}
[IO.Directory]::CreateDirectory($stagingDirectory) | Out-Null
$resourceDirectory = Join-Path $stagingDirectory "resources"
[IO.Directory]::CreateDirectory($resourceDirectory) | Out-Null

$launcherStaged = Join-Path $stagingDirectory "launcher.exe"
$composeStaged = Join-Path $resourceDirectory "compose.yaml"
$imagesStaged = Join-Path $resourceDirectory "images.release.env"
$aclScriptStaged = Join-Path $resourceDirectory "secure-acl.ps1"
$manifestStaged = Join-Path $resourceDirectory "release-manifest.json"
Copy-Item -LiteralPath $composeSource -Destination $composeStaged
Copy-Item -LiteralPath $imagesSource -Destination $imagesStaged
Copy-Item -LiteralPath $aclScriptSource -Destination $aclScriptStaged

$composeHash = (Get-FileHash -LiteralPath $composeStaged -Algorithm SHA256).Hash.ToLowerInvariant()
$imagesHash = (Get-FileHash -LiteralPath $imagesStaged -Algorithm SHA256).Hash.ToLowerInvariant()
$aclScriptHash = (Get-FileHash -LiteralPath $aclScriptStaged -Algorithm SHA256).Hash.ToLowerInvariant()
$releaseManifest = [ordered]@{
    schema_version = "1.0"
    product_version = $ProductVersion
    compose_sha256 = $composeHash
    images_sha256 = $imagesHash
    acl_script_sha256 = $aclScriptHash
}
$manifestJson = $releaseManifest | ConvertTo-Json -Compress
$utf8WithoutBom = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
[IO.File]::WriteAllText($manifestStaged, $manifestJson, $utf8WithoutBom)
$manifestHash = (Get-FileHash -LiteralPath $manifestStaged -Algorithm SHA256).Hash.ToLowerInvariant()

$targetTriple = "x86_64-pc-windows-msvc"
Invoke-Checked -Program $cargo -Arguments @(
    "test", "--locked", "--manifest-path", $launcherCargoManifest
)
$previousBinding = [Environment]::GetEnvironmentVariable(
    "DES_RELEASE_MANIFEST_SHA256",
    [EnvironmentVariableTarget]::Process
)
try {
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_MANIFEST_SHA256",
        $manifestHash,
        [EnvironmentVariableTarget]::Process
    )
    Invoke-Checked -Program $cargo -Arguments @(
        "build", "--locked",
        "--manifest-path", $launcherCargoManifest,
        "--target", $targetTriple,
        "--release"
    )
}
finally {
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_MANIFEST_SHA256",
        $previousBinding,
        [EnvironmentVariableTarget]::Process
    )
}

$launcherSource = Join-Path $repositoryRoot "desktop\windows\target\$targetTriple\release\launcher.exe"
$launcherSource = Resolve-ExistingFile -Path $launcherSource -Description "Windows Launcher executable"
Copy-Item -LiteralPath $launcherSource -Destination $launcherStaged

Invoke-Checked -Program $signtool -Arguments @(
    "sign", "/sha1", $SigningCertificateThumbprint,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $launcherStaged
)
Assert-AuthenticodeSignature -Path $launcherStaged -ExpectedThumbprint $SigningCertificateThumbprint

$setupPath = Join-Path $outputDirectoryResolved "DataX-Enterprise-Studio-Setup-$ProductVersion-x64.exe"
if (Test-Path -LiteralPath $setupPath) {
    throw "Setup output already exists; remove it explicitly before rebuilding: $setupPath"
}
Invoke-Checked -Program $makensis -Arguments @(
    "/DPRODUCT_VERSION=$ProductVersion",
    "/DFILE_VERSION=$fileVersion",
    "/DLAUNCHER_EXE=$launcherStaged",
    "/DCOMPOSE_FILE=$composeStaged",
    "/DIMAGE_ENV_FILE=$imagesStaged",
    "/DACL_SCRIPT=$aclScriptStaged",
    "/DRELEASE_MANIFEST=$manifestStaged",
    "/DOUTPUT_FILE=$setupPath",
    $nsiSource
)

Invoke-Checked -Program $signtool -Arguments @(
    "sign", "/sha1", $SigningCertificateThumbprint,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $setupPath
)
Assert-AuthenticodeSignature -Path $setupPath -ExpectedThumbprint $SigningCertificateThumbprint

$launcherDigest = (Get-FileHash -LiteralPath $launcherStaged -Algorithm SHA256).Hash.ToLowerInvariant()
$setupDigest = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "Setup: $setupPath"
Write-Output "Setup SHA256: $setupDigest"
Write-Output "Launcher SHA256: $launcherDigest"
Write-Output "Release manifest SHA256: $manifestHash"
Write-Output "Compose SHA256: $composeHash"
Write-Output "Image lock SHA256: $imagesHash"
Write-Output "ACL helper SHA256: $aclScriptHash"
