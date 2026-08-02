[CmdletBinding()]
param(
    [string]$ProductVersion,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[0-9a-f]{12}$')]
    [string]$ReleaseCandidate,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$CandidateCommit,
    [string]$ComposeFile,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseImagesFile,
    [string]$OutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$CargoPath,
    [Parameter(Mandatory = $true)]
    [string]$RustcPath,
    [Parameter(Mandatory = $true)]
    [string]$MakensisPath,
    [Parameter(Mandatory = $true)]
    [string]$SigntoolPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$SigningCertificateThumbprint,
    [Parameter(Mandatory = $true)]
    [string]$AllowedSignerFile,
    [ValidatePattern('^https://')]
    [string]$TimestampUrl = "https://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$CargoCompilerOverrideVariables = @(
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_TARGET_DIR",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTC_BOOTSTRAP"
)

function Resolve-ExistingFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "$Description path is invalid."
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Description path is invalid."
    }
    if ($fullPath.Length -le $root.Length) {
        throw "$Description must be a regular file."
    }
    $current = $root
    foreach ($segment in ($fullPath.Substring($root.Length) -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }
        $current = Join-Path -Path $current -ChildPath $segment
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        }
        catch {
            throw "$Description path cannot be accessed."
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Description path must not contain a reparse point."
        }
    }
    if ($item.PSIsContainer) {
        throw "$Description must be a regular file."
    }
    return $fullPath
}

function Resolve-RequiredExecutable {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$ExplicitPath
    )

    if ([string]::IsNullOrWhiteSpace($ExplicitPath) -or
        $ExplicitPath -notmatch '^[A-Za-z]:\\') {
        throw "$Name must be supplied as an explicit local Windows path."
    }
    try {
        $fullPath = [IO.Path]::GetFullPath($ExplicitPath)
        $disk = Get-CimInstance `
            -ClassName Win32_LogicalDisk `
            -Filter "DeviceID='$($fullPath.Substring(0, 2))'" `
            -ErrorAction Stop
    }
    catch {
        throw "$Name must be on a local fixed Windows volume."
    }
    if ($null -eq $disk -or [int]$disk.DriveType -ne 3) {
        throw "$Name must be on a local fixed Windows volume."
    }
    $resolved = Resolve-ExistingFile -Path $fullPath -Description $Name
    if (-not [IO.Path]::GetFileName($resolved).Equals(
        $Name,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Name path must name $Name."
    }
    return $resolved
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
        throw "A required external command failed with exit code $LASTEXITCODE"
    }
}

function Assert-NoCargoCompilerOverrides {
    foreach ($name in $CargoCompilerOverrideVariables) {
        $value = [Environment]::GetEnvironmentVariable(
            $name,
            [EnvironmentVariableTarget]::Process
        )
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "Ambient compiler override $name is forbidden for release signing."
        }
    }
    $environment = [Environment]::GetEnvironmentVariables(
        [EnvironmentVariableTarget]::Process
    )
    foreach ($name in $environment.Keys) {
        $nameText = [string]$name
        if ($nameText.StartsWith(
            "CARGO_TARGET_",
            [StringComparison]::OrdinalIgnoreCase
        ) -or $nameText -match '^CARGO_PROFILE_[A-Z0-9_]+_RUSTFLAGS$') {
            throw "Ambient Cargo target or profile compiler override is forbidden for release signing."
        }
    }
}

function Invoke-ConfiguredCargo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Cargo,
        [Parameter(Mandatory = $true)]
        [string]$Rustc,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Assert-NoCargoCompilerOverrides
    $previousRustc = [Environment]::GetEnvironmentVariable(
        "RUSTC",
        [EnvironmentVariableTarget]::Process
    )
    try {
        [Environment]::SetEnvironmentVariable(
            "RUSTC",
            $Rustc,
            [EnvironmentVariableTarget]::Process
        )
        & $Cargo @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "cargo.exe failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            "RUSTC",
            $previousRustc,
            [EnvironmentVariableTarget]::Process
        )
    }
}

function Assert-AuthenticodeSignature {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]
        [string[]]$AllowedSha256
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $Path with status $($signature.Status)."
    }
    $actualSha1 = $signature.SignerCertificate.Thumbprint.Replace(" ", "")
    $actualSha256 = Get-CertificateSha256 -Certificate $signature.SignerCertificate
    if (-not $actualSha1.Equals($ExpectedThumbprint, [StringComparison]::OrdinalIgnoreCase) -or
        -not $actualSha256.Equals($ExpectedSha256, [StringComparison]::Ordinal) -or
        -not (Test-OrdinalContains -Values $AllowedSha256 -Expected $actualSha256)) {
        throw "Unexpected signing certificate for $Path."
    }
}

function Read-CanonicalSignerAllowlist {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $resolved = Resolve-ExistingFile -Path $Path -Description "publisher allowlist"
    $item = Get-Item -LiteralPath $resolved
    if ($item.Length -le 0 -or $item.Length -gt 16384) {
        throw "Publisher allowlist has an invalid size."
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = [IO.File]::ReadAllText($resolved, $strictUtf8)
    if ($text.Length -eq 0 -or $text[0] -eq [char]0xFEFF) {
        throw "Publisher allowlist must be non-empty UTF-8 without a BOM."
    }
    $document = $text | ConvertFrom-Json
    $propertyNames = @($document.PSObject.Properties.Name)
    if ($propertyNames.Count -ne 2 -or
        $propertyNames[0] -cne "schema_version" -or
        $propertyNames[1] -cne "allowed_authenticode_signer_certificate_sha256" -or
        $document.schema_version -cne "1.0") {
        throw "Publisher allowlist schema is invalid or non-canonical."
    }
    $values = @($document.allowed_authenticode_signer_certificate_sha256)
    if ($values.Count -lt 1 -or $values.Count -gt 8) {
        throw "Publisher allowlist must contain between one and eight certificates."
    }
    for ($index = 0; $index -lt $values.Count; $index++) {
        if ($values[$index] -isnot [string] -or
            $values[$index] -cnotmatch '^[0-9a-f]{64}$') {
            throw "Publisher allowlist contains an invalid certificate SHA-256."
        }
        if ($index -gt 0 -and
            [string]::CompareOrdinal($values[$index - 1], $values[$index]) -ge 0) {
            throw "Publisher allowlist must be strictly ordinal-sorted and unique."
        }
    }
    $canonicalDocument = [ordered]@{
        schema_version = "1.0"
        allowed_authenticode_signer_certificate_sha256 = @($values)
    }
    $canonical = $canonicalDocument | ConvertTo-Json -Compress
    if ($text -cne $canonical) {
        throw "Publisher allowlist must use the exact canonical JSON form."
    }
    return [string[]]$values
}

function Get-CertificateSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    return $Certificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    ).ToLowerInvariant()
}

function Test-OrdinalContains {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Values,
        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    foreach ($value in $Values) {
        if ($value.Equals($Expected, [StringComparison]::Ordinal)) {
            return $true
        }
    }
    return $false
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

$cargo = Resolve-RequiredExecutable -Name "cargo.exe" -ExplicitPath $CargoPath
$rustc = Resolve-RequiredExecutable -Name "rustc.exe" -ExplicitPath $RustcPath
$makensis = Resolve-RequiredExecutable -Name "makensis.exe" -ExplicitPath $MakensisPath
$signtool = Resolve-RequiredExecutable -Name "signtool.exe" -ExplicitPath $SigntoolPath
Assert-NoCargoCompilerOverrides
$composeSource = Resolve-ExistingFile -Path $ComposeFile -Description "Windows Compose file"
$imagesSource = Resolve-ExistingFile -Path $ReleaseImagesFile -Description "Release image lock"
$aclScriptSource = Resolve-ExistingFile -Path $aclScriptSource -Description "ACL helper"
$nsiSource = Resolve-ExistingFile -Path $installerScript -Description "NSIS installer script"
$launcherCargoManifest = Resolve-ExistingFile -Path $launcherCargoManifest -Description "Launcher Cargo manifest"
Read-And-ValidateImageLock -Path $imagesSource
$allowedSigners = Read-CanonicalSignerAllowlist -Path $AllowedSignerFile
$expectedSignerThumbprint = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
$certificatePath = "Cert:\CurrentUser\My\$expectedSignerThumbprint"
$signingCertificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
if (-not $signingCertificate.HasPrivateKey) {
    throw "The selected Windows signing certificate has no private key."
}
$now = Get-Date
if ($signingCertificate.NotBefore -gt $now -or $signingCertificate.NotAfter -le $now) {
    throw "The selected signing certificate is not currently valid."
}
$codeSigning = @(
    $signingCertificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        ForEach-Object { $_.EnhancedKeyUsages } |
        Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }
)
if ($codeSigning.Count -eq 0) {
    throw "The selected certificate is not authorized for code signing."
}
$expectedSignerSha256 = Get-CertificateSha256 -Certificate $signingCertificate
if (-not (Test-OrdinalContains -Values $allowedSigners -Expected $expectedSignerSha256)) {
    throw "The selected signing certificate is absent from the protected SHA-256 allowlist."
}

$metadataJson = Invoke-ConfiguredCargo -Cargo $cargo -Rustc $rustc -Arguments @(
    "metadata", "--format-version", "1", "--no-deps",
    "--manifest-path", $launcherCargoManifest
)
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
$releaseCandidatePattern = "^$([Regex]::Escape($ProductVersion))-[0-9a-f]{12}$"
if ($ReleaseCandidate -cnotmatch $releaseCandidatePattern -or
    $ReleaseCandidate -cne "$ProductVersion-$($CandidateCommit.Substring(0, 12))") {
    throw "ReleaseCandidate must bind the exact ProductVersion and CandidateCommit prefix."
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
    schema_version = "1.3"
    product_version = $ProductVersion
    release_candidate = $ReleaseCandidate
    candidate_commit = $CandidateCommit
    compose_sha256 = $composeHash
    images_sha256 = $imagesHash
    acl_script_sha256 = $aclScriptHash
    allowed_authenticode_signer_certificate_sha256 = @($allowedSigners)
}
$manifestJson = $releaseManifest | ConvertTo-Json -Compress
$utf8WithoutBom = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
[IO.File]::WriteAllText($manifestStaged, $manifestJson, $utf8WithoutBom)
$manifestHash = (Get-FileHash -LiteralPath $manifestStaged -Algorithm SHA256).Hash.ToLowerInvariant()

$targetTriple = "x86_64-pc-windows-msvc"
Invoke-ConfiguredCargo -Cargo $cargo -Rustc $rustc -Arguments @(
    "test", "--locked", "--manifest-path", $launcherCargoManifest
)
$previousBinding = [Environment]::GetEnvironmentVariable(
    "DES_RELEASE_MANIFEST_SHA256",
    [EnvironmentVariableTarget]::Process
)
$previousCandidateBinding = [Environment]::GetEnvironmentVariable(
    "DES_RELEASE_CANDIDATE",
    [EnvironmentVariableTarget]::Process
)
$previousCandidateCommitBinding = [Environment]::GetEnvironmentVariable(
    "DES_RELEASE_CANDIDATE_COMMIT",
    [EnvironmentVariableTarget]::Process
)
try {
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_MANIFEST_SHA256",
        $manifestHash,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_CANDIDATE",
        $ReleaseCandidate,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_CANDIDATE_COMMIT",
        $CandidateCommit,
        [EnvironmentVariableTarget]::Process
    )
    Invoke-ConfiguredCargo -Cargo $cargo -Rustc $rustc -Arguments @(
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
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_CANDIDATE",
        $previousCandidateBinding,
        [EnvironmentVariableTarget]::Process
    )
    [Environment]::SetEnvironmentVariable(
        "DES_RELEASE_CANDIDATE_COMMIT",
        $previousCandidateCommitBinding,
        [EnvironmentVariableTarget]::Process
    )
}

$launcherSource = Join-Path $repositoryRoot "desktop\windows\target\$targetTriple\release\launcher.exe"
$launcherSource = Resolve-ExistingFile -Path $launcherSource -Description "Windows Launcher executable"
Copy-Item -LiteralPath $launcherSource -Destination $launcherStaged

Invoke-Checked -Program $signtool -Arguments @(
    "sign", "/sha1", $expectedSignerThumbprint,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $launcherStaged
)
Assert-AuthenticodeSignature `
    -Path $launcherStaged `
    -ExpectedThumbprint $expectedSignerThumbprint `
    -ExpectedSha256 $expectedSignerSha256 `
    -AllowedSha256 $allowedSigners

$setupPath = Join-Path $outputDirectoryResolved "DataX-Enterprise-Studio-Setup-$ProductVersion-x64.exe"
if (Test-Path -LiteralPath $setupPath) {
    throw "Setup output already exists; remove it explicitly before rebuilding: $setupPath"
}
Invoke-Checked -Program $makensis -Arguments @(
    "/DPRODUCT_VERSION=$ProductVersion",
    "/DRELEASE_CANDIDATE=$ReleaseCandidate",
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
    "sign", "/sha1", $expectedSignerThumbprint,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $setupPath
)
Assert-AuthenticodeSignature `
    -Path $setupPath `
    -ExpectedThumbprint $expectedSignerThumbprint `
    -ExpectedSha256 $expectedSignerSha256 `
    -AllowedSha256 $allowedSigners

$launcherDigest = (Get-FileHash -LiteralPath $launcherStaged -Algorithm SHA256).Hash.ToLowerInvariant()
$setupDigest = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "Setup: $setupPath"
Write-Output "Setup SHA256: $setupDigest"
Write-Output "Launcher SHA256: $launcherDigest"
Write-Output "Release manifest SHA256: $manifestHash"
Write-Output "Compose SHA256: $composeHash"
Write-Output "Image lock SHA256: $imagesHash"
Write-Output "ACL helper SHA256: $aclScriptHash"
