[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string]$ProductVersion,
    [Parameter(Mandatory = $true)]
    [string]$BuildOutputDirectory,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$SigningCertificateThumbprint,
    [Parameter(Mandatory = $true)]
    [string]$AllowedSignerFile,
    [Parameter(Mandatory = $true)]
    [string]$CargoPath,
    [Parameter(Mandatory = $true)]
    [string]$RustcPath,
    [Parameter(Mandatory = $true)]
    [string]$MakensisPath,
    [Parameter(Mandatory = $true)]
    [string]$SigntoolPath,
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

function Resolve-ExistingDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a non-reparse directory: $Path"
    }
    return $resolved.Path
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

function Get-CertificateSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    return $Certificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    ).ToLowerInvariant()
}

function Assert-AuthenticodeSigner {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha1,
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
    if (-not $actualSha1.Equals($ExpectedSha1, [StringComparison]::OrdinalIgnoreCase) -or
        -not $actualSha256.Equals($ExpectedSha256, [StringComparison]::Ordinal) -or
        -not (Test-OrdinalContains -Values $AllowedSha256 -Expected $actualSha256)) {
        throw "Unexpected Authenticode signer identity for $Path."
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
    [Runtime.InteropServices.Architecture]::X64) {
    throw "A native AMD64 Windows host is required."
}

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory "..\.."))
$launcherCargoManifest = Resolve-ExistingFile `
    -Path (Join-Path $repositoryRoot "desktop\windows\Cargo.toml") `
    -Description "Launcher Cargo manifest"
$nsiSource = Resolve-ExistingFile `
    -Path (Join-Path $repositoryRoot "installer\windows\DataXEnterpriseStudio.nsi") `
    -Description "NSIS installer script"
$outputDirectory = Resolve-ExistingDirectory `
    -Path $BuildOutputDirectory `
    -Description "Windows build output"
$stagingDirectory = Resolve-ExistingDirectory `
    -Path (Join-Path $outputDirectory "staging-$ProductVersion") `
    -Description "Windows staging directory"
$resourceDirectory = Resolve-ExistingDirectory `
    -Path (Join-Path $stagingDirectory "resources") `
    -Description "Windows staging resources"
$launcherStaged = Resolve-ExistingFile `
    -Path (Join-Path $stagingDirectory "launcher.exe") `
    -Description "staged Windows Launcher"
$composeStaged = Resolve-ExistingFile `
    -Path (Join-Path $resourceDirectory "compose.yaml") `
    -Description "staged Compose file"
$imagesStaged = Resolve-ExistingFile `
    -Path (Join-Path $resourceDirectory "images.release.env") `
    -Description "staged image lock"
$aclScriptStaged = Resolve-ExistingFile `
    -Path (Join-Path $resourceDirectory "secure-acl.ps1") `
    -Description "staged ACL helper"
$manifestStaged = Resolve-ExistingFile `
    -Path (Join-Path $resourceDirectory "release-manifest.json") `
    -Description "staged release manifest"

$allowedSigners = Read-CanonicalSignerAllowlist -Path $AllowedSignerFile
$expectedSha1 = $SigningCertificateThumbprint.Replace(" ", "").ToUpperInvariant()
$certificatePath = "Cert:\CurrentUser\My\$expectedSha1"
$certificate = Get-Item -LiteralPath $certificatePath -ErrorAction Stop
if (-not $certificate.HasPrivateKey) {
    throw "The selected Windows signing certificate has no private key."
}
$now = Get-Date
if ($certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
    throw "The selected Windows signing certificate is not currently valid."
}
$codeSigning = @(
    $certificate.Extensions |
        Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
        ForEach-Object { $_.EnhancedKeyUsages } |
        Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }
)
if ($codeSigning.Count -eq 0) {
    throw "The selected certificate is not authorized for code signing."
}
$expectedSha256 = Get-CertificateSha256 -Certificate $certificate
if (-not (Test-OrdinalContains -Values $allowedSigners -Expected $expectedSha256)) {
    throw "The selected signing certificate is absent from the protected SHA-256 allowlist."
}

$cargo = Resolve-RequiredExecutable -Name "cargo.exe" -ExplicitPath $CargoPath
$rustc = Resolve-RequiredExecutable -Name "rustc.exe" -ExplicitPath $RustcPath
$makensis = Resolve-RequiredExecutable -Name "makensis.exe" -ExplicitPath $MakensisPath
$signtool = Resolve-RequiredExecutable -Name "signtool.exe" -ExplicitPath $SigntoolPath
Assert-NoCargoCompilerOverrides
$metadataJson = Invoke-ConfiguredCargo -Cargo $cargo -Rustc $rustc -Arguments @(
    "metadata", "--format-version", "1", "--no-deps",
    "--manifest-path", $launcherCargoManifest
)
$metadata = $metadataJson | ConvertFrom-Json
$package = @($metadata.packages) |
    Where-Object { $_.name -eq "datax-enterprise-studio-launcher" } |
    Select-Object -First 1
if ($null -eq $package -or [string]$package.version -cne $ProductVersion) {
    throw "ProductVersion must match the Launcher Cargo package version."
}

$releaseManifest = [ordered]@{
    schema_version = "1.1"
    product_version = $ProductVersion
    compose_sha256 = (
        Get-FileHash -LiteralPath $composeStaged -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    images_sha256 = (
        Get-FileHash -LiteralPath $imagesStaged -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    acl_script_sha256 = (
        Get-FileHash -LiteralPath $aclScriptStaged -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    allowed_authenticode_signer_certificate_sha256 = @($allowedSigners)
}
$manifestJson = $releaseManifest | ConvertTo-Json -Compress
$utf8WithoutBom = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($manifestStaged, $manifestJson, $utf8WithoutBom)
$manifestHash = (
    Get-FileHash -LiteralPath $manifestStaged -Algorithm SHA256
).Hash.ToLowerInvariant()

$targetTriple = "x86_64-pc-windows-msvc"
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
}

$launcherSource = Resolve-ExistingFile `
    -Path (Join-Path ([string]$metadata.target_directory) "$targetTriple\release\launcher.exe") `
    -Description "rebuilt Windows Launcher"
Copy-Item -LiteralPath $launcherSource -Destination $launcherStaged -Force
Invoke-Checked -Program $signtool -Arguments @(
    "sign", "/sha1", $expectedSha1,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $launcherStaged
)
Assert-AuthenticodeSigner `
    -Path $launcherStaged `
    -ExpectedSha1 $expectedSha1 `
    -ExpectedSha256 $expectedSha256 `
    -AllowedSha256 $allowedSigners

$setupPath = Join-Path `
    $outputDirectory `
    "DataX-Enterprise-Studio-Setup-$ProductVersion-x64.exe"
$setupPath = Resolve-ExistingFile `
    -Path $setupPath `
    -Description "intermediate Setup output"
Remove-Item -LiteralPath $setupPath -Force
$fileVersion = "$ProductVersion.0"
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
$setupPath = Resolve-ExistingFile `
    -Path $setupPath `
    -Description "rebuilt Setup output"
Invoke-Checked -Program $signtool -Arguments @(
    "sign", "/sha1", $expectedSha1,
    "/fd", "SHA256", "/td", "SHA256",
    "/tr", $TimestampUrl,
    $setupPath
)
Assert-AuthenticodeSigner `
    -Path $setupPath `
    -ExpectedSha1 $expectedSha1 `
    -ExpectedSha256 $expectedSha256 `
    -AllowedSha256 $allowedSigners

Invoke-Checked -Program $launcherStaged -Arguments @(
    "verify-release", "--installer", $setupPath
)
Write-Output "Publisher binding finalized for certificate SHA-256 $expectedSha256."
