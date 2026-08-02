[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$LauncherPath,
    [Parameter(Mandatory = $true)]
    [string]$SetupPath,
    [Parameter(Mandatory = $true)]
    [string]$ResourcesDirectory,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string]$ExpectedVersion,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-[0-9a-f]{12}$')]
    [string]$ExpectedReleaseCandidate,
    [Parameter(Mandatory = $true)]
    [string]$ExpectedAllowlistFile
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
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a non-reparse regular file: $Path"
    }
    return $resolved.Path
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

function Read-StrictJson {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [int64]$MaximumBytes
    )

    $resolved = Resolve-ExistingFile -Path $Path -Description "JSON document"
    $item = Get-Item -LiteralPath $resolved
    if ($item.Length -le 0 -or $item.Length -gt $MaximumBytes) {
        throw "JSON document has an invalid size: $Path"
    }
    $strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
    $text = [IO.File]::ReadAllText($resolved, $strictUtf8)
    if ($text.Length -eq 0 -or $text[0] -eq [char]0xFEFF) {
        throw "JSON document must be non-empty UTF-8 without a BOM: $Path"
    }
    return $text | ConvertFrom-Json
}

function Get-CanonicalAllowlist {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,
        [Parameter(Mandatory = $true)]
        [string[]]$ExpectedProperties,
        [Parameter(Mandatory = $true)]
        [string]$SchemaVersion
    )

    $properties = @($Document.PSObject.Properties.Name)
    if ($properties.Count -ne $ExpectedProperties.Count) {
        throw "Signer document contains an unexpected property count."
    }
    for ($index = 0; $index -lt $properties.Count; $index++) {
        if ($properties[$index] -cne $ExpectedProperties[$index]) {
            throw "Signer document properties are missing, reordered, or unknown."
        }
    }
    if ($Document.schema_version -cne $SchemaVersion) {
        throw "Signer document schema version is unsupported."
    }
    $values = @($Document.allowed_authenticode_signer_certificate_sha256)
    if ($values.Count -lt 1 -or $values.Count -gt 8) {
        throw "Signer allowlist must contain between one and eight certificates."
    }
    for ($index = 0; $index -lt $values.Count; $index++) {
        if ($values[$index] -isnot [string] -or
            $values[$index] -cnotmatch '^[0-9a-f]{64}$') {
            throw "Signer allowlist contains an invalid certificate SHA-256."
        }
        if ($index -gt 0 -and
            [string]::CompareOrdinal($values[$index - 1], $values[$index]) -ge 0) {
            throw "Signer allowlist must be strictly ordinal-sorted and unique."
        }
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

function Get-SignerSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $Path with status $($signature.Status)."
    }
    return $signature.SignerCertificate.GetCertHashString(
        [Security.Cryptography.HashAlgorithmName]::SHA256
    ).ToLowerInvariant()
}

$launcher = Resolve-ExistingFile -Path $LauncherPath -Description "Launcher"
$setup = Resolve-ExistingFile -Path $SetupPath -Description "Setup"
$resources = Resolve-ExistingDirectory `
    -Path $ResourcesDirectory `
    -Description "release resources"
$manifestPath = Join-Path $resources "release-manifest.json"
$manifest = Read-StrictJson -Path $manifestPath -MaximumBytes 65536
$manifestProperties = [string[]]@(
    "schema_version",
    "product_version",
    "release_candidate",
    "compose_sha256",
    "images_sha256",
    "acl_script_sha256",
    "allowed_authenticode_signer_certificate_sha256"
)
$manifestSigners = Get-CanonicalAllowlist `
    -Document $manifest `
    -ExpectedProperties $manifestProperties `
    -SchemaVersion "1.2"
$releaseCandidatePattern = "^$([Regex]::Escape($ExpectedVersion))-[0-9a-f]{12}$"
if ($ExpectedReleaseCandidate -cnotmatch $releaseCandidatePattern -or
    $manifest.product_version -cne $ExpectedVersion -or
    $manifest.release_candidate -cne $ExpectedReleaseCandidate -or
    $manifest.compose_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $manifest.images_sha256 -cnotmatch '^[0-9a-f]{64}$' -or
    $manifest.acl_script_sha256 -cnotmatch '^[0-9a-f]{64}$') {
    throw "Release manifest version or resource hashes are invalid."
}

$expectedDocument = Read-StrictJson `
    -Path $ExpectedAllowlistFile `
    -MaximumBytes 16384
$expectedSigners = Get-CanonicalAllowlist `
    -Document $expectedDocument `
    -ExpectedProperties ([string[]]@(
        "schema_version",
        "allowed_authenticode_signer_certificate_sha256"
    )) `
    -SchemaVersion "1.0"
if ($manifestSigners.Count -ne $expectedSigners.Count) {
    throw "Release manifest signer set differs from the protected allowlist."
}
for ($index = 0; $index -lt $manifestSigners.Count; $index++) {
    if (-not $manifestSigners[$index].Equals(
        $expectedSigners[$index],
        [StringComparison]::Ordinal
    )) {
        throw "Release manifest signer set differs from the protected allowlist."
    }
}

$resourceRules = [ordered]@{
    "compose.yaml" = [string]$manifest.compose_sha256
    "images.release.env" = [string]$manifest.images_sha256
    "secure-acl.ps1" = [string]$manifest.acl_script_sha256
}
foreach ($entry in $resourceRules.GetEnumerator()) {
    $path = Resolve-ExistingFile `
        -Path (Join-Path $resources $entry.Key) `
        -Description $entry.Key
    $actual = (
        Get-FileHash -LiteralPath $path -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if (-not $actual.Equals($entry.Value, [StringComparison]::Ordinal)) {
        throw "Release resource hash mismatch: $($entry.Key)"
    }
}

$launcherSigner = Get-SignerSha256 -Path $launcher
$setupSigner = Get-SignerSha256 -Path $setup
if (-not $launcherSigner.Equals($setupSigner, [StringComparison]::Ordinal) -or
    -not (Test-OrdinalContains -Values $manifestSigners -Expected $launcherSigner)) {
    throw "Setup and Launcher must share one allowlisted certificate SHA-256 identity."
}

& $launcher verify-release --installer $setup
if ($LASTEXITCODE -ne 0) {
    throw "Launcher release verification failed with exit code $LASTEXITCODE."
}
Write-Output "Verified Windows publisher certificate SHA-256 $launcherSigner."
