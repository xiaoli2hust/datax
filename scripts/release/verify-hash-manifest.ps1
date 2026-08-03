[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$RootDirectory,
    [string]$ManifestName = "SHA256SUMS"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($ManifestName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$' -or
    [IO.Path]::GetFileName($ManifestName) -ne $ManifestName) {
    throw "ManifestName must be a canonical file name."
}
$rootItem = Get-Item -LiteralPath (Resolve-Path -LiteralPath $RootDirectory) -Force
if (-not $rootItem.PSIsContainer -or
    ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "Evidence root must be a non-reparse directory."
}
$root = [IO.Path]::GetFullPath($rootItem.FullName)
$rootPrefix = $root.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
$manifestPath = Join-Path $root $ManifestName
$manifestItem = Get-Item -LiteralPath (Resolve-Path -LiteralPath $manifestPath) -Force
if ($manifestItem.PSIsContainer -or
    ($manifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    $manifestItem.Length -gt 1048576) {
    throw "Hash manifest must be a small, non-reparse regular file."
}
$treeItems = @(
    Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction Stop
)
foreach ($item in $treeItems) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Evidence contains a reparse-point entry."
    }
}

$strictUtf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false, $true
$text = [IO.File]::ReadAllText($manifestItem.FullName, $strictUtf8)
if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
    throw "Hash manifest must not contain a BOM."
}
$lines = [IO.File]::ReadAllLines($manifestItem.FullName, $strictUtf8)
if ($lines.Count -eq 0) {
    throw "Hash manifest must contain at least one entry."
}

$declared = @{}
$previousPath = $null
foreach ($line in $lines) {
    if ($line.Length -eq 0) {
        throw "Hash manifest contains an empty entry."
    }
    if ($line -cnotmatch '^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._/-]*)$') {
        throw "Hash manifest contains a malformed entry."
    }
    $digest = $Matches[1]
    $relative = $Matches[2]
    $parts = $relative.Split("/")
    if ($parts -contains ".." -or $relative.Contains("\") -or
        $declared.ContainsKey($relative)) {
        throw "Hash manifest contains a duplicate or unsafe path."
    }
    if ($null -ne $previousPath -and
        [StringComparer]::Ordinal.Compare($previousPath, $relative) -ge 0) {
        throw "Hash manifest paths are not in canonical order."
    }
    $previousPath = $relative
    $candidate = [IO.Path]::GetFullPath(
        (
            Join-Path $root (
                $relative.Replace(
                    [char]"/",
                    [IO.Path]::DirectorySeparatorChar
                )
            )
        )
    )
    if (-not $candidate.StartsWith(
        $rootPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Hash manifest path escapes the evidence root."
    }
    $item = Get-Item -LiteralPath $candidate -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Hash manifest target must be a non-reparse regular file."
    }
    $actual = (Get-FileHash -LiteralPath $candidate -Algorithm SHA256).Hash
    if (-not $actual.Equals($digest, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Hash mismatch for $relative."
    }
    $declared[$relative] = $true
}

$actualFiles = @(
    $treeItems |
        Where-Object { -not $_.PSIsContainer } |
        Where-Object { $_.FullName -ne $manifestItem.FullName }
)
foreach ($item in $actualFiles) {
    $relative = $item.FullName.Substring($rootPrefix.Length).Replace("\", "/")
    if (-not $declared.ContainsKey($relative)) {
        throw "Unlisted evidence file: $relative."
    }
}
if ($actualFiles.Count -ne $declared.Count) {
    throw "Hash manifest file count does not match the evidence directory."
}
